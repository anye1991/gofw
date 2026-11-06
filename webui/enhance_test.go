package webui

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"gofw/config"
	"gofw/engine"
	"gofw/rules"
)

func enhanceServer(t *testing.T) (*Server, *atomic.Pointer[rules.RuleSet]) {
	t.Helper()
	var engPtr atomic.Pointer[engine.Engine]
	var rsPtr atomic.Pointer[rules.RuleSet]
	rs := rules.NewRuleSet()
	r := rules.NewRule(rules.ActionAccept)
	r.Comment = "business rule"
	rs.Add(r)
	rsPtr.Store(rs)
	engPtr.Store(engine.NewEngine(rs))
	srv := New(&engPtr, &rsPtr, ":0", "", func(n *rules.RuleSet) { rsPtr.Store(n) })
	return srv, &rsPtr
}

// guard 预设必须只产生 4 条 ACCEPT 护栏且不生成任何 DROP，且幂等。
func TestInstallGuardPreset(t *testing.T) {
	srv, rsPtr := enhanceServer(t)
	q := geoApplyRequest{Preset: "guard", Guard: defaultGuard()}
	srv.geoInstallGuard(httptest.NewRecorder(), q)

	got := rsPtr.Load()
	if got.Len() != 5 {
		t.Fatalf("expected 4 guards + 1 business rule, got %d", got.Len())
	}
	for i := 0; i < 4; i++ {
		if !strings.HasPrefix(got.Rules[i].Comment, markGuard) {
			t.Errorf("rule #%d is not a guard: %q", i, got.Rules[i].Comment)
		}
		if got.Rules[i].Action != rules.ActionAccept {
			t.Errorf("guard #%d must be ACCEPT", i)
		}
	}
	for _, r := range got.Rules {
		if strings.HasPrefix(r.Comment, markGeo) {
			t.Errorf("guard preset must not generate fence rules: %q", r.Comment)
		}
	}
	// 再装一次，规则数不应变化（幂等）
	srv.geoInstallGuard(httptest.NewRecorder(), q)
	if rsPtr.Load().Len() != 5 {
		t.Errorf("guard preset is not idempotent: %d rules", rsPtr.Load().Len())
	}
}

// 城市 / ASN 字段必须能从 JSON 解析、经 Save 落盘、再 Load 读回，不丢失。
func TestCityASNRoundTrip(t *testing.T) {
	r, err := config.ParseRuleJSON([]byte(`{"action":"DROP","geo_city":"Beijing,Shanghai","geo_asn":"!AS4134"}`))
	if err != nil {
		t.Fatal(err)
	}
	if r.GeoCity != "Beijing,Shanghai" || r.GeoASN != "!AS4134" {
		t.Fatalf("fields lost on parse: city=%q asn=%q", r.GeoCity, r.GeoASN)
	}
	rs := rules.NewRuleSet()
	rs.Add(r)
	p := filepath.Join(t.TempDir(), "rules.yaml")
	if err := config.Save(rs, p); err != nil {
		t.Fatal(err)
	}
	back, err := config.Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(back.Rules) != 1 || back.Rules[0].GeoCity != "Beijing,Shanghai" || back.Rules[0].GeoASN != "!AS4134" {
		t.Fatalf("fields lost after YAML round trip: %+v", back.Rules)
	}
}

func TestSyncSignature(t *testing.T) {
	yaml := "default: accept\nrules: []\n"
	a := syncSign("s3cr3t", yaml)
	b := syncSign("s3cr3t", yaml)
	if a != b || len(a) != 64 {
		t.Fatalf("signature unstable or wrong length: %q", a)
	}
	if syncSign("other", yaml) == a {
		t.Fatal("different secret must produce different signature")
	}
	if syncSign("s3cr3t", yaml+"\n# tampered") == a {
		t.Fatal("tampered payload must produce different signature")
	}
}

type fakeBackend struct {
	mode      string
	switched  []string
	confirmed bool
}

func (f *fakeBackend) Mode() string              { return f.mode }
func (f *fakeBackend) Preflight() (bool, string) { return true, "ok" }
func (f *fakeBackend) SwitchTo(m string) error {
	f.switched = append(f.switched, m)
	f.mode = m
	return nil
}
func (f *fakeBackend) ArmRollback(_ time.Duration) {}
func (f *fakeBackend) Confirm()                    { f.confirmed = true }
func (f *fakeBackend) RollbackRemaining() int      { return 0 }

// 切到内核必须二次确认，否则后端拒绝且绝不调用 SwitchTo。
func TestKernelSwitchRequiresConfirmation(t *testing.T) {
	srv, _ := enhanceServer(t)
	fb := &fakeBackend{mode: "monitor"}
	srv.backendCtl = fb

	r1 := httptest.NewRequest("POST", "/api/backend/switch", strings.NewReader(`{"mode":"kernel","confirm":false}`))
	w1 := httptest.NewRecorder()
	srv.handleBackendAction(w1, r1)
	if w1.Code != 412 {
		t.Errorf("expected 412 without confirmation, got %d", w1.Code)
	}
	if len(fb.switched) != 0 {
		t.Fatal("SwitchTo must not be called without explicit confirmation")
	}

	r2 := httptest.NewRequest("POST", "/api/backend/switch", strings.NewReader(`{"mode":"kernel","confirm":true}`))
	w2 := httptest.NewRecorder()
	srv.handleBackendAction(w2, r2)
	if w2.Code != 200 || len(fb.switched) != 1 || fb.switched[0] != "kernel" {
		t.Fatalf("confirmed switch failed: code=%d calls=%v", w2.Code, fb.switched)
	}
}
