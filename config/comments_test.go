package config

import (
	"os"
	"strings"
	"testing"

	"gofw/rules"
)

const commentFixture = `# GoFW 规则集（人工维护）
default: accept

rules:
    # ===== 基础放行 =====
    - action: accept
      state: established
      comment: allow established

    # ===== 地理围栏 =====
    - action: drop
      protocol: tcp
      dst_port: "22"
      comment: block ssh
`

// 后台任何保存（配置源 PUT / 地理围栏 apply/clear）都不得抹掉人工注释。
func TestSavePreservesSectionComments(t *testing.T) {
	path := t.TempDir() + "/rules.yaml"
	if err := os.WriteFile(path, []byte(commentFixture), 0644); err != nil {
		t.Fatal(err)
	}
	rs, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.Rules) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(rs.Rules))
	}

	if err := Save(rs, path); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(got)
	for _, want := range []string{
		"# GoFW 规则集（人工维护）",
		"# ===== 基础放行 =====",
		"# ===== 地理围栏 =====",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("comment lost: %q\n--- saved file ---\n%s", want, s)
		}
	}
	iBase, iEst := strings.Index(s, "# ===== 基础放行 ====="), strings.Index(s, "comment: allow established")
	iGeo, iSSH := strings.Index(s, "# ===== 地理围栏 ====="), strings.Index(s, "comment: block ssh")
	if iBase < 0 || iEst < 0 || iBase > iEst {
		t.Errorf("基础放行注释位置错误:\n%s", s)
	}
	if iGeo < 0 || iSSH < 0 || iGeo > iSSH {
		t.Errorf("地理围栏注释位置错误:\n%s", s)
	}

	rs2, err := Load(path)
	if err != nil {
		t.Fatalf("saved file not parseable: %v\n%s", err, s)
	}
	if len(rs2.Rules) != 2 {
		t.Errorf("expected 2 rules after reload, got %d", len(rs2.Rules))
	}
}

// 模拟地理围栏：在规则集头部插入新规则后，注释仍要保留且不串行。
func TestSavePreservesCommentsWhenRulesAdded(t *testing.T) {
	path := t.TempDir() + "/rules.yaml"
	if err := os.WriteFile(path, []byte(commentFixture), 0644); err != nil {
		t.Fatal(err)
	}
	rs, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	guard := rules.NewRule(rules.ActionAccept)
	guard.Comment = "[gofw-guard] allow management ports"
	added := rules.NewRuleSet()
	added.Add(guard)
	for _, r := range rs.Rules {
		added.Add(r)
	}
	if err := Save(added, path); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	s := string(got)
	for _, want := range []string{
		"# ===== 基础放行 =====", "# ===== 地理围栏 =====",
		"[gofw-guard] allow management ports",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q after adding rules:\n%s", want, s)
		}
	}
	rs2, err := Load(path)
	if err != nil {
		t.Fatalf("saved file not parseable: %v\n%s", err, s)
	}
	if len(rs2.Rules) != 3 {
		t.Errorf("expected 3 rules, got %d", len(rs2.Rules))
	}
}

// 锚点规则被删除时，注释不能静默消失（保留到文件尾）。
func TestSaveKeepsOrphanComments(t *testing.T) {
	path := t.TempDir() + "/rules.yaml"
	if err := os.WriteFile(path, []byte(commentFixture), 0644); err != nil {
		t.Fatal(err)
	}
	rs, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	empty := rules.NewRuleSet()
	empty.DefaultAction = rs.DefaultAction
	if err := Save(empty, path); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	s := string(got)
	if !strings.Contains(s, "# ===== 基础放行 =====") {
		t.Errorf("orphan comment must be kept:\n%s", s)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("saved file not parseable: %v\n%s", err, s)
	}
}
