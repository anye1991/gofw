package webui

import (
	"net"
	"strings"
	"testing"

	"gofw/rules"
)

// 护栏必须是 ACCEPT，且覆盖已建立连接、loopback、管理端口、LAN 网段，
// 并都用 [gofw-guard] 标记以便精确清除。
func TestGuardRulesAreSafeAndTagged(t *testing.T) {
	g := buildGuardRules(defaultGuard())
	if len(g) != 4 {
		t.Fatalf("expected 4 guard rules, got %d", len(g))
	}
	for i, r := range g {
		if r.Action != rules.ActionAccept {
			t.Errorf("guard #%d must be ACCEPT, got %s", i, r.Action)
		}
		if !strings.HasPrefix(r.Comment, markGuard) {
			t.Errorf("guard #%d missing tag: %q", i, r.Comment)
		}
	}
	if g[0].State != "established" {
		t.Errorf("first guard must allow established, got state=%q", g[0].State)
	}
	if g[2].Protocol == nil || *g[2].Protocol != 6 || g[2].DstPort == nil {
		t.Error("management-ports guard must match tcp dport")
	}
	for _, port := range []uint16{22, 888, 18081, 18706} {
		if !g[2].DstPort.Matches(port) {
			t.Errorf("mgmt port %d must be covered by guard, spec=%q", port, g[2].DstPort.String())
		}
	}
}

// 首个匹配生效：护栏 ACCEPT 必须排在地理封锁 DROP 之前，
// 且来自 LAN 管理网段 / 管理端口的流量必须命中护栏而非封锁规则。
func TestGuardPrecedesFence(t *testing.T) {
	guards := buildGuardRules(defaultGuard())
	fence := rules.NewRule(rules.ActionDrop)
	fence.GeoIP = rules.ParseGeoIPSpec("CN") // deny 模式：仅放行 CN，其余 drop
	fence.Comment = markGeo + "whitelist only CN"
	fence.Direction = rules.DirIn

	rs := rules.NewRuleSet()
	rs.DefaultAction = rules.ActionAccept
	merged := append([]*rules.Rule{}, guards...)
	merged = append(merged, fence)
	rs.Rules = merged

	// 模拟一条来自 LAN 管理网段、访问管理端口的入站 TCP 包（已建立连接）
	p := uint8(6)
	ctx := rules.MatchContext{
		SrcIP: net.ParseIP("192.168.58.1"), DstIP: net.ParseIP("192.168.58.128"),
		Proto: p, DstPort: 18081, ConnState: rules.StateEstablished,
		SrcCountry: "US", Direction: rules.DirAny,
	}
	_, action := rs.Match(ctx)
	if action != rules.ActionAccept {
		t.Fatalf("LAN management traffic must be ACCEPTed by guard, got %s", action)
	}

	// 模拟来自国外、访问普通端口的新建入站包：应被 whitelist 封锁
	ctx2 := rules.MatchContext{
		SrcIP: net.ParseIP("203.0.113.9"), DstIP: net.ParseIP("192.168.58.128"),
		Proto: p, DstPort: 443, ConnState: rules.StateNew,
		SrcCountry: "US", Direction: rules.DirAny,
	}
	// 该包目的端口 443 不在管理端口集合，SrcIP 不在 LAN 网段，非 established
	_, action2 := rs.Match(ctx2)
	if action2 != rules.ActionDrop {
		t.Fatalf("foreign traffic should be DROPped by whitelist fence, got %s", action2)
	}
}

// geoClear 只移除带标记的规则，不误删用户手工规则。
func TestManagedRuleFiltering(t *testing.T) {
	manual := rules.NewRule(rules.ActionAccept)
	manual.Comment = "my own rule"
	guard := buildGuardRules(defaultGuard())[0]
	fence := rules.NewRule(rules.ActionDrop)
	fence.Comment = markGeo + "blacklist"

	all := []*rules.Rule{guard, manual, fence}
	kept := make([]*rules.Rule, 0)
	for _, r := range all {
		if !isManaged(r) {
			kept = append(kept, r)
		}
	}
	if len(kept) != 1 || kept[0] != manual {
		t.Fatalf("clear must keep only manual rule, got %d rules", len(kept))
	}
}
