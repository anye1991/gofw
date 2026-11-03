package enforce

import (
	"strings"
	"testing"

	"gofw/config"
	"gofw/rules"
)

func TestBuildScript(t *testing.T) {
	rs, err := config.Load("../rules.yaml")
	if err != nil {
		t.Fatal(err)
	}
	n := &NftablesEnforcer{}
	script := n.buildScript(rs)
	t.Log(script)
	if len(script) == 0 {
		t.Error("empty script")
	}
}

// 回归：VLAN + L4 规则必须把 "ether type vlan" 前置到 tcp 匹配之前，
// 否则 nftables 报 "conflicting protocols specified: ether vs. vlan"，
// 导致整份规则集原子替换失败、gofw 进程退出。
func TestRuleToNftVLANWithL4(t *testing.T) {
	vlanID := uint16(10)
	proto := uint8(6) // TCP
	r := rules.NewRule(rules.ActionAccept)
	r.VLAN = &vlanID
	r.Protocol = &proto
	r.DstPort = rules.ParsePortSpec("3306")
	r.Direction = rules.DirIn
	n := &NftablesEnforcer{}
	got := n.ruleToNft(r, "input")
	want := "ether type vlan vlan id 10 tcp dport 3306 accept"
	if got != want {
		t.Fatalf("VLAN+L4 rule mismatch:\n got: %q\nwant: %q", got, want)
	}
	if strings.Index(got, "ether type vlan") > strings.Index(got, "tcp dport") {
		t.Errorf("vlan match must precede L4 match, got %q", got)
	}
}

// VLAN-only 规则（无 L4）也应带 "ether type vlan" 前缀。
func TestRuleToNftVLANOnly(t *testing.T) {
	vlanID := uint16(10)
	r := rules.NewRule(rules.ActionDrop)
	r.VLAN = &vlanID
	r.Direction = rules.DirIn
	n := &NftablesEnforcer{}
	if got := n.ruleToNft(r, "input"); got != "ether type vlan vlan id 10 drop" {
		t.Errorf("VLAN-only rule = %q", got)
	}
}

// 普通 TCP 规则不得携带 VLAN 匹配，避免误改行为。
func TestRuleToNftPlainTCPNoVLAN(t *testing.T) {
	proto := uint8(6)
	r := rules.NewRule(rules.ActionAccept)
	r.Protocol = &proto
	r.DstPort = rules.ParsePortSpec("443")
	r.Direction = rules.DirIn
	n := &NftablesEnforcer{}
	got := n.ruleToNft(r, "input")
	if strings.Contains(got, "ether type vlan") {
		t.Errorf("plain TCP rule must not carry VLAN match: %q", got)
	}
	if !strings.Contains(got, "tcp dport 443 accept") {
		t.Errorf("plain TCP rule = %q", got)
	}
}
