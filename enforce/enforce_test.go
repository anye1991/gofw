package enforce

import (
	"strings"
	"testing"

	"gofw/config"
	"gofw/geoip"
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

// GeoIP deny 模式（geoip: RU）+ drop：入站应编译为 "ip saddr != @geoip_RU drop"，
// 与用户态 GeoIPSpec.Matches 的 "!inList" 语义一致。
func TestBuildScriptGeoIPDeny(t *testing.T) {
	db := geoip.NewWithBuiltin()
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{Action: rules.ActionDrop, GeoIP: rules.ParseGeoIPSpec("RU"), Direction: rules.DirIn})
	n := &NftablesEnforcer{geoDB: db}
	script := n.buildScript(rs)
	t.Log(script)
	if !strings.Contains(script, "set geoip_RU {") {
		t.Error("missing geoip_RU set definition")
	}
	if !strings.Contains(script, "type ipv4_addr") || !strings.Contains(script, "flags interval") {
		t.Error("geoip set must be type ipv4_addr; flags interval")
	}
	if !strings.Contains(script, "ip saddr != @geoip_RU drop") {
		t.Errorf("deny geoip should compile to 'ip saddr != @geoip_RU drop', got:\n%s", script)
	}
}

// GeoIP allow 模式（geoip: allow:CN）+ drop：入站应编译为 "ip saddr @geoip_CN drop"。
func TestBuildScriptGeoIPAllow(t *testing.T) {
	db := geoip.NewWithBuiltin()
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{Action: rules.ActionDrop, GeoIP: rules.ParseGeoIPSpec("allow:CN"), Direction: rules.DirIn})
	n := &NftablesEnforcer{geoDB: db}
	script := n.buildScript(rs)
	t.Log(script)
	if !strings.Contains(script, "ip saddr @geoip_CN drop") {
		t.Errorf("allow geoip should compile to 'ip saddr @geoip_CN drop', got:\n%s", script)
	}
}

// 出站 geoip 应改用 ip daddr（目标国家），与入站源国家区分。
func TestBuildScriptGeoIPOutboundUsesDaddr(t *testing.T) {
	db := geoip.NewWithBuiltin()
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{Action: rules.ActionDrop, GeoIP: rules.ParseGeoIPSpec("RU"), Direction: rules.DirOut})
	n := &NftablesEnforcer{geoDB: db}
	script := n.buildScript(rs)
	t.Log(script)
	if !strings.Contains(script, "ip daddr != @geoip_RU drop") {
		t.Errorf("outbound geoip should use 'ip daddr', got:\n%s", script)
	}
}

// 多国家 OR（geoip: CN,US）应合并进同一集合 geoip_CN_US。
func TestBuildScriptGeoIPMultiCountry(t *testing.T) {
	db := geoip.NewWithBuiltin()
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{Action: rules.ActionDrop, GeoIP: rules.ParseGeoIPSpec("CN,US"), Direction: rules.DirIn})
	n := &NftablesEnforcer{geoDB: db}
	script := n.buildScript(rs)
	t.Log(script)
	if !strings.Contains(script, "set geoip_CN_US {") {
		t.Error("multi-country rule should produce set geoip_CN_US")
	}
	if !strings.Contains(script, "ip saddr != @geoip_CN_US drop") {
		t.Errorf("multi-country deny should compile to 'ip saddr != @geoip_CN_US drop', got:\n%s", script)
	}
}

// 引用库中不存在的国家（ZZ）必须跳过该规则，不能生成空集合（否则 "!=" 取反会误杀全网）。
func TestBuildScriptGeoIPUnknownCountrySkipped(t *testing.T) {
	db := geoip.NewWithBuiltin()
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{Action: rules.ActionDrop, GeoIP: rules.ParseGeoIPSpec("ZZ"), Direction: rules.DirIn})
	n := &NftablesEnforcer{geoDB: db}
	script := n.buildScript(rs)
	t.Log(script)
	if strings.Contains(script, "geoip_ZZ") {
		t.Error("unknown country must not be compiled (no set, no matcher)")
	}
}

// 未注入 GeoIP 库时，geoip 规则整条跳过且不应出现在脚本里（避免误拦截）。
func TestBuildScriptGeoIPNoDBSkipped(t *testing.T) {
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{Action: rules.ActionDrop, GeoIP: rules.ParseGeoIPSpec("RU"), Direction: rules.DirIn})
	n := &NftablesEnforcer{} // 无 geoDB
	script := n.buildScript(rs)
	t.Log(script)
	if strings.Contains(script, "@geoip_RU") {
		t.Errorf("without GeoIP DB, geoip rule must be skipped, got:\n%s", script)
	}
}
