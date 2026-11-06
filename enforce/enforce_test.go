package enforce

import (
	"fmt"
	"os"
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

// 加载外部 CSV（模拟全国家库）后，geoip 规则应把该国的全部 CIDR 正确灌进
// 对应的命名集合，并生成引用该集合的内核规则。验证"全国家"路径在生成层正确。
func TestBuildScriptGeoIPFromCSVLibrary(t *testing.T) {
	csv := "5.255.192.0/18,RU\n" +
		"95.213.0.0/16,RU\n" +
		"178.176.0.0/13,RU\n" +
		"1.2.3.0/24,CN\n" +
		"9.9.9.0/24,CN\n"
	dir := t.TempDir()
	path := dir + "/geoip.csv"
	if err := os.WriteFile(path, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}
	db := geoip.New()
	if err := db.LoadFromCSV(path); err != nil {
		t.Fatal(err)
	}
	if db.Count() != 5 {
		t.Fatalf("expected 5 entries, got %d", db.Count())
	}

	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{Action: rules.ActionDrop, GeoIP: rules.ParseGeoIPSpec("RU"), Direction: rules.DirIn})
	n := &NftablesEnforcer{geoDB: db}
	script := n.buildScript(rs)
	t.Log(script)

	if !strings.Contains(script, "set geoip_RU {") {
		t.Fatal("missing set geoip_RU definition")
	}
	if !strings.Contains(script, "ip saddr != @geoip_RU drop") {
		t.Fatalf("expected 'ip saddr != @geoip_RU drop', got:\n%s", script)
	}
	// RU 的三条 CIDR 必须都作为集合元素出现
	for _, c := range []string{"5.255.192.0/18", "95.213.0.0/16", "178.176.0.0/13"} {
		if !strings.Contains(script, c) {
			t.Errorf("RU CIDR %s missing from geoip_RU set, got:\n%s", c, script)
		}
	}
	// 集合必须按国家隔离：CN 的 CIDR 不得出现在 geoip_RU 集合里
	if strings.Contains(script, "geoip_RU") && strings.Contains(script, "9.9.9.0/24") {
		t.Errorf("CN CIDR leaked into geoip_RU set, got:\n%s", script)
	}
}

// 内核限速（按源）：accept 规则应额外生成 meter 动态集 + limit rate over 的"超限丢弃"语句，
// 实现"单源限速、超限即丢"。此前该能力只在用户态 engine 生效，内核强制模式是空操作。
func TestRuleLimitStmtsRatePerSrc(t *testing.T) {
	proto := uint8(6)
	r := rules.NewRule(rules.ActionAccept)
	r.Protocol = &proto
	r.DstPort = rules.ParsePortSpec("22")
	r.Direction = rules.DirIn
	r.RateLimit = rules.ParseRateLimit(5, 10, true)
	n := &NftablesEnforcer{}
	got := n.ruleLimitStmts(r, "input")
	if len(got) != 1 {
		t.Fatalf("expected 1 limit stmt, got %d: %v", len(got), got)
	}
	want := "tcp dport 22 meter gofw_meter_1 size 65535 { ip saddr timeout 1m limit rate over 5/second burst 10 packets } drop"
	if got[0] != want {
		t.Errorf("per-src rate limit mismatch:\n got: %q\nwant: %q", got[0], want)
	}
	if notes := n.DegradationNotes(); len(notes) != 0 {
		t.Errorf("rate limit must not be degraded, got %v", notes)
	}
}

// 全局限速（非 per_src）：无 meter，直接 limit rate over ... drop。
func TestRuleLimitStmtsRateGlobal(t *testing.T) {
	proto := uint8(6)
	r := rules.NewRule(rules.ActionAccept)
	r.Protocol = &proto
	r.DstPort = rules.ParsePortSpec("443")
	r.Direction = rules.DirIn
	r.RateLimit = rules.ParseRateLimit(100, 0, false)
	n := &NftablesEnforcer{}
	got := n.ruleLimitStmts(r, "input")
	want := "tcp dport 443 limit rate over 100/second burst 100 packets drop"
	if len(got) != 1 || got[0] != want {
		t.Errorf("global rate limit mismatch: got %v", got)
	}
}

// 并发连接数限制（按源）：nft v1.0.2 内核不支持 meter/set + ct count，
// 必须显式降级为全局 ct count 并通过 DegradationNotes 告知，绝不生成非法语句。
func TestRuleLimitStmtsConnPerSrc(t *testing.T) {
	proto := uint8(6)
	r := rules.NewRule(rules.ActionAccept)
	r.Protocol = &proto
	r.DstPort = rules.ParsePortSpec("80,443")
	r.Direction = rules.DirIn
	r.ConnLimit = rules.ParseConnLimit(200, true)
	n := &NftablesEnforcer{}
	got := n.ruleLimitStmts(r, "input")
	if len(got) != 1 {
		t.Fatalf("expected 1 stmt, got %v", got)
	}
	want := "tcp dport { 80, 443 } ct state new ct count over 200 drop"
	if got[0] != want {
		t.Errorf("degraded per-src conn limit mismatch:\n got: %q\nwant: %q", got[0], want)
	}
	if strings.Contains(got[0], "meter") {
		t.Errorf("degraded conn limit must not contain meter: %q", got[0])
	}
	if notes := n.DegradationNotes(); len(notes) == 0 {
		t.Error("conn limit degradation must be reported via DegradationNotes")
	}
}

// nft v1.0.2 语法回归：meter 必须带唯一集合名、drop 必须在花括号外。
// 旧实现生成 `meter size 65535 { ... drop }`，nft -c -f 直接报语法错误，
// 导致整套规则集无法下发内核（全量预检才暴露）。
func TestBuildScriptMeterSyntax(t *testing.T) {
	rs := rules.NewRuleSet()
	rs.DefaultAction = rules.ActionAccept
	for i := 0; i < 3; i++ {
		proto := uint8(6)
		r := rules.NewRule(rules.ActionAccept)
		r.Protocol = &proto
		r.DstPort = rules.ParsePortSpec(fmt.Sprintf("%d", 1000+i))
		r.Direction = rules.DirIn
		r.RateLimit = rules.ParseRateLimit(5, 10, true)
		rs.Add(r)
	}
	n := &NftablesEnforcer{}
	script := n.buildScript(rs)
	if strings.Contains(script, "meter size") {
		t.Errorf("meter without a set name is invalid on nft v1.0.2:\n%s", script)
	}
	if strings.Contains(script, " drop }") {
		t.Errorf("verdict must be outside the meter braces:\n%s", script)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(script, "\n") {
		if !strings.Contains(line, "meter ") {
			continue
		}
		if !strings.HasSuffix(strings.TrimSpace(line), "} drop") {
			t.Errorf("meter stmt must end with '} drop': %q", line)
		}
		idx := strings.Index(line, "meter ")
		rest := line[idx+len("meter "):]
		name := strings.SplitN(rest, " ", 2)[0]
		if !strings.HasPrefix(name, "gofw_meter_") {
			t.Errorf("unexpected meter name %q", name)
		}
		if seen[name] {
			t.Errorf("duplicate meter name %q in one script:\n%s", name, script)
		}
		seen[name] = true
	}
	if len(seen) < 3 {
		t.Errorf("expected at least 3 distinct meters, got %d", len(seen))
	}
}

// drop 规则不应生成任何限速语句（本就全丢，限速门无意义）。
func TestRuleLimitStmtsDropRuleEmpty(t *testing.T) {
	proto := uint8(6)
	r := rules.NewRule(rules.ActionDrop)
	r.Protocol = &proto
	r.DstPort = rules.ParsePortSpec("22")
	r.RateLimit = rules.ParseRateLimit(5, 10, true)
	n := &NftablesEnforcer{}
	if stmts := n.ruleLimitStmts(r, "input"); len(stmts) != 0 {
		t.Errorf("drop rule must not emit limit stmts, got %v", stmts)
	}
}

// buildScript 中限速语句应排在主放行语句之前（先丢超限包，再放行未超限包）。
func TestBuildScriptRateOrderBeforeAccept(t *testing.T) {
	proto := uint8(6)
	r := rules.NewRule(rules.ActionAccept)
	r.Protocol = &proto
	r.DstPort = rules.ParsePortSpec("22")
	r.Direction = rules.DirIn
	r.RateLimit = rules.ParseRateLimit(5, 10, true)
	rs := rules.NewRuleSet()
	rs.Add(r)
	n := &NftablesEnforcer{}
	script := n.buildScript(rs)
	t.Log(script)
	iLimit := strings.Index(script, "limit rate over 5/second burst 10 packets } drop")
	iAccept := strings.Index(script, "tcp dport 22 accept")
	if iLimit < 0 || iAccept < 0 {
		t.Fatalf("expected both limit and accept in script:\n%s", script)
	}
	if iLimit > iAccept {
		t.Errorf("limit stmt must precede accept stmt:\n%s", script)
	}
}

// NULL 扫描（set 为空 + mask 全标志）：应编译为 "tcp flags & (mask) == 0" 形式，
// 匹配所有标志位均为 0 的隐蔽扫描包。此前 TCPFlags==0 时整段匹配被跳过，无法表达。
func TestRuleToNftNullScan(t *testing.T) {
	proto := uint8(6)
	r := rules.NewRule(rules.ActionDrop)
	r.Protocol = &proto
	r.Direction = rules.DirIn
	r.TCPFlagsMask = 0x3f // fin|syn|rst|psh|ack|urg
	n := &NftablesEnforcer{}
	got := n.ruleToNft(r, "input")
	if !strings.Contains(got, "tcp flags & (") || !strings.Contains(got, ") == (0) drop") {
		t.Errorf("null scan should compile to 'tcp flags & (mask) == (0) drop', got %q", got)
	}
	for _, f := range []string{"fin", "syn", "rst", "psh", "ack", "urg"} {
		if !strings.Contains(got, f) {
			t.Errorf("null scan mask should contain %s, got %q", f, got)
		}
	}
}

// 回归：direction:in 的规则只允许出现在 input 链。
// 若在 output/forward 链退化成无匹配器的裸 accept/drop，会误放行/误丢弃全链流量。
func TestDirectionInOnlyInputChain(t *testing.T) {
	proto := uint8(6)
	r := rules.NewRule(rules.ActionAccept)
	r.Protocol = &proto
	r.DstPort = rules.ParsePortSpec("22")
	r.Direction = rules.DirIn
	r.RateLimit = rules.ParseRateLimit(5, 10, true)
	rs := rules.NewRuleSet()
	rs.Add(r)
	n := &NftablesEnforcer{}
	script := n.buildScript(rs)
	t.Log(script)
	// output 链与 forward 链的链身（去掉链头 type/policy 声明行）必须没有任何规则语句
	for _, chain := range []string{"chain output {", "chain forward {"} {
		i := strings.Index(script, chain)
		if i < 0 {
			t.Fatalf("script missing %s:\n%s", chain, script)
		}
		rest := script[i+len(chain):]
		if j := strings.Index(rest, "}"); j >= 0 {
			rest = rest[:j]
		}
		var body []string
		for _, line := range strings.Split(rest, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "type filter") {
				body = append(body, line)
			}
		}
		if len(body) != 0 {
			t.Errorf("%s must have no rule statements, got %d:\n%s", chain, len(body), script)
		}
	}
}

// 回归：GeoIP 库缺数据的规则必须整条跳过，
// 不得退化成无匹配器的裸 accept/drop（否则会误杀全网或误放行）。
func TestGeoIPMissingDataNotBareAction(t *testing.T) {
	db := geoip.NewWithBuiltin() // 内置库无 ZZ
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{Action: rules.ActionDrop, GeoIP: rules.ParseGeoIPSpec("ZZ"), Direction: rules.DirIn})
	n := &NftablesEnforcer{geoDB: db}
	script := n.buildScript(rs)
	t.Log(script)
	// 三条链都只能是空链（除链头声明外无任何语句）
	for _, chain := range []string{"chain input {", "chain output {", "chain forward {"} {
		i := strings.Index(script, chain)
		if i < 0 {
			continue
		}
		rest := script[i:]
		if j := strings.Index(rest, "}"); j >= 0 {
			rest = rest[:j]
		}
		body := strings.TrimSpace(rest[len(chain):])
		if body != "" && !strings.Contains(body, "policy") {
			t.Errorf("%s should be empty, got:\n%s", chain, script)
		}
	}
}

// 生产规则(deploy/rules-prod.yaml)必须能被完整加载并编译出全部关键内核语句：
// 每源限速、并发限制、ICMP flood 限速、NULL 扫描、GeoIP 国家拦截等。
func TestBuildScriptProdRules(t *testing.T) {
	rs, err := config.Load("../deploy/rules-prod.yaml")
	if err != nil {
		t.Fatal(err)
	}
	db := geoip.NewWithBuiltin()
	n := &NftablesEnforcer{geoDB: db}
	script := n.buildScript(rs)
	t.Log(script)
	for _, want := range []string{
		// SSH 每源限速（meter 带唯一集合名，drop 在花括号外）
		"limit rate over 5/second burst 10 packets } drop",
		// Web 每源并发限制：内核不支持 per-src ct count，降级为全局计数
		"ct state new ct count over 200 drop",
		// ICMP flood 每源限速
		"limit rate over 50/second burst 100 packets } drop",
		// NULL 扫描
		"== (0) drop",
		// GeoIP 俄罗斯拦截
		"ip saddr @geoip_RU drop",
		// established 优先放行
		"ct state established accept",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("prod script missing %q\n%s", want, script)
		}
	}
}
