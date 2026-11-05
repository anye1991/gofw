// Package enforce 实现可插拔执行后端。
package enforce

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	"gofw/engine"
	"gofw/geoip"
	"gofw/packet"
	"gofw/rules"
)

// geoRuleInfo 一条 geoip 规则在内核侧的编译结果。
type geoRuleInfo struct {
	setName   string // IPv4 集合名，如 geoip_RU / geoip_CN_US
	setNameV6 string // IPv6 集合名，如 geoip_RU_v6（库中无 v6 段时为空）
	negate    bool   // deny 模式为 true：匹配"不属于集合"（ip saddr != @set）
	skip      bool   // 引用的国家库里无数据，整条规则跳过并告警
	skipV4    bool   // 该国无 IPv4 段，跳过 v4 语句（避免引用空集合）
}

// Enforcer 执行后端接口。
type Enforcer interface {
	Apply(rs *rules.RuleSet) bool
	OnDecision(d engine.Decision)
	Flush()
	Available() bool
	Name() string
}

// MonitorEnforcer 仅记录决策，不改动数据包路径（始终可用）。
type MonitorEnforcer struct {
	appliedRules int
}

func (m *MonitorEnforcer) Name() string { return "MonitorEnforcer" }

func (m *MonitorEnforcer) Apply(rs *rules.RuleSet) bool {
	m.appliedRules = rs.Len()
	log.Printf("[monitor] loaded %d rules, default=%s", rs.Len(), rs.DefaultAction)
	return true
}

func (m *MonitorEnforcer) OnDecision(d engine.Decision) {
	p := d.Packet
	ruleInfo := "default-policy"
	if d.Rule != nil {
		ruleInfo = d.Rule.Comment
		if ruleInfo == "" {
			ruleInfo = ruleStr(d.Rule)
		}
	}
	extra := ""
	if d.Action == rules.ActionReject {
		switch p.Proto {
		case packet.ProtoTCP:
			extra = " (reject-with tcp-rst)"
		default:
			extra = " (reject-with icmp-port-unreachable)"
		}
	}
	if d.Rule != nil && d.Rule.NAT != nil {
		extra += fmt.Sprintf(" nat=%s", d.Rule.NAT.Type)
	}
	log.Printf("%-7s %s state=%-11s [%s]%s", d.Action, p.Summary(), d.ConnState, ruleInfo, extra)
}

func (m *MonitorEnforcer) Flush() { m.appliedRules = 0 }

func (m *MonitorEnforcer) Available() bool { return true }

func ruleStr(r *rules.Rule) string {
	if r == nil {
		return "no-match"
	}
	return r.String()
}

// NftablesEnforcer 将规则集翻译为 nftables 规则并下发到内核。
type NftablesEnforcer struct {
	nftPath string
	avail   *bool
	geoDB   *geoip.DB // GeoIP 库，用于把国家码编译成内核集合

	// 以下字段仅在 buildScript 单次调用期间有效，用于 ruleToNft 复用预编译结果
	geoSets   map[string][]string // IPv4 集合名 -> CIDR 元素
	geoSetsV6 map[string][]string // IPv6 集合名 -> CIDR 元素
	geoInfo   map[*rules.Rule]*geoRuleInfo

	// banProvider 返回当前临时封禁的 IP（按地址族分开），由 main.go 注入。
	// 每次 Apply 时读取，使动态封禁随规则热替换一起下发内核。
	banProvider func() (v4, v6 []string)
}

// SetBanProvider 注入临时封禁列表提供者（来自 geoctl.Tracker）。
func (n *NftablesEnforcer) SetBanProvider(fn func() (v4, v6 []string)) {
	n.banProvider = fn
}

func (n *NftablesEnforcer) Name() string { return "NftablesEnforcer" }

func (n *NftablesEnforcer) Available() bool {
	if n.avail != nil {
		return *n.avail
	}
	path, err := exec.LookPath("nft")
	if err != nil {
		n.avail = boolPtr(false)
		return false
	}
	n.nftPath = path
	// 实测权限
	cmd := exec.Command(path, "list", "tables")
	err = cmd.Run()
	ok := err == nil
	n.avail = &ok
	return ok
}

func boolPtr(b bool) *bool { return &b }

// SetGeoIP 注入 GeoIP 库，使 geoip 规则能被编译进内核匹配集合。
// 不调用则不编译 geoip（相关规则在 buildScript 时被跳过并告警）。
func (n *NftablesEnforcer) SetGeoIP(db *geoip.DB) {
	n.geoDB = db
}

func (n *NftablesEnforcer) Apply(rs *rules.RuleSet) bool {
	if !n.Available() {
		return false
	}
	// 先删除旧表（表不存在时忽略错误），保证规则集是替换而非追加
	exec.Command(n.nftPath, "delete", "table", "inet", "gofw").Run()
	exec.Command(n.nftPath, "delete", "table", "ip", "gofw_nat").Run()
	exec.Command(n.nftPath, "delete", "table", "ip6", "gofw_nat").Run()

	script := n.buildScript(rs)
	cmd := exec.Command(n.nftPath, "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[nftables] apply failed: %s", strings.TrimSpace(string(out)))
		return false
	}
	log.Printf("[nftables] applied %d rules (default=%s)", rs.Len(), rs.DefaultAction)
	return true
}

func (n *NftablesEnforcer) Flush() {
	if !n.Available() {
		return
	}
	exec.Command(n.nftPath, "delete", "table", "inet", "gofw").Run()
	exec.Command(n.nftPath, "delete", "table", "ip", "gofw_nat").Run()
	exec.Command(n.nftPath, "delete", "table", "ip6", "gofw_nat").Run()
}

func (n *NftablesEnforcer) OnDecision(d engine.Decision) {
	switch d.Action {
	case rules.ActionDrop:
		log.Printf("DROP %s state=%s", d.Packet.Summary(), d.ConnState)
	case rules.ActionReject:
		log.Printf("REJECT %s state=%s", d.Packet.Summary(), d.ConnState)
	}
}

func (n *NftablesEnforcer) buildScript(rs *rules.RuleSet) string {
	def := "drop"
	if rs.DefaultAction == rules.ActionAccept {
		def = "accept"
	}

	// 预编译 geoip 规则：把规则里出现的国家码编译成内核集合（v4 / v6 分开）
	n.geoSets, n.geoSetsV6, n.geoInfo = n.compileGeoIP(rs)
	defer func() {
		n.geoSets = nil
		n.geoSetsV6 = nil
		n.geoInfo = nil
	}()

	// 当前临时封禁 IP（决策层已生效；内核层再补一层，确保 nftables 模式下也真正丢弃）
	var banV4, banV6 []string
	if n.banProvider != nil {
		banV4, banV6 = n.banProvider()
	}

	var sb strings.Builder
	// filter 表
	sb.WriteString("table inet gofw {\n")

	// GeoIP IPv4 命名集合（type ipv4_addr; flags interval），须在引用它的链之前声明
	if len(n.geoSets) > 0 {
		names := make([]string, 0, len(n.geoSets))
		for name := range n.geoSets {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			sb.WriteString(fmt.Sprintf("    set %s {\n", name))
			sb.WriteString("        type ipv4_addr\n")
			sb.WriteString("        flags interval\n")
			sb.WriteString("        elements = { " + strings.Join(n.geoSets[name], ", ") + " }\n")
			sb.WriteString("    }\n")
		}
	}
	// GeoIP IPv6 命名集合（type ipv6_addr），与 v4 集合分开声明
	if len(n.geoSetsV6) > 0 {
		names := make([]string, 0, len(n.geoSetsV6))
		for name := range n.geoSetsV6 {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			sb.WriteString(fmt.Sprintf("    set %s {\n", name))
			sb.WriteString("        type ipv6_addr\n")
			sb.WriteString("        flags interval\n")
			sb.WriteString("        elements = { " + strings.Join(n.geoSetsV6[name], ", ") + " }\n")
			sb.WriteString("    }\n")
		}
	}
	// 动态临时封禁集合（自动封禁 + 手动封禁）
	if len(banV4) > 0 {
		sb.WriteString("    set gofw_ban_v4 {\n")
		sb.WriteString("        type ipv4_addr\n")
		sb.WriteString("        flags interval\n")
		sb.WriteString("        elements = { " + strings.Join(banV4, ", ") + " }\n")
		sb.WriteString("    }\n")
	}
	if len(banV6) > 0 {
		sb.WriteString("    set gofw_ban_v6 {\n")
		sb.WriteString("        type ipv6_addr\n")
		sb.WriteString("        flags interval\n")
		sb.WriteString("        elements = { " + strings.Join(banV6, ", ") + " }\n")
		sb.WriteString("    }\n")
	}

	// banStmts 生成链首的封禁丢弃语句（优先级高于其余规则）
	banStmts := func() string {
		var s string
		if len(banV4) > 0 {
			s += "        ip saddr @gofw_ban_v4 drop comment \"gofw auto-ban\"\n"
		}
		if len(banV6) > 0 {
			s += "        ip6 saddr @gofw_ban_v6 drop comment \"gofw auto-ban\"\n"
		}
		return s
	}

	// writeRule 输出一条规则在该链上的 v4 语句，以及 geoip 规则的 v6 变体。
	writeRule := func(r *rules.Rule, chain string) {
		if r.NAT != nil {
			return // NAT 规则放到 nat 表
		}
		for _, ls := range n.ruleLimitStmts(r, chain) {
			sb.WriteString("        " + ls + "\n")
		}
		if stmt := n.ruleToNftGeo(r, chain, false); stmt != "" {
			sb.WriteString("        " + stmt + "\n")
		}
		if r.GeoIP != nil {
			if stmt6 := n.ruleToNftGeo(r, chain, true); stmt6 != "" {
				sb.WriteString("        " + stmt6 + "\n")
			}
		}
	}

	sb.WriteString("    chain input {\n")
	sb.WriteString(fmt.Sprintf("        type filter hook input priority 0; policy %s;\n", def))
	sb.WriteString(banStmts())
	for _, r := range rs.Rules {
		writeRule(r, "input")
	}
	sb.WriteString("    }\n")
	sb.WriteString("    chain output {\n")
	sb.WriteString(fmt.Sprintf("        type filter hook output priority 0; policy %s;\n", def))
	sb.WriteString(banStmts())
	for _, r := range rs.Rules {
		writeRule(r, "output")
	}
	sb.WriteString("    }\n")
	sb.WriteString("    chain forward {\n")
	sb.WriteString(fmt.Sprintf("        type filter hook forward priority 0; policy %s;\n", def))
	sb.WriteString(banStmts())
	for _, r := range rs.Rules {
		writeRule(r, "forward")
	}
	sb.WriteString("    }\n")
	sb.WriteString("}\n")

	// nat 表（IPv4）
	n.writeNATTable(&sb, rs, "ip", false)
	// nat 表（IPv6）
	n.writeNATTable(&sb, rs, "ip6", true)
	return sb.String()
}

// compileGeoIP 预扫描规则集，把每条 geoip 规则编译成内核集合信息。
// 返回的 geoSets 为 集合名 -> 元素(CIDR)列表；geoInfo 为 规则 -> 编译结果。
// 语义与用户态 engine 的 GeoIPSpec.Matches 完全一致：
//   - deny 模式（如 geoip: RU）：匹配"不属于列表国家" → 内核 matcher 用 "!=" 取反
//   - allow 模式（如 geoip: allow:CN）：匹配"属于列表国家" → 内核 matcher 直接命中
// 若规则引用的国家在本机 GeoIP 库里没有任何网段，则整条规则跳过并告警，
// 避免生成空集合导致 "ip saddr != @空集" 命中全部流量而误杀全网。
func (n *NftablesEnforcer) compileGeoIP(rs *rules.RuleSet) (map[string][]string, map[string][]string, map[*rules.Rule]*geoRuleInfo) {
	sets := map[string][]string{}
	setsV6 := map[string][]string{}
	info := map[*rules.Rule]*geoRuleInfo{}

	hasDB := n.geoDB != nil && n.geoDB.Loaded()
	for _, r := range rs.Rules {
		if r.GeoIP == nil || !r.GeoIP.Enabled() {
			continue
		}
		if !hasDB {
			log.Printf("[geoip] WARN: GeoIP 库未加载，跳过规则: %s", r.String())
			info[r] = &geoRuleInfo{skip: true}
			continue
		}
		codes := sortedCountryCodes(r.GeoIP)
		if len(codes) == 0 {
			info[r] = &geoRuleInfo{skip: true}
			continue
		}
		var elemsV4, elemsV6 []string
		missing := false
		for _, c := range codes {
			v4, v6 := n.geoDB.CIDRsForCountrySplit(c)
			if len(v4) == 0 && len(v6) == 0 {
				log.Printf("[geoip] WARN: 国家 %s 不在 GeoIP 库中，跳过规则: %s", c, r.String())
				missing = true
				break
			}
			elemsV4 = append(elemsV4, v4...)
			elemsV6 = append(elemsV6, v6...)
		}
		if missing {
			info[r] = &geoRuleInfo{skip: true}
			continue
		}
		base := "geoip_" + strings.Join(codes, "_")
		setName := base
		setNameV6 := ""
		if len(elemsV4) > 0 {
			sets[setName] = dedupSorted(elemsV4)
		}
		if len(elemsV6) > 0 {
			setNameV6 = base + "_v6"
			setsV6[setNameV6] = dedupSorted(elemsV6)
		}
		info[r] = &geoRuleInfo{
			setName:   setName,
			setNameV6: setNameV6,
			negate:    r.GeoIP.Mode == "deny",
			skipV4:    len(elemsV4) == 0, // 仅有 v6 数据时跳过 v4 语句，避免引用空集合
		}
	}
	return sets, setsV6, info
}

func sortedCountryCodes(g *rules.GeoIPSpec) []string {
	if g == nil || len(g.Countries) == 0 {
		return nil
	}
	codes := make([]string, 0, len(g.Countries))
	for c := range g.Countries {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	return codes
}

func dedupSorted(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

// ruleIsIPv6 判断规则是否涉及 IPv6（基于 src/dst IP 匹配器）。
func ruleIsIPv6(r *rules.Rule) bool {
	if r.SrcIP != nil && r.SrcIP.String() != "any" {
		if ip := net.ParseIP(strings.Split(r.SrcIP.String(), "/")[0]); ip != nil && ip.To4() == nil {
			return true
		}
	}
	if r.DstIP != nil && r.DstIP.String() != "any" {
		if ip := net.ParseIP(strings.Split(r.DstIP.String(), "/")[0]); ip != nil && ip.To4() == nil {
			return true
		}
	}
	if r.NAT != nil {
		if ip := net.ParseIP(r.NAT.ToSrcIP); ip != nil && ip.To4() == nil {
			return true
		}
		if ip := net.ParseIP(r.NAT.ToDstIP); ip != nil && ip.To4() == nil {
			return true
		}
	}
	return false
}

func (n *NftablesEnforcer) writeNATTable(sb *strings.Builder, rs *rules.RuleSet, family string, wantIPv6 bool) {
	hasNAT := false
	for _, r := range rs.Rules {
		if r.NAT != nil && ruleIsIPv6(r) == wantIPv6 {
			hasNAT = true
			break
		}
	}
	if !hasNAT {
		return
	}
	sb.WriteString(fmt.Sprintf("table %s gofw_nat {\n", family))
	sb.WriteString("    chain prerouting {\n")
	sb.WriteString("        type nat hook prerouting priority 0; policy accept;\n")
	for _, r := range rs.Rules {
		if r.NAT == nil || ruleIsIPv6(r) != wantIPv6 {
			continue
		}
		if r.NAT.Type == "dnat" {
			if stmt := n.natRuleToNft(r, "dnat", family); stmt != "" {
				sb.WriteString("        " + stmt + "\n")
			}
		}
	}
	sb.WriteString("    }\n")
	sb.WriteString("    chain postrouting {\n")
	sb.WriteString("        type nat hook postrouting priority 100; policy accept;\n")
	for _, r := range rs.Rules {
		if r.NAT == nil || ruleIsIPv6(r) != wantIPv6 {
			continue
		}
		if r.NAT.Type == "snat" || r.NAT.Type == "masquerade" {
			if stmt := n.natRuleToNft(r, r.NAT.Type, family); stmt != "" {
				sb.WriteString("        " + stmt + "\n")
			}
		}
	}
	sb.WriteString("    }\n")
	sb.WriteString("}\n")
}

// natRuleToNft 生成 NAT 规则语句。family 为 "ip" 或 "ip6"。
func (n *NftablesEnforcer) natRuleToNft(r *rules.Rule, natType, family string) string {
	var matchers []string
	if !r.SrcIP.Matches(nil) && r.SrcIP.String() != "any" {
		matchers = append(matchers, family+" saddr "+r.SrcIP.String())
	}
	if !r.DstIP.Matches(nil) && r.DstIP.String() != "any" {
		matchers = append(matchers, family+" daddr "+r.DstIP.String())
	}
	if r.Protocol != nil {
		switch *r.Protocol {
		case 6:
			if r.DstPort != nil {
				matchers = append(matchers, "tcp dport "+portSpec(r.DstPort))
			}
		case 17:
			if r.DstPort != nil {
				matchers = append(matchers, "udp dport "+portSpec(r.DstPort))
			}
		}
	}

	var stmt string
	switch natType {
	case "dnat":
		target := r.NAT.ToDstIP
		if r.NAT.ToDstPort != 0 {
			target += fmt.Sprintf(":%d", r.NAT.ToDstPort)
		}
		stmt = strings.Join(matchers, " ") + " dnat to " + target
	case "snat":
		target := r.NAT.ToSrcIP
		if r.NAT.ToSrcPort != 0 {
			target += fmt.Sprintf(":%d", r.NAT.ToSrcPort)
		}
		stmt = strings.Join(matchers, " ") + " snat to " + target
	case "masquerade":
		stmt = strings.Join(matchers, " ") + " masquerade"
	}
	if r.Comment != "" {
		stmt += fmt.Sprintf(" comment %q", r.Comment)
	}
	return stmt
}

// buildMatchers 生成规则在指定链上的匹配表达式（不含动作）。
// 方向过滤、VLAN、L3/L4、MAC、GeoIP、ct state 等匹配都在此组装，
// 供 ruleToNft（生成主语句）与 ruleLimitStmts（生成限速/并发的超限丢弃语句）复用。
// ok=false 表示整条规则在该链上应跳过（方向不匹配 / GeoIP 库缺数据），
// 调用方必须据此跳过，否则会退化成无匹配器的裸 accept/drop 误伤全网。
func (n *NftablesEnforcer) buildMatchers(r *rules.Rule, chain string) (matchers []string, ok bool) {
	return n.buildMatchersGeo(r, chain, false)
}

// buildMatchersGeo 生成匹配表达式。v6=true 时用于 geoip 规则的 IPv6 变体：
// 仅把 geoip 集合换成 v6 集合并改用 ip6 saddr/daddr；其余匹配保持原样。
// 非 geoip 规则在 v6=true 时返回 ok=false（nftables inet 族下一条语句已同时覆盖两族，
// 无需重复下发，否则会造成双份规则）。
func (n *NftablesEnforcer) buildMatchersGeo(r *rules.Rule, chain string, v6 bool) (matchers []string, ok bool) {
	// 方向过滤：in→input, out→output, any→所有链（含 forward）
	switch r.Direction {
	case rules.DirIn:
		if chain != "input" {
			return nil, false
		}
	case rules.DirOut:
		if chain != "output" {
			return nil, false
		}
	}

	// VLAN 标签匹配必须显式前置 "ether type vlan"，且位于 L3/L4 匹配之前。
	// 否则 nftables 会把同规则的 ip/tcp 等 L3/L4 匹配解析为 ether→ip 直接依赖，
	// 与 ether→vlan 依赖冲突，报 "conflicting protocols specified: ether vs. vlan"，
	// 导致整份规则集原子替换失败、gofw 进程退出（如 rules.yaml 的 "MySQL only from VLAN 10"）。
	if r.VLAN != nil {
		matchers = append(matchers, "ether type vlan", fmt.Sprintf("vlan id %d", *r.VLAN))
	}

	if r.Protocol != nil {
		proto := protoName(*r.Protocol)
		hasL4 := false
		if *r.Protocol == 6 { // TCP
			if r.DstPort != nil {
				matchers = append(matchers, "tcp dport "+portSpec(r.DstPort))
				hasL4 = true
			}
			if r.SrcPort != nil {
				matchers = append(matchers, "tcp sport "+portSpec(r.SrcPort))
				hasL4 = true
			}
			if r.TCPFlags != 0 || r.TCPFlagsMask != 0 {
				mask := r.TCPFlagsMask
				if mask == 0 {
					mask = r.TCPFlags
				}
				setNames := flagNames(r.TCPFlags)
				if setNames == "" {
					// NULL 扫描：掩码内所有标志位全为 0
					setNames = "0"
				}
				maskNames := flagNames(mask)
				matchers = append(matchers, fmt.Sprintf("tcp flags & (%s) == (%s)", maskNames, setNames))
				hasL4 = true
			}
		} else if *r.Protocol == 17 { // UDP
			if r.DstPort != nil {
				matchers = append(matchers, "udp dport "+portSpec(r.DstPort))
				hasL4 = true
			}
			if r.SrcPort != nil {
				matchers = append(matchers, "udp sport "+portSpec(r.SrcPort))
				hasL4 = true
			}
		}
		if !hasL4 {
			if proto == "icmp" || proto == "icmpv6" {
				matchers = append(matchers, "ip protocol "+proto)
			} else {
				matchers = append(matchers, proto)
			}
		}
	}

	if r.SrcMAC != nil && r.SrcMAC.String() != "any" {
		matchers = append(matchers, "ether saddr "+r.SrcMAC.String())
	}
	if r.DstMAC != nil && r.DstMAC.String() != "any" {
		matchers = append(matchers, "ether daddr "+r.DstMAC.String())
	}
	isV6 := ruleIsIPv6(r)
	fam := "ip"
	if isV6 {
		fam = "ip6"
	}
	if !r.SrcIP.Matches(nil) && r.SrcIP.String() != "any" {
		matchers = append(matchers, fam+" saddr "+r.SrcIP.String())
	}
	if !r.DstIP.Matches(nil) && r.DstIP.String() != "any" {
		matchers = append(matchers, fam+" daddr "+r.DstIP.String())
	}

	// GeoIP：下沉内核匹配（仅在 geoip 规则且已编译时）。
	// 入站/转发看源国家（ip saddr），出站看目标国家（ip daddr）。
	if n.geoInfo != nil {
		if gi := n.geoInfo[r]; gi != nil && r.GeoIP != nil {
			if v6 {
				// IPv6 变体：无 v6 数据则不下发这条，避免引用空集合。
				if gi.setNameV6 == "" {
					return nil, false
				}
				addr := "ip6 saddr"
				if chain == "output" {
					addr = "ip6 daddr"
				}
				if gi.negate {
					matchers = append(matchers, addr+" != "+"@"+gi.setNameV6)
				} else {
					matchers = append(matchers, addr+" "+"@"+gi.setNameV6)
				}
			} else {
				if gi.skip || gi.skipV4 {
					return nil, false // 库里缺数据，交由告警日志提示
				}
				addr := "ip saddr"
				if chain == "output" {
					addr = "ip daddr"
				}
				if gi.negate {
					matchers = append(matchers, addr+" != "+"@"+gi.setName)
				} else {
					matchers = append(matchers, addr+" "+"@"+gi.setName)
				}
			}
		}
	} else if v6 {
		return nil, false
	}
	// 非 geoip 规则不产出 v6 变体（inet 族单条语句已覆盖两族）
	if r.GeoIP == nil && v6 {
		return nil, false
	}

	if r.State != "" {
		matchers = append(matchers, "ct state "+r.State)
	}

	return matchers, true
}

// ruleToNft 生成规则在指定链上的完整语句（匹配 + 动作）。
// 方向不匹配 / GeoIP 缺数据时返回空串，由调用方跳过。
func (n *NftablesEnforcer) ruleToNft(r *rules.Rule, chain string) string {
	return n.ruleToNftGeo(r, chain, false)
}

// ruleToNftGeo 生成一条完整规则语句；v6=true 时生成 geoip 规则的 IPv6 变体。
func (n *NftablesEnforcer) ruleToNftGeo(r *rules.Rule, chain string, v6 bool) string {
	matchers, ok := n.buildMatchersGeo(r, chain, v6)
	if !ok {
		return ""
	}
	action := actionToNft(r.Action)
	stmt := action
	if len(matchers) > 0 {
		stmt = strings.Join(matchers, " ") + " " + action
	}
	if r.Comment != "" {
		stmt += fmt.Sprintf(" comment %q", r.Comment)
	}
	return stmt
}

// ruleLimitStmts 为带速率/并发/带宽限制且基础动作为“放行”的规则，
// 生成内核层的“超限即丢”语句。语义与用户态 engine.Match 的限速门一致：
// 规则已命中（按 L3/L4 匹配），若 rate/conn/bandwidth 超限则 DROP，未超限则落到放行主语句。
// 仅对 accept/log 类规则生成；drop 规则本就全丢，无需重复。
// 生成顺序在 buildScript 中位于主语句之前，确保超限包先被丢弃、未超限包再被放行。
func (n *NftablesEnforcer) ruleLimitStmts(r *rules.Rule, chain string) []string {
	if r.Action == rules.ActionDrop || r.Action == rules.ActionReject {
		return nil
	}
	base, ok := n.buildMatchers(r, chain)
	if !ok {
		return nil // 方向不匹配 / GeoIP 缺数据：整条跳过
	}
	var out []string
	// 速率限制（包/秒）：超限丢
	if r.RateLimit != nil && r.RateLimit.Rate > 0 {
		rate, burst := r.RateLimit.Rate, r.RateLimit.Burst
		if burst <= 0 {
			burst = rate
		}
		expr := fmt.Sprintf("limit rate over %d/second burst %d packets drop", rate, burst)
		out = append(out, n.limitStmt(base, expr, r.RateLimit.PerSrc))
	}
	// 并发连接数限制（仅新连接计数）：超限丢
	if r.ConnLimit != nil && r.ConnLimit.Max > 0 {
		expr := "ct state new ct count over " + strconv.Itoa(r.ConnLimit.Max) + " drop"
		// 若规则本身已带 ct state 匹配（如 established），避免重复 ct state 导致语法错误
		if hasCTState(base) {
			expr = "ct count over " + strconv.Itoa(r.ConnLimit.Max) + " drop"
		}
		out = append(out, n.limitStmt(base, expr, r.ConnLimit.PerSrc))
	}
	// 带宽限制（字节/秒）：超限丢
	if r.Bandwidth != nil && r.Bandwidth.BytesPerSec > 0 {
		expr := fmt.Sprintf("limit rate over %d bytes/second drop", r.Bandwidth.BytesPerSec)
		out = append(out, n.limitStmt(base, expr, r.Bandwidth.PerSrc))
	}
	return out
}

// limitStmt 把匹配表达式(base)与超限动作(expr)组装成内核语句。
// perSrc=true 时用按源 IP 的动态 meter（ip saddr 作键，带超时回收），
// 实现“每个来源独立限流/限连接”，更接近真实防爆破/抗 DDoS 语义。
func (n *NftablesEnforcer) limitStmt(base []string, expr string, perSrc bool) string {
	joined := strings.Join(base, " ")
	if perSrc {
		return fmt.Sprintf("%s meter size 65535 { ip saddr timeout 1m %s }", joined, expr)
	}
	if joined == "" {
		return expr
	}
	return joined + " " + expr
}

// hasCTState 判断匹配表达式中是否已含 ct state 子句。
func hasCTState(matchers []string) bool {
	for _, m := range matchers {
		if strings.Contains(m, "ct state") {
			return true
		}
	}
	return false
}

func portSpec(ps *rules.PortSpec) string {
	s := ps.String()
	if s == "any" {
		return ""
	}
	if strings.Contains(s, ",") {
		return "{ " + strings.ReplaceAll(s, ",", ", ") + " }"
	}
	return s
}

func flagNames(f uint8) string {
	var names []string
	for name, bit := range map[string]uint8{"syn": 0x02, "ack": 0x10, "fin": 0x01, "rst": 0x04, "psh": 0x08, "urg": 0x20} {
		if f&bit != 0 {
			names = append(names, name)
		}
	}
	return strings.Join(names, "|")
}

func actionToNft(action string) string {
	switch action {
	case rules.ActionAccept:
		return "accept"
	case rules.ActionLog:
		return "log accept"
	case rules.ActionReject:
		return "reject"
	}
	return "drop"
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 1:
		return "icmp"
	case 58:
		return "icmpv6"
	}
	return "any"
}

// BuildEnforcer 工厂：优先 nftables，不可用降级 monitor。
func BuildEnforcer(preferNft bool) Enforcer {
	if preferNft {
		nft := &NftablesEnforcer{}
		if nft.Available() {
			log.Printf("enforcement backend: nftables (kernel-level drop)")
			return nft
		}
		log.Printf("nftables unavailable (need CAP_NET_ADMIN); falling back to monitor mode")
	}
	return &MonitorEnforcer{}
}
