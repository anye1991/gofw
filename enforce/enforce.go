// Package enforce 实现可插拔执行后端。
package enforce

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"

	"gofw/engine"
	"gofw/packet"
	"gofw/rules"
)

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
	var sb strings.Builder
	// filter 表
	sb.WriteString("table inet gofw {\n")
	sb.WriteString("    chain input {\n")
	sb.WriteString(fmt.Sprintf("        type filter hook input priority 0; policy %s;\n", def))
	for _, r := range rs.Rules {
		if r.NAT != nil {
			continue // NAT 规则放到 nat 表
		}
		if stmt := n.ruleToNft(r, "input"); stmt != "" {
			sb.WriteString("        " + stmt + "\n")
		}
	}
	sb.WriteString("    }\n")
	sb.WriteString("    chain output {\n")
	sb.WriteString(fmt.Sprintf("        type filter hook output priority 0; policy %s;\n", def))
	for _, r := range rs.Rules {
		if r.NAT != nil {
			continue
		}
		if stmt := n.ruleToNft(r, "output"); stmt != "" {
			sb.WriteString("        " + stmt + "\n")
		}
	}
	sb.WriteString("    }\n")
	sb.WriteString("    chain forward {\n")
	sb.WriteString(fmt.Sprintf("        type filter hook forward priority 0; policy %s;\n", def))
	for _, r := range rs.Rules {
		if r.NAT != nil {
			continue
		}
		if stmt := n.ruleToNft(r, "forward"); stmt != "" {
			sb.WriteString("        " + stmt + "\n")
		}
	}
	sb.WriteString("    }\n")
	sb.WriteString("}\n")

	// nat 表（IPv4）
	n.writeNATTable(&sb, rs, "ip", false)
	// nat 表（IPv6）
	n.writeNATTable(&sb, rs, "ip6", true)
	return sb.String()
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

func (n *NftablesEnforcer) ruleToNft(r *rules.Rule, chain string) string {
	// 方向过滤：in→input, out→output, any→所有链（含 forward）
	switch r.Direction {
	case rules.DirIn:
		if chain != "input" {
			return ""
		}
	case rules.DirOut:
		if chain != "output" {
			return ""
		}
	}
	var matchers []string

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
			if r.TCPFlags != 0 {
				setNames := flagNames(r.TCPFlags)
				mask := r.TCPFlagsMask
				if mask == 0 {
					mask = r.TCPFlags
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
	if r.State != "" {
		matchers = append(matchers, "ct state "+r.State)
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
