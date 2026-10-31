// Package config 从 YAML 加载规则集。
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"gofw/rules"

	"gopkg.in/yaml.v3"
)

type rawRuleset struct {
	Default  string            `yaml:"default" json:"default"`
	IPGroups map[string]string `yaml:"ip_groups" json:"ip_groups"`
	Rules    []rawRule         `yaml:"rules" json:"rules"`
}

type rawRule struct {
	Action     string      `yaml:"action" json:"action"`
	SrcIP      string      `yaml:"src_ip" json:"src_ip"`
	DstIP      string      `yaml:"dst_ip" json:"dst_ip"`
	SrcMAC     string      `yaml:"src_mac" json:"src_mac"`
	DstMAC     string      `yaml:"dst_mac" json:"dst_mac"`
	Protocol   string      `yaml:"protocol" json:"protocol"`
	SrcPort    interface{} `yaml:"src_port" json:"src_port"`
	DstPort    interface{} `yaml:"dst_port" json:"dst_port"`
	TCPFlags   interface{} `yaml:"tcp_flags" json:"tcp_flags"`
	Direction  string      `yaml:"direction" json:"direction"`
	State      string      `yaml:"state" json:"state"`
	VLAN       int         `yaml:"vlan" json:"vlan"`
	Time       string      `yaml:"time" json:"time"`
	RateLimit  int         `yaml:"rate_limit" json:"rate_limit"`
	Burst      int         `yaml:"burst" json:"burst"`
	PerSrc     bool        `yaml:"per_src" json:"per_src"`
	Bandwidth  float64     `yaml:"bandwidth" json:"bandwidth"` // Mbps
	BurstBytes int64       `yaml:"burst_bytes" json:"burst_bytes"`
	ConnLimit  int         `yaml:"conn_limit" json:"conn_limit"`
	GeoIP      string      `yaml:"geoip" json:"geoip"`
	AppProto   string      `yaml:"app_proto" json:"app_proto"`
	IPGroup    string      `yaml:"ip_group" json:"ip_group"`
	NAT        *rawNAT     `yaml:"nat" json:"nat"`
	Comment    string      `yaml:"comment" json:"comment"`
	Name       string      `yaml:"name" json:"name"`
}

type rawNAT struct {
	Type      string `yaml:"type" json:"type"`
	ToSrcIP   string `yaml:"to_src_ip" json:"to_src_ip"`
	ToSrcPort int    `yaml:"to_src_port" json:"to_src_port"`
	ToDstIP   string `yaml:"to_dst_ip" json:"to_dst_ip"`
	ToDstPort int    `yaml:"to_dst_port" json:"to_dst_port"`
}

func Load(path string) (*rules.RuleSet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadFromData(data)
}

// LoadFromData 从 YAML 字节数据加载规则集。
func LoadFromData(data []byte) (*rules.RuleSet, error) {
	var raw rawRuleset
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return raw.toRuleSet()
}

func (r rawRuleset) toRuleSet() (*rules.RuleSet, error) {
	def := strings.ToUpper(r.Default)
	if def == "" {
		def = rules.ActionDrop
	}
	if !validAction(def) {
		return nil, fmt.Errorf("invalid default action: %s", def)
	}
	rs := rules.NewRuleSet()
	rs.DefaultAction = def

	// 加载地址簿
	for name, spec := range r.IPGroups {
		rs.IPGroups[name] = rules.ParseIPMatcher(spec)
	}

	for i, rr := range r.Rules {
		rule, err := rr.toRule()
		if err != nil {
			return nil, fmt.Errorf("rule #%d: %w", i, err)
		}
		rs.Add(rule)
	}
	return rs, nil
}

func (r rawRule) toRule() (*rules.Rule, error) {
	action := strings.ToUpper(r.Action)
	if !validAction(action) {
		return nil, fmt.Errorf("invalid action: %s", r.Action)
	}
	rule := rules.NewRule(action)
	rule.SrcIP = rules.ParseIPMatcher(r.SrcIP)
	rule.DstIP = rules.ParseIPMatcher(r.DstIP)
	rule.SrcMAC = rules.ParseMACMatcher(r.SrcMAC)
	rule.DstMAC = rules.ParseMACMatcher(r.DstMAC)

	if r.Protocol != "" {
		p, ok := protoNum(strings.ToLower(r.Protocol))
		if !ok {
			return nil, fmt.Errorf("invalid protocol: %s", r.Protocol)
		}
		rule.Protocol = &p
	}

	if sp := portString(r.SrcPort); sp != "" {
		rule.SrcPort = rules.ParsePortSpec(sp)
	}
	if dp := portString(r.DstPort); dp != "" {
		rule.DstPort = rules.ParsePortSpec(dp)
	}

	if r.TCPFlags != nil {
		f, mask, err := parseTCPFlags(r.TCPFlags)
		if err != nil {
			return nil, err
		}
		rule.TCPFlags = f
		rule.TCPFlagsMask = mask
	}

	if r.Direction != "" {
		if !validDirection(r.Direction) {
			return nil, fmt.Errorf("invalid direction: %s", r.Direction)
		}
		rule.Direction = r.Direction
	}
	if r.State != "" {
		if !validState(r.State) {
			return nil, fmt.Errorf("invalid state: %s", r.State)
		}
		rule.State = r.State
	}
	if r.VLAN > 0 {
		v := uint16(r.VLAN)
		rule.VLAN = &v
	}
	if r.Time != "" {
		rule.Time = rules.ParseTimeSpec(r.Time)
	}
	if r.RateLimit > 0 {
		rule.RateLimit = rules.ParseRateLimit(r.RateLimit, r.Burst, r.PerSrc)
	}
	if r.Bandwidth > 0 {
		rule.Bandwidth = rules.ParseBandwidthLimit(r.Bandwidth, r.BurstBytes, r.PerSrc)
	}
	if r.ConnLimit > 0 {
		rule.ConnLimit = rules.ParseConnLimit(r.ConnLimit, r.PerSrc)
	}
	if r.GeoIP != "" {
		rule.GeoIP = rules.ParseGeoIPSpec(r.GeoIP)
	}
	if r.AppProto != "" {
		rule.AppProto = strings.ToLower(strings.TrimSpace(r.AppProto))
	}
	if r.IPGroup != "" {
		rule.IPGroup = r.IPGroup
	}
	if r.NAT != nil {
		natType := strings.ToLower(r.NAT.Type)
		switch natType {
		case "snat", "dnat", "masquerade":
		default:
			return nil, fmt.Errorf("invalid nat type %q (must be snat/dnat/masquerade)", r.NAT.Type)
		}
		rule.NAT = &rules.NATSpec{
			Type:      natType,
			ToSrcIP:   r.NAT.ToSrcIP,
			ToSrcPort: uint16(r.NAT.ToSrcPort),
			ToDstIP:   r.NAT.ToDstIP,
			ToDstPort: uint16(r.NAT.ToDstPort),
		}
	}
	rule.Comment = r.Comment
	rule.Name = r.Name
	return rule, nil
}

func portString(v interface{}) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case int:
		return strconv.Itoa(t)
	case []interface{}:
		var parts []string
		for _, item := range t {
			parts = append(parts, portString(item))
		}
		return strings.Join(parts, ",")
	}
	return fmt.Sprintf("%v", v)
}

func parseTCPFlags(v interface{}) (uint8, uint8, error) {
	switch t := v.(type) {
	case string:
		return flagSet(strings.Split(t, ",")), 0, nil
	case []interface{}:
		var items []string
		for _, item := range t {
			items = append(items, fmt.Sprintf("%v", item))
		}
		return flagSet(items), 0, nil
	case map[string]interface{}:
		set := flagSet(splitAny(t["set"]))
		mask := flagSet(splitAny(t["mask"]))
		return set, mask, nil
	}
	return 0, 0, fmt.Errorf("invalid tcp_flags")
}

func splitAny(v interface{}) []string {
	if v == nil {
		return nil
	}
	switch t := v.(type) {
	case string:
		return strings.Split(t, ",")
	case []interface{}:
		var out []string
		for _, item := range t {
			out = append(out, fmt.Sprintf("%v", item))
		}
		return out
	}
	return nil
}

func flagSet(items []string) uint8 {
	var f uint8
	flagMap := map[string]uint8{"syn": 0x02, "ack": 0x10, "fin": 0x01, "rst": 0x04, "psh": 0x08, "urg": 0x20}
	for _, item := range items {
		item = strings.TrimSpace(strings.ToLower(item))
		if bit, ok := flagMap[item]; ok {
			f |= bit
		}
	}
	return f
}

func protoNum(name string) (uint8, bool) {
	switch name {
	case "tcp":
		return 6, true
	case "udp":
		return 17, true
	case "icmp":
		return 1, true
	case "icmpv6":
		return 58, true
	}
	return 0, false
}

func validAction(a string) bool {
	switch a {
	case rules.ActionAccept, rules.ActionDrop, rules.ActionReject, rules.ActionLog:
		return true
	}
	return false
}

func validDirection(d string) bool {
	switch d {
	case rules.DirAny, rules.DirIn, rules.DirOut:
		return true
	}
	return false
}

func validState(s string) bool {
	switch s {
	case rules.StateNew, rules.StateEstablished, rules.StateRelated, rules.StateInvalid:
		return true
	}
	return false
}

// ParseRuleJSON 从 JSON 字节解析一条规则。JSON 字段与 YAML 配置字段一致。
func ParseRuleJSON(data []byte) (*rules.Rule, error) {
	var rr rawRule
	if err := json.Unmarshal(data, &rr); err != nil {
		return nil, fmt.Errorf("parse rule json: %w", err)
	}
	return rr.toRule()
}

// Save 将规则集序列化为 YAML 并写入文件。
func Save(rs *rules.RuleSet, path string) error {
	type outNAT struct {
		Type      string `yaml:"type"`
		ToSrcIP   string `yaml:"to_src_ip,omitempty"`
		ToSrcPort uint16 `yaml:"to_src_port,omitempty"`
		ToDstIP   string `yaml:"to_dst_ip,omitempty"`
		ToDstPort uint16 `yaml:"to_dst_port,omitempty"`
	}
	type outRateLimit struct {
		Rate   int  `yaml:"rate"`
		Burst  int  `yaml:"burst,omitempty"`
		PerSrc bool `yaml:"per_src,omitempty"`
	}
	type outRule struct {
		Action       string        `yaml:"action"`
		SrcIP        string        `yaml:"src_ip,omitempty"`
		DstIP        string        `yaml:"dst_ip,omitempty"`
		SrcMAC       string        `yaml:"src_mac,omitempty"`
		DstMAC       string        `yaml:"dst_mac,omitempty"`
		Protocol     string        `yaml:"protocol,omitempty"`
		SrcPort      string        `yaml:"src_port,omitempty"`
		DstPort      string        `yaml:"dst_port,omitempty"`
		TCPFlags     string        `yaml:"tcp_flags,omitempty"`
		TCPFlagsMask string        `yaml:"tcp_flags_mask,omitempty"`
		Direction    string        `yaml:"direction,omitempty"`
		State        string        `yaml:"state,omitempty"`
		VLAN         int           `yaml:"vlan,omitempty"`
		Time         string        `yaml:"time,omitempty"`
		RateLimit    *outRateLimit `yaml:"rate_limit,omitempty"`
		Bandwidth    float64       `yaml:"bandwidth,omitempty"`
		BurstBytes   int64         `yaml:"burst_bytes,omitempty"`
		ConnLimit    int           `yaml:"conn_limit,omitempty"`
		PerSrc       bool          `yaml:"per_src,omitempty"`
		GeoIP        string        `yaml:"geoip,omitempty"`
		AppProto     string        `yaml:"app_proto,omitempty"`
		IPGroup      string        `yaml:"ip_group,omitempty"`
		NAT          *outNAT       `yaml:"nat,omitempty"`
		Comment      string        `yaml:"comment,omitempty"`
		Name         string        `yaml:"name,omitempty"`
	}
	out := struct {
		Default  string            `yaml:"default"`
		IPGroups map[string]string `yaml:"ip_groups,omitempty"`
		Rules    []outRule         `yaml:"rules"`
	}{Default: strings.ToLower(rs.DefaultAction), IPGroups: rs.ExportIPGroups()}
	for _, r := range rs.Rules {
		or := outRule{Action: strings.ToLower(r.Action), Name: r.Name}
		if r.SrcIP.String() != "any" {
			or.SrcIP = r.SrcIP.String()
		}
		if r.DstIP.String() != "any" {
			or.DstIP = r.DstIP.String()
		}
		if r.SrcMAC.String() != "any" {
			or.SrcMAC = r.SrcMAC.String()
		}
		if r.DstMAC.String() != "any" {
			or.DstMAC = r.DstMAC.String()
		}
		if r.Protocol != nil {
			switch *r.Protocol {
			case 6:
				or.Protocol = "tcp"
			case 17:
				or.Protocol = "udp"
			case 1:
				or.Protocol = "icmp"
			case 58:
				or.Protocol = "icmpv6"
			}
		}
		if r.SrcPort != nil && r.SrcPort.String() != "any" {
			or.SrcPort = r.SrcPort.String()
		}
		if r.DstPort != nil && r.DstPort.String() != "any" {
			or.DstPort = r.DstPort.String()
		}
		if r.TCPFlags != 0 {
			or.TCPFlags = rules.TCPFlagsToString(r.TCPFlags)
			if r.TCPFlagsMask != 0 && r.TCPFlagsMask != r.TCPFlags {
				or.TCPFlagsMask = rules.TCPFlagsToString(r.TCPFlagsMask)
			}
		}
		if r.Direction != rules.DirAny {
			or.Direction = r.Direction
		}
		if r.State != "" {
			or.State = r.State
		}
		if r.VLAN != nil {
			or.VLAN = int(*r.VLAN)
		}
		if r.Time != nil && r.Time.String() != "" {
			or.Time = r.Time.String()
		}
		if r.RateLimit != nil && r.RateLimit.Rate > 0 {
			or.RateLimit = &outRateLimit{Rate: r.RateLimit.Rate, Burst: r.RateLimit.Burst, PerSrc: r.RateLimit.PerSrc}
		}
		if r.Bandwidth != nil && r.Bandwidth.BytesPerSec > 0 {
			mbps := float64(r.Bandwidth.BytesPerSec) * 8 / 1024 / 1024
			or.Bandwidth = mbps
			or.BurstBytes = r.Bandwidth.Burst
			or.PerSrc = r.Bandwidth.PerSrc
		}
		if r.ConnLimit != nil && r.ConnLimit.Max > 0 {
			or.ConnLimit = r.ConnLimit.Max
			or.PerSrc = r.ConnLimit.PerSrc
		}
		if r.GeoIP != nil {
			or.GeoIP = r.GeoIP.String()
		}
		if r.AppProto != "" {
			or.AppProto = r.AppProto
		}
		if r.IPGroup != "" {
			or.IPGroup = r.IPGroup
		}
		if r.NAT != nil {
			or.NAT = &outNAT{Type: r.NAT.Type, ToSrcIP: r.NAT.ToSrcIP, ToSrcPort: r.NAT.ToSrcPort,
				ToDstIP: r.NAT.ToDstIP, ToDstPort: r.NAT.ToDstPort}
		}
		if r.Comment != "" {
			or.Comment = r.Comment
		}
		out.Rules = append(out.Rules, or)
	}
	data, err := yaml.Marshal(out)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
