// Package rules 实现网络层防火墙规则匹配。
package rules

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// 动作
const (
	ActionAccept = "ACCEPT"
	ActionDrop   = "DROP"
	ActionReject = "REJECT"
	ActionLog    = "LOG"
)

// 方向
const (
	DirAny = "any"
	DirIn  = "in"
	DirOut = "out"
)

// 连接状态
const (
	StateNew         = "new"
	StateEstablished = "established"
	StateRelated     = "related"
	StateInvalid     = "invalid"
)

var tcpFlagMap = map[string]uint8{
	"syn": 0x02, "ack": 0x10, "fin": 0x01, "rst": 0x04, "psh": 0x08, "urg": 0x20,
}

// PortSpec 端口匹配。
type PortSpec struct {
	values map[uint16]struct{}
	ranges [][2]uint16
	any    bool
}

func ParsePortSpec(spec string) *PortSpec {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "any" {
		return &PortSpec{any: true}
	}
	ps := &PortSpec{values: make(map[uint16]struct{})}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") || strings.Contains(part, ":") {
			sep := "-"
			if strings.Contains(part, ":") {
				sep = ":"
			}
			ends := strings.SplitN(part, sep, 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(ends[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(ends[1]))
			if err1 != nil || err2 != nil {
				continue
			}
			if lo > hi {
				lo, hi = hi, lo
			}
			ps.ranges = append(ps.ranges, [2]uint16{uint16(lo), uint16(hi)})
		} else {
			v, err := strconv.Atoi(part)
			if err != nil {
				continue
			}
			ps.values[uint16(v)] = struct{}{}
		}
	}
	if len(ps.values) == 0 && len(ps.ranges) == 0 {
		ps.any = true
	}
	return ps
}

func (ps *PortSpec) Matches(port uint16) bool {
	if ps == nil || ps.any {
		return true
	}
	if _, ok := ps.values[port]; ok {
		return true
	}
	for _, r := range ps.ranges {
		if port >= r[0] && port <= r[1] {
			return true
		}
	}
	return false
}

func (ps *PortSpec) String() string {
	if ps == nil || ps.any {
		return "any"
	}
	// 收集并排序离散端口，保证输出稳定
	vals := make([]int, 0, len(ps.values))
	for v := range ps.values {
		vals = append(vals, int(v))
	}
	sort.Ints(vals)
	var parts []string
	for _, v := range vals {
		parts = append(parts, strconv.Itoa(v))
	}
	for _, r := range ps.ranges {
		parts = append(parts, strconv.Itoa(int(r[0]))+"-"+strconv.Itoa(int(r[1])))
	}
	return strings.Join(parts, ",")
}

// IPMatcher IP/CIDR 匹配。
type IPMatcher struct {
	nets []*net.IPNet
	any  bool
	raw  string // 原始规范字符串，用于序列化回写
}

func ParseIPMatcher(spec string) *IPMatcher {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "any" {
		return &IPMatcher{any: true, raw: ""}
	}
	m := &IPMatcher{raw: spec}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(part)
		if err != nil {
			ip := net.ParseIP(part)
			if ip == nil {
				continue
			}
			if ip.To4() != nil {
				ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
			} else {
				ipnet = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
			}
		}
		m.nets = append(m.nets, ipnet)
	}
	if len(m.nets) == 0 {
		m.any = true
	}
	return m
}

func (m *IPMatcher) Matches(ip net.IP) bool {
	if m == nil || m.any || ip == nil {
		return m == nil || m.any
	}
	for _, n := range m.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (m *IPMatcher) String() string {
	if m == nil || m.any {
		return "any"
	}
	if m.raw != "" {
		return m.raw
	}
	var parts []string
	for _, n := range m.nets {
		parts = append(parts, n.String())
	}
	return strings.Join(parts, ",")
}

// Raw 返回原始规范字符串。
func (m *IPMatcher) Raw() string {
	if m == nil {
		return ""
	}
	return m.raw
}

// MACMatcher MAC 地址匹配。
type MACMatcher struct {
	addrs []net.HardwareAddr
	any   bool
}

func ParseMACMatcher(spec string) *MACMatcher {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "any" {
		return &MACMatcher{any: true}
	}
	m := &MACMatcher{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		hw, err := net.ParseMAC(part)
		if err != nil {
			continue
		}
		m.addrs = append(m.addrs, hw)
	}
	if len(m.addrs) == 0 {
		m.any = true
	}
	return m
}

func (m *MACMatcher) Matches(hw net.HardwareAddr) bool {
	if m == nil || m.any {
		return true
	}
	for _, a := range m.addrs {
		if len(a) == len(hw) {
			equal := true
			for i := range a {
				if a[i] != hw[i] {
					equal = false
					break
				}
			}
			if equal {
				return true
			}
		}
	}
	return false
}

func (m *MACMatcher) String() string {
	if m == nil || m.any {
		return "any"
	}
	var parts []string
	for _, a := range m.addrs {
		parts = append(parts, a.String())
	}
	return strings.Join(parts, ",")
}

// TimeSpec 时间规则：HH:MM-HH:MM，可指定星期。
type TimeSpec struct {
	StartHour, StartMin int
	EndHour, EndMin     int
	Days                map[time.Weekday]bool // nil 表示每天
	enabled             bool
}

func ParseTimeSpec(spec string) *TimeSpec {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "any" {
		return &TimeSpec{enabled: false}
	}
	ts := &TimeSpec{enabled: true, Days: make(map[time.Weekday]bool)}
	parts := strings.SplitN(spec, " ", 2)
	rangeParts := strings.SplitN(parts[0], "-", 2)
	if len(rangeParts) == 2 {
		ts.StartHour, ts.StartMin = parseHHMM(rangeParts[0])
		ts.EndHour, ts.EndMin = parseHHMM(rangeParts[1])
	}
	if len(parts) == 2 {
		dayMap := map[string]time.Weekday{
			"mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
			"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday, "sun": time.Sunday,
		}
		for _, d := range strings.Split(parts[1], ",") {
			if wd, ok := dayMap[strings.ToLower(strings.TrimSpace(d))]; ok {
				ts.Days[wd] = true
			}
		}
		if len(ts.Days) == 0 {
			ts.Days = nil
		}
	}
	return ts
}

func parseHHMM(s string) (int, int) {
	parts := strings.SplitN(s, ":", 2)
	h, _ := strconv.Atoi(parts[0])
	m := 0
	if len(parts) == 2 {
		m, _ = strconv.Atoi(parts[1])
	}
	return h, m
}

// String 序列化为 "09:00-18:00 mon,tue,...,sun" 格式。
func (ts *TimeSpec) String() string {
	if ts == nil || !ts.enabled {
		return ""
	}
	s := fmt.Sprintf("%02d:%02d-%02d:%02d", ts.StartHour, ts.StartMin, ts.EndHour, ts.EndMin)
	if ts.Days != nil && len(ts.Days) > 0 {
		var names []string
		for _, wd := range []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday, time.Saturday, time.Sunday} {
			if ts.Days[wd] {
				names = append(names, wd.String()[:3])
			}
		}
		if len(names) > 0 {
			s += " " + strings.ToLower(strings.Join(names, ","))
		}
	}
	return s
}

func (ts *TimeSpec) Matches(now time.Time) bool {
	if ts == nil || !ts.enabled {
		return true
	}
	if ts.Days != nil && !ts.Days[now.Weekday()] {
		return false
	}
	cur := now.Hour()*60 + now.Minute()
	start := ts.StartHour*60 + ts.StartMin
	end := ts.EndHour*60 + ts.EndMin
	if start <= end {
		return cur >= start && cur <= end
	}
	// 跨天
	return cur >= start || cur <= end
}

// RateLimit 速率限制。
type RateLimit struct {
	Rate    int  // 每秒包数/连接数，0 表示不限
	Burst   int  // 突发
	PerSrc  bool // 按源 IP 分别限流
	enabled bool

	// 全局令牌桶（PerSrc=false 时使用）
	mu     sync.Mutex
	tokens int64
	last   int64

	// 按源 IP 的令牌桶（PerSrc=true 时使用）
	srcBuckets sync.Map // string(srcIP) -> *srcBucket
}

type srcBucket struct {
	mu     sync.Mutex
	tokens int64
	last   int64
}

func ParseRateLimit(rate, burst int, perSrc bool) *RateLimit {
	if rate <= 0 {
		return &RateLimit{enabled: false}
	}
	if burst <= 0 {
		burst = rate
	}
	return &RateLimit{
		Rate: rate, Burst: burst, PerSrc: perSrc, enabled: true,
		tokens: int64(burst), last: time.Now().UnixNano(),
	}
}

// Allow 检查是否允许通过。per-src 模式下按源 IP 分别计令牌。
func (r *RateLimit) Allow(src net.IP) bool {
	if r == nil || !r.enabled {
		return true
	}
	if r.PerSrc {
		key := ""
		if src != nil {
			key = src.String()
		}
		v, _ := r.srcBuckets.LoadOrStore(key, &srcBucket{
			tokens: int64(r.Burst),
			last:   time.Now().UnixNano(),
		})
		return r.consume(v.(*srcBucket))
	}
	return r.consumeGlobal()
}

// consumeGlobal 用 mutex 保证 refill+consume 原子性，避免 TOCTOU。
func (r *RateLimit) consumeGlobal() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UnixNano()
	elapsed := now - r.last
	add := elapsed * int64(r.Rate) / 1e9
	if add > 0 {
		r.tokens += add
		r.last = now
	}
	if r.tokens > int64(r.Burst) {
		r.tokens = int64(r.Burst)
	}
	if r.tokens > 0 {
		r.tokens--
		return true
	}
	return false
}

// consume 按源 IP 桶消耗令牌，同样用 mutex 保证原子性。
func (r *RateLimit) consume(b *srcBucket) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now().UnixNano()
	elapsed := now - b.last
	add := elapsed * int64(r.Rate) / 1e9
	if add > 0 {
		b.tokens += add
		b.last = now
	}
	if b.tokens > int64(r.Burst) {
		b.tokens = int64(r.Burst)
	}
	if b.tokens > 0 {
		b.tokens--
		return true
	}
	return false
}

// BandwidthLimit 带宽限制（基于字节的令牌桶）。
type BandwidthLimit struct {
	BytesPerSec int64 // 每秒字节数
	Burst       int64 // 突发字节数
	PerSrc      bool
	enabled     bool

	mu     sync.Mutex
	tokens int64
	last   int64

	srcBuckets sync.Map // string(srcIP) -> *bwBucket
}

type bwBucket struct {
	mu     sync.Mutex
	tokens int64
	last   int64
}

// ParseBandwidthLimit 解析带宽限制。mbps 为兆比特每秒。
func ParseBandwidthLimit(mbps float64, burstBytes int64, perSrc bool) *BandwidthLimit {
	if mbps <= 0 {
		return &BandwidthLimit{enabled: false}
	}
	bps := int64(mbps * 1024 * 1024 / 8) // Mbps -> bytes/sec
	if burstBytes <= 0 {
		burstBytes = bps // 默认突发 1 秒
	}
	return &BandwidthLimit{
		BytesPerSec: bps, Burst: burstBytes, PerSrc: perSrc, enabled: true,
		tokens: burstBytes, last: time.Now().UnixNano(),
	}
}

// Allow 检查包是否在带宽限制内。n 为包字节数。
func (b *BandwidthLimit) Allow(src net.IP, n int) bool {
	if b == nil || !b.enabled {
		return true
	}
	if b.PerSrc {
		key := ""
		if src != nil {
			key = src.String()
		}
		v, _ := b.srcBuckets.LoadOrStore(key, &bwBucket{
			tokens: b.Burst, last: time.Now().UnixNano(),
		})
		return b.consume(v.(*bwBucket), int64(n))
	}
	return b.consumeGlobal(int64(n))
}

func (b *BandwidthLimit) consumeGlobal(n int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now().UnixNano()
	elapsed := now - b.last
	add := elapsed * b.BytesPerSec / 1e9
	if add > 0 {
		b.tokens += add
		b.last = now
	}
	if b.tokens > b.Burst {
		b.tokens = b.Burst
	}
	if b.tokens >= n {
		b.tokens -= n
		return true
	}
	return false
}

func (b *BandwidthLimit) consume(bk *bwBucket, n int64) bool {
	bk.mu.Lock()
	defer bk.mu.Unlock()
	now := time.Now().UnixNano()
	elapsed := now - bk.last
	add := elapsed * b.BytesPerSec / 1e9
	if add > 0 {
		bk.tokens += add
		bk.last = now
	}
	if bk.tokens > b.Burst {
		bk.tokens = b.Burst
	}
	if bk.tokens >= n {
		bk.tokens -= n
		return true
	}
	return false
}

// ConnLimit 并发连接数限制。
type ConnLimit struct {
	Max     int  // 最大并发连接数
	PerSrc  bool // 按源 IP 分别限制
	enabled bool

	// 全局计数（PerSrc=false）
	globalCount int64 // 原子

	// 按源 IP 计数（PerSrc=true）
	srcCounts sync.Map // string(srcIP) -> *int64
}

// ParseConnLimit 解析连接数限制。
func ParseConnLimit(max int, perSrc bool) *ConnLimit {
	if max <= 0 {
		return &ConnLimit{enabled: false}
	}
	return &ConnLimit{Max: max, PerSrc: perSrc, enabled: true}
}

// Allow 检查是否允许新建连接。返回是否放行。
func (c *ConnLimit) Allow(src net.IP) bool {
	if c == nil || !c.enabled {
		return true
	}
	if c.PerSrc {
		key := ""
		if src != nil {
			key = src.String()
		}
		v, _ := c.srcCounts.LoadOrStore(key, new(int64))
		cnt := v.(*int64)
		if atomic.LoadInt64(cnt) >= int64(c.Max) {
			return false
		}
		atomic.AddInt64(cnt, 1)
		return true
	}
	if atomic.LoadInt64(&c.globalCount) >= int64(c.Max) {
		return false
	}
	atomic.AddInt64(&c.globalCount, 1)
	return true
}

// Release 释放一个连接计数（连接关闭时调用）。
func (c *ConnLimit) Release(src net.IP) {
	if c == nil || !c.enabled {
		return
	}
	if c.PerSrc {
		key := ""
		if src != nil {
			key = src.String()
		}
		if v, ok := c.srcCounts.Load(key); ok {
			atomic.AddInt64(v.(*int64), -1)
		}
		return
	}
	atomic.AddInt64(&c.globalCount, -1)
}

// GeoIPSpec 地理位置匹配。
type GeoIPSpec struct {
	Countries map[string]bool // 允许/拒绝的国家码集合
	Mode      string          // "allow" 仅允许列表内 / "deny" 仅拒绝列表内
	enabled   bool
}

// ParseGeoIPSpec 解析地理位置规则。格式: "CN,US" 默认 deny 模式，"allow:CN,US" 为 allow 模式。
func ParseGeoIPSpec(spec string) *GeoIPSpec {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "any" {
		return &GeoIPSpec{enabled: false}
	}
	g := &GeoIPSpec{Countries: make(map[string]bool), Mode: "deny"}
	if strings.HasPrefix(spec, "allow:") {
		g.Mode = "allow"
		spec = spec[6:]
	} else if strings.HasPrefix(spec, "deny:") {
		g.Mode = "deny"
		spec = spec[5:]
	}
	for _, c := range strings.Split(spec, ",") {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c != "" {
			g.Countries[c] = true
		}
	}
	if len(g.Countries) == 0 {
		g.enabled = false
	} else {
		g.enabled = true
	}
	return g
}

// Matches 检查 IP 是否匹配 GeoIP 规则。
// country 为 IP 对应的国家码（由 geoip 包查询），空字符串表示未知。
func (g *GeoIPSpec) Matches(country string) bool {
	if g == nil || !g.enabled {
		return true
	}
	inList := g.Countries[strings.ToUpper(country)]
	if g.Mode == "allow" {
		return inList
	}
	// deny 模式
	return !inList
}

func (g *GeoIPSpec) String() string {
	if g == nil || !g.enabled {
		return ""
	}
	var codes []string
	for c := range g.Countries {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	return g.Mode + ":" + strings.Join(codes, ",")
}

// Rule 一条防火墙规则。
type Rule struct {
	Action       string
	SrcIP        *IPMatcher
	DstIP        *IPMatcher
	SrcMAC       *MACMatcher
	DstMAC       *MACMatcher
	Protocol     *uint8
	SrcPort      *PortSpec
	DstPort      *PortSpec
	TCPFlags     uint8
	TCPFlagsMask uint8
	Direction    string
	State        string
	VLAN         *uint16 // nil = any
	Time         *TimeSpec
	RateLimit    *RateLimit
	Bandwidth    *BandwidthLimit // 带宽限速（字节/秒）
	ConnLimit    *ConnLimit      // 并发连接数限制
	GeoIP        *GeoIPSpec      // 地理位置匹配
	AppProto     string          // 应用层协议（DPI），如 http/dns/tls
	IPGroup      string          // 引用地址簿名称
	NAT          *NATSpec
	Comment      string
	Name         string

	// 命中计数（原子）
	hitCount uint64
	hitBytes uint64
}

// NATSpec NAT 规则。
type NATSpec struct {
	Type      string // snat / dnat / masquerade
	ToSrcIP   string
	ToSrcPort uint16
	ToDstIP   string
	ToDstPort uint16
}

func NewRule(action string) *Rule {
	return &Rule{
		Action:    action,
		SrcIP:     &IPMatcher{any: true},
		DstIP:     &IPMatcher{any: true},
		SrcMAC:    &MACMatcher{any: true},
		DstMAC:    &MACMatcher{any: true},
		Direction: DirAny,
	}
}

func protoNum(name string) (uint8, bool) {
	switch strings.ToLower(name) {
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

// MatchContext 规则匹配的上下文。
type MatchContext struct {
	SrcIP, DstIP     net.IP
	SrcMAC, DstMAC   net.HardwareAddr
	Proto            uint8
	SrcPort, DstPort uint16
	TCPFlags         uint8
	VLAN             uint16
	ConnState        string
	Direction        string // DirIn / DirOut / DirAny
	Now              time.Time
	PacketLen        int    // 用于命中字节统计
	SrcCountry       string // 源 IP 国家码（GeoIP）
	AppProto         string // 应用层协议（DPI 识别）
}

// Match 检查包是否匹配规则（不含速率限制）。
func (r *Rule) Match(c MatchContext) bool {
	if !r.SrcIP.Matches(c.SrcIP) {
		return false
	}
	if !r.DstIP.Matches(c.DstIP) {
		return false
	}
	if !r.SrcMAC.Matches(c.SrcMAC) {
		return false
	}
	if !r.DstMAC.Matches(c.DstMAC) {
		return false
	}
	if r.Protocol != nil && *r.Protocol != c.Proto {
		return false
	}
	if r.SrcPort != nil && !r.SrcPort.Matches(c.SrcPort) {
		return false
	}
	if r.DstPort != nil && !r.DstPort.Matches(c.DstPort) {
		return false
	}
	if r.TCPFlags != 0 {
		mask := r.TCPFlagsMask
		if mask == 0 {
			mask = r.TCPFlags
		}
		if c.TCPFlags&mask != r.TCPFlags {
			return false
		}
	}
	if r.VLAN != nil && *r.VLAN != c.VLAN {
		return false
	}
	if r.Direction != DirAny && c.Direction != DirAny && r.Direction != c.Direction {
		return false
	}
	if r.State != "" && r.State != c.ConnState {
		return false
	}
	if !r.Time.Matches(c.Now) {
		return false
	}
	if r.GeoIP != nil && !r.GeoIP.Matches(c.SrcCountry) {
		return false
	}
	if r.AppProto != "" && r.AppProto != c.AppProto {
		return false
	}
	return true
}

// HitCount 返回命中次数。
func (r *Rule) HitCount() uint64 { return atomic.LoadUint64(&r.hitCount) }

// HitBytes 返回命中字节数。
func (r *Rule) HitBytes() uint64 { return atomic.LoadUint64(&r.hitBytes) }

// AddHit 增加命中计数。
func (r *Rule) AddHit(bytes int) {
	atomic.AddUint64(&r.hitCount, 1)
	atomic.AddUint64(&r.hitBytes, uint64(bytes))
}

func (r *Rule) String() string {
	proto := "any"
	if r.Protocol != nil {
		proto = protoName(*r.Protocol)
	}
	parts := []string{
		r.Action, proto,
		r.SrcIP.String() + ":" + r.SrcPort.String(),
		"->",
		r.DstIP.String() + ":" + r.DstPort.String(),
	}
	if r.TCPFlags != 0 {
		parts = append(parts, "flags="+TCPFlagsToString(r.TCPFlags))
	}
	if r.VLAN != nil {
		parts = append(parts, "vlan="+strconv.Itoa(int(*r.VLAN)))
	}
	if r.State != "" {
		parts = append(parts, "state="+r.State)
	}
	if r.Direction != DirAny {
		parts = append(parts, "dir="+r.Direction)
	}
	if r.RateLimit != nil && r.RateLimit.enabled {
		parts = append(parts, "rate="+strconv.Itoa(r.RateLimit.Rate)+"/s")
	}
	if r.Bandwidth != nil && r.Bandwidth.enabled {
		mbps := float64(r.Bandwidth.BytesPerSec) * 8 / 1024 / 1024
		parts = append(parts, fmt.Sprintf("bw=%.1fMbps", mbps))
	}
	if r.ConnLimit != nil && r.ConnLimit.enabled {
		parts = append(parts, "connlimit="+strconv.Itoa(r.ConnLimit.Max))
	}
	if r.GeoIP != nil {
		if s := r.GeoIP.String(); s != "" {
			parts = append(parts, "geoip="+s)
		}
	}
	if r.AppProto != "" {
		parts = append(parts, "app="+r.AppProto)
	}
	if r.NAT != nil {
		parts = append(parts, "nat="+r.NAT.Type)
	}
	if r.Comment != "" {
		parts = append(parts, "# "+r.Comment)
	}
	return strings.Join(parts, " ")
}

// TCPFlagsToString 将 TCP flag 位转为逗号分隔的名称（按位值排序）。
func TCPFlagsToString(f uint8) string {
	// 按 flag 位值从小到大排列，保证输出稳定
	type pair struct {
		name string
		bit  uint8
	}
	var pairs []pair
	for name, bit := range tcpFlagMap {
		if f&bit != 0 {
			pairs = append(pairs, pair{name, bit})
		}
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].bit < pairs[j].bit })
	var names []string
	for _, p := range pairs {
		names = append(names, p.name)
	}
	return strings.Join(names, ",")
}

// RuleSet 规则集，首条匹配胜出。
type RuleSet struct {
	Rules         []*Rule
	DefaultAction string
	IPGroups      map[string]*IPMatcher // 地址簿
}

func NewRuleSet() *RuleSet {
	return &RuleSet{DefaultAction: ActionDrop, IPGroups: make(map[string]*IPMatcher)}
}

// ExportIPGroups 导出地址簿为 name -> CIDR 字符串映射，用于 YAML 回写。
func (rs *RuleSet) ExportIPGroups() map[string]string {
	if rs == nil || len(rs.IPGroups) == 0 {
		return nil
	}
	out := make(map[string]string, len(rs.IPGroups))
	for name, m := range rs.IPGroups {
		if s := m.String(); s != "" && s != "any" {
			out[name] = s
		}
	}
	return out
}

func (rs *RuleSet) Add(r *Rule) {
	rs.Rules = append(rs.Rules, r)
}

// Match 返回首个匹配规则和动作。检查速率限制。
func (rs *RuleSet) Match(c MatchContext) (*Rule, string) {
	for _, r := range rs.Rules {
		if !r.Match(c) {
			continue
		}
		// 地址簿解析
		if r.IPGroup != "" {
			if grp, ok := rs.IPGroups[r.IPGroup]; ok && !grp.Matches(c.SrcIP) {
				continue
			}
		}
		// 速率限制（包/秒）
		if r.RateLimit != nil && !r.RateLimit.Allow(c.SrcIP) {
			return r, ActionDrop
		}
		// 带宽限制（字节/秒）
		if r.Bandwidth != nil && !r.Bandwidth.Allow(c.SrcIP, c.PacketLen) {
			return r, ActionDrop
		}
		// 并发连接数限制（仅对新连接检查）
		if r.ConnLimit != nil && c.ConnState == StateNew && !r.ConnLimit.Allow(c.SrcIP) {
			return r, ActionDrop
		}
		if c.PacketLen > 0 {
			r.AddHit(c.PacketLen)
		} else {
			r.AddHit(0)
		}
		return r, r.Action
	}
	return nil, rs.DefaultAction
}

func (rs *RuleSet) Len() int { return len(rs.Rules) }
