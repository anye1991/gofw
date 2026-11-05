// Package engine 实现防火墙决策引擎与连接跟踪。
package engine

import (
	"encoding/binary"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"gofw/dpi"
	"gofw/geoctl"
	"gofw/geoip"
	"gofw/packet"
	"gofw/rules"
)

const (
	CTNew         = "new"
	CTEstablished = "established"
	CTRelated     = "related"
	CTInvalid     = "invalid"

	tcpTimeout      = 3600
	tcpCloseTimeout = 10
	udpTimeout      = 120
	icmpTimeout     = 30
	fragTimeout     = 30
)

// TCP 状态机内部值（原子操作）。
const (
	stClosed      int32 = 0
	stSynSent     int32 = 1
	stSynRecv     int32 = 2
	stEstablished int32 = 3
	stFinWait     int32 = 4
	stCloseWait   int32 = 5
)

var stateName = map[int32]string{
	stClosed: "CLOSED", stSynSent: "SYN_SENT", stSynRecv: "SYN_RECV",
	stEstablished: "ESTABLISHED", stFinWait: "FIN_WAIT", stCloseWait: "CLOSE_WAIT",
}

// ConnEntry 连接跟踪条目。
type ConnEntry struct {
	state    int32 // 原子，见 stateName[]
	Proto    uint8
	SrcIP    net.IP
	SrcPort  uint16
	DstIP    net.IP
	DstPort  uint16
	LastSeen int64
	Packets  uint64
	Bytes    uint64
	OrigKey  string
}

func (c *ConnEntry) StateName() string { return stateName[atomic.LoadInt32(&c.state)] }
func (c *ConnEntry) setState(s int32)  { atomic.StoreInt32(&c.state, s) }

func (c *ConnEntry) isOrig(src net.IP, sp uint16, dst net.IP, dp uint16) bool {
	return c.SrcIP.Equal(src) && c.SrcPort == sp && c.DstIP.Equal(dst) && c.DstPort == dp
}

func (c *ConnEntry) isReply(src net.IP, sp uint16, dst net.IP, dp uint16) bool {
	return c.SrcIP.Equal(dst) && c.SrcPort == dp && c.DstIP.Equal(src) && c.DstPort == sp
}

// ConnectionTracker 并发安全的连接跟踪表。
type ConnectionTracker struct {
	table     sync.Map
	lastSweep int64 // 原子，秒
}

func connKey(proto uint8, src net.IP, sp uint16, dst net.IP, dp uint16) string {
	return string([]byte{proto}) + src.String() + ":" + itoa(int(sp)) + "->" + dst.String() + ":" + itoa(int(dp))
}

func revKey(proto uint8, src net.IP, sp uint16, dst net.IP, dp uint16) string {
	return connKey(proto, dst, dp, src, sp)
}

func (ct *ConnectionTracker) Lookup(p *packet.Packet) (*ConnEntry, string) {
	if p.SrcIP == nil {
		return nil, CTInvalid
	}
	sp, dp := p.SrcPort, p.DstPort
	if p.Proto != packet.ProtoICMP && p.Proto != packet.ProtoICMPv6 {
		if !p.HasL4 {
			return nil, CTInvalid
		}
	}
	fwd := connKey(p.Proto, p.SrcIP, sp, p.DstIP, dp)
	rev := revKey(p.Proto, p.SrcIP, sp, p.DstIP, dp)

	var entry *ConnEntry
	if v, ok := ct.table.Load(fwd); ok {
		entry = v.(*ConnEntry)
	} else if v, ok := ct.table.Load(rev); ok {
		entry = v.(*ConnEntry)
	}

	ct.maybeSweep()

	if entry == nil {
		return nil, ct.classifyNew(p)
	}

	ct.updateTCPState(entry, p, fwd)
	atomic.StoreInt64(&entry.LastSeen, time.Now().Unix())
	atomic.AddUint64(&entry.Packets, 1)
	atomic.AddUint64(&entry.Bytes, uint64(len(p.Raw)))

	switch atomic.LoadInt32(&entry.state) {
	case stEstablished, stFinWait, stCloseWait:
		return entry, CTEstablished
	case stSynSent, stSynRecv:
		if entry.isReply(p.SrcIP, sp, p.DstIP, dp) {
			return entry, CTEstablished
		}
		return entry, CTNew
	default:
		return entry, CTEstablished
	}
}

func (ct *ConnectionTracker) classifyNew(p *packet.Packet) string {
	if p.Proto == packet.ProtoTCP {
		if p.TCPFlags&packet.TCPSyn != 0 && p.TCPFlags&packet.TCPAck == 0 {
			return CTNew
		}
		if p.TCPFlags&packet.TCPRst != 0 {
			return CTNew
		}
		return CTInvalid
	}
	return CTNew
}

func (ct *ConnectionTracker) Ensure(p *packet.Packet) *ConnEntry {
	sp, dp := p.SrcPort, p.DstPort
	fwd := connKey(p.Proto, p.SrcIP, sp, p.DstIP, dp)
	if v, ok := ct.table.Load(fwd); ok {
		e := v.(*ConnEntry)
		atomic.AddUint64(&e.Packets, 1)
		atomic.AddUint64(&e.Bytes, uint64(len(p.Raw)))
		atomic.StoreInt64(&e.LastSeen, time.Now().Unix())
		return e
	}
	state := stEstablished
	if p.Proto == packet.ProtoTCP {
		state = stSynSent
	}
	e := &ConnEntry{
		state: state, Proto: p.Proto,
		SrcIP: p.SrcIP, SrcPort: sp, DstIP: p.DstIP, DstPort: dp,
		LastSeen: time.Now().Unix(), Packets: 1, Bytes: uint64(len(p.Raw)),
		OrigKey: fwd,
	}
	ct.table.Store(fwd, e)
	return e
}

func (ct *ConnectionTracker) updateTCPState(e *ConnEntry, p *packet.Packet, fwdKey string) {
	if e.Proto != packet.ProtoTCP {
		return
	}
	flags := p.TCPFlags
	isOrig := e.OrigKey == fwdKey

	switch atomic.LoadInt32(&e.state) {
	case stClosed:
		if flags&packet.TCPSyn != 0 && flags&packet.TCPAck == 0 {
			e.setState(stSynSent)
		}
	case stSynSent:
		if isOrig {
			if flags&packet.TCPRst != 0 {
				e.setState(stClosed)
			}
		} else {
			if flags&packet.TCPSyn != 0 && flags&packet.TCPAck != 0 {
				e.setState(stSynRecv)
			} else if flags&packet.TCPRst != 0 {
				e.setState(stClosed)
			}
		}
	case stSynRecv:
		if isOrig && flags&packet.TCPAck != 0 && flags&packet.TCPSyn == 0 {
			e.setState(stEstablished)
		}
	case stEstablished:
		if flags&packet.TCPFin != 0 {
			if isOrig {
				e.setState(stFinWait)
			} else {
				e.setState(stCloseWait)
			}
		} else if flags&packet.TCPRst != 0 {
			e.setState(stClosed)
		}
	case stFinWait, stCloseWait:
		if flags&packet.TCPAck != 0 {
			e.setState(stClosed)
		}
	}
}

// maybeSweep 节流 sweep 到每秒一次（CAS 保证只有一个 goroutine 执行）。
func (ct *ConnectionTracker) maybeSweep() {
	now := time.Now().Unix()
	old := atomic.LoadInt64(&ct.lastSweep)
	if old < now && atomic.CompareAndSwapInt64(&ct.lastSweep, old, now) {
		ct.sweep()
	}
}

func (ct *ConnectionTracker) sweep() {
	now := time.Now().Unix()
	ct.table.Range(func(key, value interface{}) bool {
		e := value.(*ConnEntry)
		timeout := int64(tcpTimeout)
		if e.Proto != packet.ProtoTCP {
			if e.Proto == packet.ProtoICMP || e.Proto == packet.ProtoICMPv6 {
				timeout = icmpTimeout
			} else {
				timeout = udpTimeout
			}
		}
		if atomic.LoadInt32(&e.state) == stClosed {
			timeout = tcpCloseTimeout
		}
		if now-atomic.LoadInt64(&e.LastSeen) > timeout {
			ct.table.Delete(key)
		}
		return true
	})
}

func (ct *ConnectionTracker) Stats() map[string]int {
	var total, established, tcpC, udpC int
	ct.table.Range(func(_, value interface{}) bool {
		e := value.(*ConnEntry)
		total++
		if atomic.LoadInt32(&e.state) == stEstablished {
			established++
		}
		if e.Proto == packet.ProtoTCP {
			tcpC++
		} else if e.Proto == packet.ProtoUDP {
			udpC++
		}
		return true
	})
	return map[string]int{"total": total, "established": established, "tcp": tcpC, "udp": udpC}
}

// ConnInfo 用于导出的连接信息。
type ConnInfo struct {
	Proto   uint8
	Src     string
	Dst     string
	State   string
	Packets uint64
	Bytes   uint64
	Age     int64
}

func (ct *ConnectionTracker) Dump() []ConnInfo {
	var list []ConnInfo
	now := time.Now().Unix()
	ct.table.Range(func(_, value interface{}) bool {
		e := value.(*ConnEntry)
		list = append(list, ConnInfo{
			Proto:   e.Proto,
			Src:     e.SrcIP.String() + ":" + itoa(int(e.SrcPort)),
			Dst:     e.DstIP.String() + ":" + itoa(int(e.DstPort)),
			State:   e.StateName(),
			Packets: atomic.LoadUint64(&e.Packets),
			Bytes:   atomic.LoadUint64(&e.Bytes),
			Age:     now - atomic.LoadInt64(&e.LastSeen),
		})
		return true
	})
	sort.Slice(list, func(i, j int) bool { return list[i].Bytes > list[j].Bytes })
	return list
}

// ---------------------------------------------------------------------------
// 分片重组
// ---------------------------------------------------------------------------
type fragEntry struct {
	mu       sync.Mutex
	packets  []fragPacket
	lastSeen int64 // 原子
}

type fragPacket struct {
	offset uint16
	data   []byte
	more   bool
}

// FragReassembler IP 分片重组器。
type FragReassembler struct {
	table     sync.Map // key -> *fragEntry
	lastSweep int64    // 原子，秒
}

func fragKey(p *packet.Packet) string {
	return p.SrcIP.String() + "|" + p.DstIP.String() + "|" + itoa(int(p.ID)) + "|" + itoa(int(p.Proto))
}

// Process 处理一个分片包。如果重组完成，返回重组后的 L4 payload 和 true。
func (fr *FragReassembler) Process(p *packet.Packet) ([]byte, bool) {
	if !p.IsFragment {
		return nil, false
	}
	key := fragKey(p)
	now := time.Now().Unix()
	fr.maybeSweep()

	v, _ := fr.table.LoadOrStore(key, &fragEntry{})
	fe := v.(*fragEntry)

	// 用 L4Offset 提取 payload，兼容 VLAN 和扩展头
	var payload []byte
	if p.L4Offset > 0 && p.L4Offset <= len(p.Raw) {
		payload = p.Raw[p.L4Offset:]
	} else {
		return nil, false
	}

	fe.mu.Lock()
	atomic.StoreInt64(&fe.lastSeen, now)
	fe.packets = append(fe.packets, fragPacket{offset: p.FragOffset, data: payload, more: p.MoreFrag})
	done, out := fr.tryReassembleLocked(fe)
	fe.mu.Unlock()

	if done {
		fr.table.Delete(key)
		return out, true
	}
	return nil, false
}

// tryReassembleLocked 在持有 fe.mu 的情况下尝试重组。
// 每次新分片到达都尝试；只有 offset=0 的首片存在、且最后一片 (more=false) 已到、
// 且所有片连续时才成功。失败时不删除条目，等待更多分片。
func (fr *FragReassembler) tryReassembleLocked(fe *fragEntry) (bool, []byte) {
	if len(fe.packets) == 0 {
		return false, nil
	}
	sort.Slice(fe.packets, func(i, j int) bool { return fe.packets[i].offset < fe.packets[j].offset })

	// 必须有首片 (offset 0) 和尾片 (more=false)
	if fe.packets[0].offset != 0 {
		return false, nil
	}
	if fe.packets[len(fe.packets)-1].more {
		return false, nil
	}

	// 检查连续性并计算总长
	var total int
	for i, fp := range fe.packets {
		if i > 0 && fp.offset != fe.packets[i-1].offset+uint16(len(fe.packets[i-1].data)) {
			return false, nil
		}
		total += len(fp.data)
	}
	if total == 0 {
		return false, nil
	}
	result := make([]byte, total)
	off := 0
	for _, fp := range fe.packets {
		copy(result[off:], fp.data)
		off += len(fp.data)
	}
	return true, result
}

// maybeSweep 节流到每秒一次。
func (fr *FragReassembler) maybeSweep() {
	now := time.Now().Unix()
	old := atomic.LoadInt64(&fr.lastSweep)
	if old < now && atomic.CompareAndSwapInt64(&fr.lastSweep, old, now) {
		fr.sweep()
	}
}

func (fr *FragReassembler) sweep() {
	now := time.Now().Unix()
	fr.table.Range(func(key, value interface{}) bool {
		fe := value.(*fragEntry)
		if now-atomic.LoadInt64(&fe.lastSeen) > fragTimeout {
			fr.table.Delete(key)
		}
		return true
	})
}

// ---------------------------------------------------------------------------
// 决策引擎
// ---------------------------------------------------------------------------
type Decision struct {
	Action    string
	Rule      *rules.Rule
	ConnState string
	Packet    *packet.Packet
}

func (d *Decision) Allowed() bool {
	return d.Action == rules.ActionAccept || d.Action == rules.ActionLog
}

// Event 是单条决策记录，供 Web UI 实时拦截流展示。
type Event struct {
	TS          int64  `json:"ts"`
	Action      string `json:"action"`
	SrcIP       string `json:"src_ip"`
	SrcPort     uint16 `json:"src_port"`
	DstIP       string `json:"dst_ip"`
	DstPort     uint16 `json:"dst_port"`
	Proto       uint8  `json:"proto"`
	Country     string `json:"country"`
	RuleComment string `json:"rule"`
	RuleIndex   int    `json:"rule_index"`
}

// eventRing 是一个有界环形缓冲，保存最近若干条决策。
type eventRing struct {
	mu  sync.Mutex
	buf []Event
	cap int
}

func (r *eventRing) push(e Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, e)
	if len(r.buf) > r.cap {
		r.buf = r.buf[len(r.buf)-r.cap:]
	}
}

func (r *eventRing) snapshot() []Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, len(r.buf))
	copy(out, r.buf)
	return out
}

type Engine struct {
	Ruleset   *rules.RuleSet
	Conntrack *ConnectionTracker
	Frag      *FragReassembler
	GeoIP     *geoip.DB
	DPI       *dpi.Detector
	GeoCtl    *geoctl.Tracker // 地理围栏统计 / 临时封禁（可为 nil）
	packets   uint64
	accepted  uint64
	dropped   uint64
	bytes     uint64

	eventCh chan Event
	events  *eventRing
}

func NewEngine(rs *rules.RuleSet) *Engine {
	e := &Engine{
		Ruleset:   rs,
		Conntrack: &ConnectionTracker{},
		Frag:      &FragReassembler{},
		GeoIP:     geoip.New(),
		DPI:       dpi.NewDetector(),
		eventCh:   make(chan Event, 1024),
		events:    &eventRing{cap: 500},
	}
	go e.collectEvents()
	return e
}

// collectEvents 将异步决策事件写入有界环形缓冲，避免阻塞 Decide 热路径。
func (e *Engine) collectEvents() {
	for ev := range e.eventCh {
		e.events.push(ev)
	}
}

// Recent 返回最近若干条决策记录（按时间升序）。
func (e *Engine) Recent() []Event {
	evs := e.events.snapshot()
	out := make([]Event, len(evs))
	for i, v := range evs {
		out[i] = v
	}
	return out
}

// publish 非阻塞地记录一条决策事件。
func (e *Engine) publish(action string, rule *rules.Rule, p *packet.Packet, country string) {
	idx := -1
	if rule != nil {
		for i, r := range e.Ruleset.Rules {
			if r == rule {
				idx = i
				break
			}
		}
	}
	ev := Event{
		TS:          time.Now().Unix(),
		Action:      action,
		SrcIP:       p.SrcIP.String(),
		SrcPort:     p.SrcPort,
		DstIP:       p.DstIP.String(),
		DstPort:     p.DstPort,
		Proto:       p.Proto,
		Country:     country,
		RuleIndex:   idx,
	}
	if rule != nil {
		ev.RuleComment = rule.Comment
	}
	select {
	case e.eventCh <- ev:
	default:
	}
}

// SetGeoIP 设置 GeoIP 数据库。
func (e *Engine) SetGeoIP(db *geoip.DB) {
	if db != nil {
		e.GeoIP = db
	}
}

// SetGeoCtl 注入地理围栏统计 / 临时封禁跟踪器。
func (e *Engine) SetGeoCtl(t *geoctl.Tracker) {
	e.GeoCtl = t
}

// SetRuleset 热替换规则集，保留连接跟踪表和分片重组器（持久连接跟踪）。
func (e *Engine) SetRuleset(rs *rules.RuleSet) {
	e.Ruleset = rs
}

// Decide 对一个包做出决策。
func (e *Engine) Decide(p *packet.Packet) Decision {
	atomic.AddUint64(&e.packets, 1)
	atomic.AddUint64(&e.bytes, uint64(len(p.Raw)))

	// 临时封禁：命中即在规则匹配前直接丢弃（优先级最高）。
	// 该检查独立于执行后端，monitor / nftables 两种模式都生效于决策层。
	if e.GeoCtl != nil && e.GeoCtl.IsBanned(p.SrcIP) {
		country := ""
		if e.GeoIP != nil && e.GeoIP.Loaded() {
			country = e.GeoIP.Lookup(p.SrcIP)
		}
		e.GeoCtl.ObserveBanned(country)
		atomic.AddUint64(&e.dropped, 1)
		e.publish(rules.ActionDrop, nil, p, country)
		return Decision{Action: rules.ActionDrop, ConnState: CTNew, Packet: p}
	}

	// 分片重组
	if p.IsFragment {
		if l4, ok := e.Frag.Process(p); ok {
			// 重组完成，重新解析 L4
			p.IsFragment = false
			e.parseReassembledL4(p, l4)
		} else {
			// 还没收齐，暂放（默认放行首片以外的，等重组后再判）
			return Decision{Action: rules.ActionAccept, ConnState: CTNew, Packet: p}
		}
	}

	_, connState := e.Conntrack.Lookup(p)

	// GeoIP 查询
	srcCountry := ""
	if e.GeoIP != nil && e.GeoIP.Loaded() {
		srcCountry = e.GeoIP.Lookup(p.SrcIP)
	}

	// DPI 应用层协议识别
	appProto := ""
	if e.DPI != nil {
		appProto = e.DPI.Detect(p)
	}

	ctx := rules.MatchContext{
		SrcIP: p.SrcIP, DstIP: p.DstIP,
		SrcMAC: p.SrcMAC, DstMAC: p.DstMAC,
		Proto: p.Proto, SrcPort: p.SrcPort, DstPort: p.DstPort,
		TCPFlags: p.TCPFlags, VLAN: p.VLAN, ConnState: connState,
		Now: time.Now(), PacketLen: len(p.Raw),
		SrcCountry: srcCountry, AppProto: appProto,
		// 抓包为混杂模式，用户态无法可靠区分入/出站；显式设为 any，
		// 使带 direction 的规则仍参与用户态决策（精确的方向过滤由内核
		// nftables 按 input/output/forward 链完成）。否则 c.Direction 为空串，
		// 会被 Rule.Match 误判为方向不符而跳过全部 direction:in/out 规则。
		Direction: rules.DirAny,
	}
	rule, action := e.Ruleset.Match(ctx)

	if connState == CTNew && (action == rules.ActionAccept || action == rules.ActionLog) {
		e.Conntrack.Ensure(p)
	}

	if action == rules.ActionAccept || action == rules.ActionLog {
		atomic.AddUint64(&e.accepted, 1)
	} else {
		atomic.AddUint64(&e.dropped, 1)
	}

	if e.GeoCtl != nil {
		drop := action != rules.ActionAccept && action != rules.ActionLog
		e.GeoCtl.Observe(p.SrcIP, srcCountry, action, drop)
	}

	e.publish(action, rule, p, srcCountry)

	return Decision{Action: action, Rule: rule, ConnState: connState, Packet: p}
}

func (e *Engine) parseReassembledL4(p *packet.Packet, l4 []byte) {
	switch p.Proto {
	case packet.ProtoTCP:
		if len(l4) >= 20 {
			p.SrcPort = binary.BigEndian.Uint16(l4[0:2])
			p.DstPort = binary.BigEndian.Uint16(l4[2:4])
			p.TCPFlags = l4[13] & 0x3f
			p.HasL4 = true
		}
	case packet.ProtoUDP:
		if len(l4) >= 8 {
			p.SrcPort = binary.BigEndian.Uint16(l4[0:2])
			p.DstPort = binary.BigEndian.Uint16(l4[2:4])
			p.HasL4 = true
		}
	case packet.ProtoICMP, packet.ProtoICMPv6:
		p.HasL4 = true
	}
}

func (e *Engine) Stats() map[string]interface{} {
	return map[string]interface{}{
		"packets":     atomic.LoadUint64(&e.packets),
		"accepted":    atomic.LoadUint64(&e.accepted),
		"dropped":     atomic.LoadUint64(&e.dropped),
		"bytes":       atomic.LoadUint64(&e.bytes),
		"connections": e.Conntrack.Stats(),
		"rules":       e.Ruleset.Len(),
	}
}

// RuleStats 返回每条规则的命中统计。
func (e *Engine) RuleStats() []map[string]interface{} {
	var out []map[string]interface{}
	for i, r := range e.Ruleset.Rules {
		out = append(out, map[string]interface{}{
			"index":   i,
			"action":  r.Action,
			"hits":    r.HitCount(),
			"bytes":   r.HitBytes(),
			"comment": r.Comment,
		})
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
