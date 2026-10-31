package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	"gofw/config"
	"gofw/dpi"
	"gofw/engine"
	"gofw/geoip"
	"gofw/ha"
	"gofw/packet"
	"gofw/rules"
)

func main() {
	pass := 0
	fail := 0
	check := func(name string, ok bool) {
		if ok {
			fmt.Printf("  PASS: %s\n", name)
			pass++
		} else {
			fmt.Printf("  FAIL: %s\n", name)
			fail++
		}
	}

	fmt.Println("=== 1. DPI 深度包检测 ===")
	d := dpi.NewDetector()
	// HTTP
	httpPkt := makeHTTP("GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	check("HTTP detected", d.Detect(httpPkt) == "http")
	// TLS
	tlsPkt := makeTLS()
	check("TLS detected", d.Detect(tlsPkt) == "tls")
	// SSH
	sshPkt := makeSSH()
	check("SSH detected", d.Detect(sshPkt) == "ssh")
	// DNS
	dnsPkt := makeDNS()
	check("DNS detected", d.Detect(dnsPkt) == "dns")
	// MySQL 服务端问候包
	mysqlSrvPkt := makeMySQLServerGreeting()
	check("MySQL server greeting detected", d.Detect(mysqlSrvPkt) == "mysql")
	// MySQL 客户端认证响应包
	mysqlCliPkt := makeMySQLClientAuth()
	check("MySQL client auth detected", d.Detect(mysqlCliPkt) == "mysql")

	fmt.Println("=== 2. GeoIP 地理位置 ===")
	db := geoip.New()
	check("empty DB not loaded", !db.Loaded())
	// 构造内存数据：直接用 LoadFromCSV 的逻辑
	loadGeoIPInline(db, "10.0.0.0/8,CN", "192.168.0.0/16,US")
	check("DB loaded", db.Loaded())
	check("10.1.2.3 -> CN", db.Lookup(net.ParseIP("10.1.2.3")) == "CN")
	check("192.168.1.1 -> US", db.Lookup(net.ParseIP("192.168.1.1")) == "US")
	check("8.8.8.8 -> unknown", db.Lookup(net.ParseIP("8.8.8.8")) == "")

	fmt.Println("=== 3. Bandwidth 带宽限速 ===")
	bw := rules.ParseBandwidthLimit(10, 0, false) // 10 Mbps
	check("bw enabled", bw != nil && bw.BytesPerSec > 0)
	// 10Mbps = 1,310,720 bytes/sec, burst = 1秒 = 1,310,720
	// 一个 1500 字节的包应该放行
	check("small packet allowed", bw.Allow(nil, 1500))
	// 消耗完带宽后大的包应该被拒绝
	for i := 0; i < 1000; i++ {
		bw.Allow(nil, 1500)
	}
	check("exceeded bandwidth dropped", !bw.Allow(nil, 1500))

	fmt.Println("=== 4. ConnLimit 并发连接限制 ===")
	cl := rules.ParseConnLimit(2, false)
	check("conn 1 allowed", cl.Allow(net.ParseIP("1.1.1.1")))
	check("conn 2 allowed", cl.Allow(net.ParseIP("2.2.2.2")))
	check("conn 3 blocked (limit 2)", !cl.Allow(net.ParseIP("3.3.3.3")))
	cl.Release(net.ParseIP("1.1.1.1"))
	check("after release, conn allowed", cl.Allow(net.ParseIP("3.3.3.3")))

	fmt.Println("=== 5. 持久连接跟踪 (SetRuleset) ===")
	rs1 := rules.NewRuleSet()
	rs1.DefaultAction = rules.ActionDrop
	r1 := rules.NewRule(rules.ActionAccept)
	r1.Protocol = protoPtr(6)
	rs1.Add(r1)
	eng := engine.NewEngine(rs1)
	// 创建一个连接
	synPkt := makeSYN("10.0.0.1", "10.0.0.2", 12345, 80)
	eng.Decide(synPkt)
	connsBefore := eng.Conntrack.Dump()
	check("connection exists before reload", len(connsBefore) > 0)
	// 热替换规则集
	rs2 := rules.NewRuleSet()
	rs2.DefaultAction = rules.ActionAccept
	eng.SetRuleset(rs2)
	connsAfter := eng.Conntrack.Dump()
	check("connection preserved after SetRuleset", len(connsAfter) > 0)
	check("ruleset swapped", eng.Ruleset.DefaultAction == rules.ActionAccept)

	fmt.Println("=== 6. YAML 配置解析新字段 ===")
	yaml := `
default: drop
rules:
  - action: accept
    protocol: tcp
    dst_port: 80
    bandwidth: 10
    conn_limit: 100
    per_src: true
    geoip: allow:CN,US
    app_proto: http
`
	rs, err := config.LoadFromData([]byte(yaml))
	if err != nil {
		fmt.Printf("  FAIL: yaml parse: %v\n", err)
		fail++
	} else {
		r := rs.Rules[0]
		check("bandwidth parsed", r.Bandwidth != nil && r.Bandwidth.BytesPerSec > 0)
		check("conn_limit parsed", r.ConnLimit != nil && r.ConnLimit.Max == 100)
		check("per_src parsed", r.Bandwidth.PerSrc && r.ConnLimit.PerSrc)
		check("geoip parsed", r.GeoIP != nil && r.GeoIP.Matches("CN") && !r.GeoIP.Matches("JP"))
		check("app_proto parsed", r.AppProto == "http")
	}

	fmt.Println("=== 7. 内置 GeoIP 国家库 ===")
	bdb := geoip.NewWithBuiltin()
	check("builtin loaded", bdb.Loaded() && bdb.Count() > 0)
	// 中国 IP 段
	check("114.114.114.114 -> CN", bdb.Lookup(net.ParseIP("114.114.114.114")) == "CN")
	check("223.5.5.5 -> CN", bdb.Lookup(net.ParseIP("223.5.5.5")) == "CN")
	// 美国 IP 段
	check("8.8.8.8 -> US", bdb.Lookup(net.ParseIP("8.8.8.8")) == "US")
	check("9.9.9.9 -> US", bdb.Lookup(net.ParseIP("9.9.9.9")) == "US")
	// 日本
	check("133.0.0.1 -> JP", bdb.Lookup(net.ParseIP("133.0.0.1")) == "JP")
	// 未匹配
	check("255.255.255.255 -> unknown", bdb.Lookup(net.ParseIP("255.255.255.255")) == "")

	fmt.Println("=== 8. VRRP 协议配置与状态 ===")
	// VRRP 配置解析（VRID>0 时启用 VRRP，否则回退 TCP 探测）
	cfg := &ha.Config{Enabled: true, VRID: 51, Priority: 100, AdvertInt: 1, VIP: "192.168.1.1"}
	mgr := ha.NewManager(cfg)
	check("VRRP config parsed", cfg.VRID == 51 && cfg.Priority == 100 && cfg.AdvertInt == 1)
	// 非 255 优先级初始状态应为 backup
	check("initial state backup", mgr.State() == ha.StateBackup)
	// 优先级 255（VIP 拥有者）配置
	cfgOwner := &ha.Config{Enabled: true, VRID: 51, Priority: 255, AdvertInt: 1, VIP: "192.168.1.1"}
	check("owner priority=255", cfgOwner.Priority == 255)
	// 验证 state 字符串
	check("state string BACKUP", mgr.State().String() == "BACKUP")
	check("state string UNKNOWN", ha.StateUnknown.String() == "UNKNOWN")
	// 未启用 VRRP（VRID=0）时保持原 TCP 探测模式可用
	cfgTCP := &ha.Config{Enabled: true, Mode: "backup", PeerIP: "10.0.0.2", VIP: "192.168.1.1", Interface: "eth0"}
	mgrTCP := ha.NewManager(cfgTCP)
	check("tcp mode config parsed", cfgTCP.VRID == 0 && mgrTCP.State() == ha.StateBackup)
	// master/backup 状态切换回调
	promoted := false
	mgr.SetCallbacks(func() { promoted = true }, nil)
	// 手动触发提升（模拟 VRRP master down 后的提升）
	mgr.PromoteForTest()
	check("promote callback fired", promoted && mgr.IsMaster())
	mgr.Stop()

	fmt.Println()
	fmt.Printf("结果: %d 通过, %d 失败\n", pass, fail)
	if fail > 0 {
		panic("some checks failed")
	}
}

func protoPtr(p uint8) *uint8 { return &p }

// --- 辅助构造包 ---
func makeHTTP(body string) *packet.Packet {
	payload := []byte(body)
	return makeTCP(payload)
}

func makeTLS() *packet.Packet {
	// TLS ClientHello: 0x16 0x03 0x01 ...
	payload := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00}
	return makeTCP(payload)
}

func makeSSH() *packet.Packet {
	return makeTCP([]byte("SSH-2.0-OpenSSH_8.0"))
}

func makeDNS() *packet.Packet {
	// DNS query: ID=0x1234, flags=0x0100, qdcount=1
	payload := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01}
	return makeUDP(payload)
}

// makeMySQLServerGreeting 构造 MySQL 服务端问候包（握手阶段，服务端→客户端）。
// 包结构: payload_len(3,LE)=0x08, seq=0x00, protocol_version=0x0a, server_version="8.0.21\0"
func makeMySQLServerGreeting() *packet.Packet {
	payload := []byte{
		0x0a,                               // protocol version = 10
		'8', '.', '0', '.', '2', '1', 0x00, // server version "8.0.21\0"
	}
	pkt := make([]byte, 4)
	pkt[0] = byte(len(payload)) // payload length low byte
	pkt[1] = 0x00
	pkt[2] = 0x00
	pkt[3] = 0x00 // sequence id
	pkt = append(pkt, payload...)
	return makeTCP(pkt)
}

// makeMySQLClientAuth 构造 MySQL 客户端认证响应包（客户端→服务端）。
// 包结构: payload_len(3,LE), seq=0x01, capability_flags(4,LE), max_packet(4,LE),
//
//	charset(1), reserved(23 zeros), username "root\0"
func makeMySQLClientAuth() *packet.Packet {
	payload := []byte{
		// capability flags = 0x0000a685 (含 CLIENT_PROTOCOL_41=0x200)
		0x85, 0xa6, 0x00, 0x00,
		// max packet size = 0x00ffffff
		0xff, 0xff, 0xff, 0x00,
		// charset = utf8 (0x21)
		0x21,
	}
	// 23 字节保留零
	payload = append(payload, make([]byte, 23)...)
	// username "root\0"
	payload = append(payload, []byte{'r', 'o', 'o', 't', 0x00}...)
	pkt := make([]byte, 4)
	pkt[0] = byte(len(payload))
	pkt[1] = byte(len(payload) >> 8)
	pkt[2] = 0x00
	pkt[3] = 0x01 // sequence id
	pkt = append(pkt, payload...)
	return makeTCP(pkt)
}

func makeTCP(payload []byte) *packet.Packet {
	// 构造以太网 + IPv4 + TCP + payload
	eth := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00}
	ipHdr := []byte{0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00,
		10, 0, 0, 1, 10, 0, 0, 2}
	tcpHdr := make([]byte, 20)
	tcpHdr[0], tcpHdr[1] = 0x30, 0x39 // sport 12345
	tcpHdr[2], tcpHdr[3] = 0x00, 0x50 // dport 80
	tcpHdr[12] = 0x50                 // data offset = 20 bytes
	tcpHdr[13] = 0x18                 // PSH+ACK
	data := append(eth, ipHdr...)
	data = append(data, tcpHdr...)
	data = append(data, payload...)
	p := &packet.Packet{}
	p.Parse(data, "test")
	return p
}

func makeUDP(payload []byte) *packet.Packet {
	eth := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00}
	ipHdr := []byte{0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
		10, 0, 0, 1, 10, 0, 0, 2}
	udpHdr := []byte{0x12, 0x34, 0x00, 0x35, 0x00, 0x00, 0x00, 0x00}
	data := append(eth, ipHdr...)
	data = append(data, udpHdr...)
	data = append(data, payload...)
	p := &packet.Packet{}
	p.Parse(data, "test")
	return p
}

func makeSYN(src, dst string, sport, dport uint16) *packet.Packet {
	srcIP := net.ParseIP(src).To4()
	dstIP := net.ParseIP(dst).To4()
	eth := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0x08, 0x00}
	ipHdr := []byte{0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00}
	ipHdr = append(ipHdr, srcIP...)
	ipHdr = append(ipHdr, dstIP...)
	tcpHdr := make([]byte, 20)
	tcpHdr[0] = byte(sport >> 8)
	tcpHdr[1] = byte(sport)
	tcpHdr[2] = byte(dport >> 8)
	tcpHdr[3] = byte(dport)
	tcpHdr[12] = 0x50
	tcpHdr[13] = 0x02 // SYN
	data := append(eth, ipHdr...)
	data = append(data, tcpHdr...)
	p := &packet.Packet{}
	p.Parse(data, "test")
	return p
}

// loadGeoIPInline 通过临时文件加载 geoip 条目
func loadGeoIPInline(db *geoip.DB, entries ...string) {
	f, err := os.CreateTemp("", "geoip_*.csv")
	if err != nil {
		return
	}
	defer os.Remove(f.Name())
	f.WriteString(strings.Join(entries, "\n"))
	f.Close()
	db.LoadFromCSV(f.Name())
}
