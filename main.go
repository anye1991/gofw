// Command gofw 是网络层防火墙。
//
// 用法:
//
//	gofw start -r rules.yaml [-i eth0] [--monitor] [--workers N]
//	gofw rules list -r rules.yaml
//	gofw rules add ...
//	gofw rules del <index>
//	gofw test -r rules.yaml <hex_frame>
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gofw/alert"
	"gofw/capture"
	"gofw/config"
	"gofw/enforce"
	"gofw/engine"
	"gofw/geoip"
	"gofw/ha"
	"gofw/packet"
	"gofw/rules"
	"gofw/webui"

	"gopkg.in/yaml.v3"
)

const version = "1.0.0"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "start":
		os.Exit(cmdStart(os.Args[2:]))
	case "rules":
		os.Exit(cmdRules(os.Args[2:]))
	case "conns":
		os.Exit(cmdConns(os.Args[2:]))
	case "reload":
		os.Exit(cmdReload(os.Args[2:]))
	case "test":
		os.Exit(cmdTest(os.Args[2:]))
	case "-v", "--version":
		fmt.Println("gofw", version)
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`gofw - 网络层防火墙 (Go)

用法:
  gofw start -r rules.yaml [-i eth0] [--monitor] [--workers N] [--stats-interval N] [--ctl-sock PATH]
                            [--gateway] [--web :8080] [--ha ha.yaml] [--alert alert.yaml]
  gofw rules list -r rules.yaml
  gofw rules stats [--ctl-sock PATH]
  gofw rules add -r rules.yaml <action> [--src-ip CIDR] [--dst-ip CIDR] [-p proto] [--src-port P] [--dst-port P] [--tcp-flags f] [--direction in|out] [--state s] [--comment "x"] [--conn-limit N] [--bandwidth Mbps] [--geoip CN,US]
  gofw rules del -r rules.yaml <index>
  gofw conns list [--ctl-sock PATH]
  gofw reload [--ctl-sock PATH]
  gofw test -r rules.yaml <hex_frame>`)
}

// ---------------------------------------------------------------------------
// start
// ---------------------------------------------------------------------------
func cmdStart(args []string) int {
	fs := newFlagSet(args)
	rulesFile := fs.string("r", "rules", "")
	iface := fs.string("i", "interface", "eth0")
	monitor := fs.bool("", "monitor", false)
	workers := fs.int("", "workers", runtime.NumCPU())
	statsInterval := fs.float("", "stats-interval", 0)
	keepRules := fs.bool("", "keep-rules", false)
	ctlSock := fs.string("", "ctl-sock", "/tmp/gofw.sock")
	logFile := fs.string("", "log-file", "")
	gateway := fs.bool("", "gateway", false)
	webAddr := fs.string("", "web", "")       // Web 管理界面监听地址
	haConfig := fs.string("", "ha", "")       // HA 配置文件
	alertConfig := fs.string("", "alert", "") // 告警配置文件

	if rulesFile == "" {
		fmt.Fprintln(os.Stderr, "error: -r rules.yaml is required")
		return 1
	}

	// 文件日志（同时输出到 stderr 和文件）
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "cannot open log file %s: %v\n", logFile, err)
			return 1
		}
		log.SetOutput(io.MultiWriter(os.Stderr, f))
	}

	rs, err := config.Load(rulesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error loading rules: %v\n", err)
		return 1
	}
	log.Printf("loaded %d rules from %s (default=%s)", rs.Len(), rulesFile, rs.DefaultAction)

	var rsPtr atomic.Pointer[rules.RuleSet]
	rsPtr.Store(rs)

	var engPtr atomic.Pointer[engine.Engine]
	eng := engine.NewEngine(rs)
	engPtr.Store(eng)

	// GeoIP 数据库加载（优先外部 CSV，否则使用内置国家库）
	geoPath := rulesFile + ".geoip"
	var geoDB *geoip.DB
	if _, err := os.Stat(geoPath); err == nil {
		db := geoip.New()
		if err := db.LoadFromCSV(geoPath); err != nil {
			log.Printf("warning: geoip load failed: %v", err)
		} else {
			geoDB = db
			eng.SetGeoIP(db)
			log.Printf("geoip loaded from %s: %d entries", geoPath, db.Count())
		}
	} else {
		// 无外部 CSV，加载内置国家库
		geoDB = geoip.NewWithBuiltin()
		eng.SetGeoIP(geoDB)
		log.Printf("geoip builtin loaded: %d entries", geoDB.Count())
	}

	// 告警管理器
	var alertMgr *alert.Manager
	if alertConfig != "" {
		ac, err := loadAlertConfig(alertConfig)
		if err != nil {
			log.Printf("warning: alert config load failed: %v", err)
		} else {
			alertMgr = alert.NewManager(ac)
			log.Printf("alert enabled (webhook=%s, email_to=%v)", ac.WebhookURL, ac.Email.To)
		}
	}

	// HA 高可用
	var haMgr *ha.Manager
	if haConfig != "" {
		hc, err := loadHAConfig(haConfig)
		if err != nil {
			log.Printf("warning: ha config load failed: %v", err)
		} else {
			haMgr = ha.NewManager(hc)
			haMgr.SetCallbacks(
				func() { log.Println("[ha] promoted: taking over VIP") },
				func() { log.Println("[ha] demoted: releasing VIP") },
			)
			haMgr.Start()
			log.Printf("ha started, mode=%s, peer=%s, vip=%s", hc.Mode, hc.PeerIP, hc.VIP)
		}
	}

	enf := enforce.BuildEnforcer(!monitor)
	if g, ok := enf.(*enforce.NftablesEnforcer); ok && geoDB != nil {
		g.SetGeoIP(geoDB)
	}
	if !enf.Apply(rs) {
		log.Printf("failed to apply ruleset to enforcer")
		return 1
	}

	// 网关模式：启用 IP 转发
	if gateway {
		if err := enableIPForwarding(); err != nil {
			log.Printf("warning: cannot enable IP forwarding: %v", err)
		} else {
			log.Println("IP forwarding enabled (gateway mode)")
		}
	}

	// 支持多接口（逗号分隔），用于网关模式同时抓内外网卡
	ifaces := splitIfaces(iface)
	var pktCh <-chan *packet.Packet
	var stopCapture func()
	if len(ifaces) > 1 {
		mcap := capture.NewMulti(ifaces)
		if err := mcap.Open(); err != nil {
			fmt.Fprintf(os.Stderr, "cannot open capture on %v: %v\n", ifaces, err)
			return 1
		}
		defer mcap.Close()
		pktCh = mcap.Packets(65536)
		stopCapture = mcap.Stop
		log.Printf("gofw gateway mode, capturing on %v", ifaces)
	} else {
		cap := capture.New(iface)
		if err := cap.Open(); err != nil {
			fmt.Fprintf(os.Stderr, "cannot open capture on %s: %v\n", iface, err)
			return 1
		}
		defer cap.Close()
		pktCh = cap.Packets(65536)
		stopCapture = cap.Stop
	}

	log.Printf("gofw started (backend=%s, workers=%d, ctl=%s)", enf.Name(), workers, ctlSock)

	// 并发流水线
	decCh := make(chan engine.Decision, 4096)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range pktCh {
				e := engPtr.Load()
				dec := e.Decide(p)
				decCh <- dec
			}
		}()
	}

	// 执行 goroutine
	go func() {
		for d := range decCh {
			enf.OnDecision(d)
			capture.ReleasePacket(d.Packet)
		}
	}()

	// 控制 socket
	ctlStop := make(chan struct{})
	go serveControl(ctlSock, &engPtr, &rsPtr, rulesFile, enf, ctlStop)

	// Web 管理界面
	if webAddr != "" {
		go func() {
			applyFn := func(newRS *rules.RuleSet) {
				engPtr.Load().SetRuleset(newRS)
				rsPtr.Store(newRS)
				enf.Apply(newRS)
			}
			srv := webui.New(&engPtr, &rsPtr, webAddr, rulesFile, applyFn)
			log.Printf("web UI listening on %s", webAddr)
			if err := srv.Start(); err != nil {
				log.Printf("web UI error: %v", err)
			}
		}()
	}

	// 统计 + 告警
	var lastDropped uint64
	if statsInterval > 0 || alertMgr != nil {
		go func() {
			interval := statsInterval
			if interval <= 0 {
				interval = 1 // 默认每秒检查一次（用于告警）
			}
			t := time.NewTicker(time.Duration(interval * float64(time.Second)))
			defer t.Stop()
			for range t.C {
				s := engPtr.Load().Stats()
				dropped := s["dropped"].(uint64)
				droppedPerSec := dropped - lastDropped
				lastDropped = dropped
				if statsInterval > 0 {
					log.Printf("stats: pkts=%v accepted=%v dropped=%v conns=%v",
						s["packets"], s["accepted"], s["dropped"], s["connections"])
				}
				if alertMgr != nil {
					alertMgr.CheckDropRate(int64(droppedPerSec))
				}
			}
		}()
	}

	// 信号处理
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGUSR1)

	for {
		sig := <-sigCh
		switch sig {
		case syscall.SIGHUP:
			log.Println("SIGHUP received, reloading rules...")
			newRS, err := config.Load(rulesFile)
			if err != nil {
				log.Printf("reload failed: %v", err)
				continue
			}
			// 热替换规则集，保留连接跟踪表（持久连接跟踪）
			curEng := engPtr.Load()
			curEng.SetRuleset(newRS)
			rsPtr.Store(newRS)
			enf.Apply(newRS)
			log.Printf("reloaded %d rules (default=%s), conntrack preserved", newRS.Len(), newRS.DefaultAction)
		case syscall.SIGUSR1:
			s := engPtr.Load().Stats()
			log.Printf("SIGUSR1 stats: pkts=%v accepted=%v dropped=%v bytes=%v conns=%v",
				s["packets"], s["accepted"], s["dropped"], s["bytes"], s["connections"])
		case syscall.SIGINT, syscall.SIGTERM:
			log.Println("shutting down...")
			stopCapture()
			wg.Wait()
			close(decCh)
			time.Sleep(100 * time.Millisecond)
			close(ctlStop)
			os.Remove(ctlSock)
			if haMgr != nil {
				haMgr.Stop()
			}

			if !keepRules {
				enf.Flush()
				log.Println("rules flushed")
			}
			s := engPtr.Load().Stats()
			log.Printf("final stats: pkts=%v accepted=%v dropped=%v bytes=%v conns=%v",
				s["packets"], s["accepted"], s["dropped"], s["bytes"], s["connections"])
			return 0
		}
	}
}

// ---------------------------------------------------------------------------
// rules
// ---------------------------------------------------------------------------
func cmdRules(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: gofw rules <list|stats|add|del> ...")
		return 1
	}
	switch args[0] {
	case "list":
		return cmdRulesList(args[1:])
	case "stats":
		return ctlRequest(args[1:], "stats")
	case "add":
		return cmdRulesAdd(args[1:])
	case "del":
		return cmdRulesDel(args[1:])
	}
	fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n", args[0])
	return 1
}

func cmdRulesList(args []string) int {
	fs := newFlagSet(args)
	rulesFile := fs.string("r", "rules", "")
	if rulesFile == "" {
		fmt.Fprintln(os.Stderr, "error: -r rules.yaml is required")
		return 1
	}
	rs, err := config.Load(rulesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	fmt.Printf("# ruleset: %d rules, default=%s\n", rs.Len(), rs.DefaultAction)
	for i, r := range rs.Rules {
		fmt.Printf("[%2d] %s\n", i, r.String())
	}
	return 0
}

func cmdRulesAdd(args []string) int {
	fs := newFlagSet(args)
	rulesFile := fs.string("r", "rules", "")
	action := strings.ToUpper(fs.positional(0))
	srcIP := fs.string("", "src-ip", "")
	dstIP := fs.string("", "dst-ip", "")
	proto := fs.string("p", "protocol", "")
	srcPort := fs.string("", "src-port", "")
	dstPort := fs.string("", "dst-port", "")
	tcpFlags := fs.string("", "tcp-flags", "")
	direction := fs.string("", "direction", "")
	state := fs.string("", "state", "")
	comment := fs.string("", "comment", "")
	srcMAC := fs.string("", "src-mac", "")
	dstMAC := fs.string("", "dst-mac", "")
	vlan := fs.int("", "vlan", 0)
	timeSpec := fs.string("", "time", "")
	rateLimit := fs.int("", "rate-limit", 0)
	burst := fs.int("", "burst", 0)
	perSrc := fs.bool("", "per-src", false)
	ipGroup := fs.string("", "ip-group", "")
	natType := fs.string("", "nat-type", "")
	natToSrcIP := fs.string("", "nat-to-src-ip", "")
	natToSrcPort := fs.int("", "nat-to-src-port", 0)
	natToDstIP := fs.string("", "nat-to-dst-ip", "")
	natToDstPort := fs.int("", "nat-to-dst-port", 0)
	connLimit := fs.int("", "conn-limit", 0)
	bandwidth := fs.float("", "bandwidth", 0)
	burstBytes := fs.int("", "burst-bytes", 0)
	geoip := fs.string("", "geoip", "")
	appProto := fs.string("", "app-proto", "")

	if rulesFile == "" {
		fmt.Fprintln(os.Stderr, "error: -r rules.yaml is required")
		return 1
	}
	rs, err := config.Load(rulesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if !validAction(action) {
		fmt.Fprintf(os.Stderr, "error: invalid action %s\n", action)
		return 1
	}
	rule := rules.NewRule(action)
	if srcIP != "" {
		rule.SrcIP = rules.ParseIPMatcher(srcIP)
	}
	if dstIP != "" {
		rule.DstIP = rules.ParseIPMatcher(dstIP)
	}
	if proto != "" {
		p, ok := protoNum(strings.ToLower(proto))
		if !ok {
			fmt.Fprintf(os.Stderr, "error: invalid protocol %s\n", proto)
			return 1
		}
		rule.Protocol = &p
	}
	if srcPort != "" {
		rule.SrcPort = rules.ParsePortSpec(srcPort)
	}
	if dstPort != "" {
		rule.DstPort = rules.ParsePortSpec(dstPort)
	}
	if tcpFlags != "" {
		rule.TCPFlags = tcpFlagSet(strings.Split(tcpFlags, ","))
	}
	if direction != "" {
		rule.Direction = direction
	}
	if state != "" {
		rule.State = state
	}
	if srcMAC != "" {
		rule.SrcMAC = rules.ParseMACMatcher(srcMAC)
	}
	if dstMAC != "" {
		rule.DstMAC = rules.ParseMACMatcher(dstMAC)
	}
	if vlan != 0 {
		v := uint16(vlan)
		rule.VLAN = &v
	}
	if timeSpec != "" {
		rule.Time = rules.ParseTimeSpec(timeSpec)
	}
	if rateLimit > 0 {
		rule.RateLimit = rules.ParseRateLimit(rateLimit, burst, perSrc)
	}
	if bandwidth > 0 {
		rule.Bandwidth = rules.ParseBandwidthLimit(bandwidth, int64(burstBytes), perSrc)
	}
	if connLimit > 0 {
		rule.ConnLimit = rules.ParseConnLimit(connLimit, perSrc)
	}
	if geoip != "" {
		rule.GeoIP = rules.ParseGeoIPSpec(geoip)
	}
	if appProto != "" {
		rule.AppProto = strings.ToLower(appProto)
	}
	if ipGroup != "" {
		rule.IPGroup = ipGroup
	}
	if natType != "" {
		rule.NAT = &rules.NATSpec{
			Type:      strings.ToLower(natType),
			ToSrcIP:   natToSrcIP,
			ToSrcPort: uint16(natToSrcPort),
			ToDstIP:   natToDstIP,
			ToDstPort: uint16(natToDstPort),
		}
	}
	rule.Comment = comment

	rs.Add(rule)
	if err := saveRules(rs, rulesFile); err != nil {
		fmt.Fprintf(os.Stderr, "error saving: %v\n", err)
		return 1
	}
	fmt.Printf("added rule: %s\n", rule.String())
	return 0
}

func cmdRulesDel(args []string) int {
	fs := newFlagSet(args)
	rulesFile := fs.string("r", "rules", "")
	idxStr := fs.positional(0)
	if rulesFile == "" || idxStr == "" {
		fmt.Fprintln(os.Stderr, "usage: gofw rules del -r rules.yaml <index>")
		return 1
	}
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid index %s\n", idxStr)
		return 1
	}
	rs, err := config.Load(rulesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	if idx < 0 || idx >= rs.Len() {
		fmt.Fprintf(os.Stderr, "error: index %d out of range\n", idx)
		return 1
	}
	removed := rs.Rules[idx]
	rs.Rules = append(rs.Rules[:idx], rs.Rules[idx+1:]...)
	if err := saveRules(rs, rulesFile); err != nil {
		fmt.Fprintf(os.Stderr, "error saving: %v\n", err)
		return 1
	}
	fmt.Printf("removed rule [%d]: %s\n", idx, removed.String())
	return 0
}

// ---------------------------------------------------------------------------
// test
// ---------------------------------------------------------------------------
func cmdTest(args []string) int {
	fs := newFlagSet(args)
	rulesFile := fs.string("r", "rules", "")
	frame := fs.positional(0)
	if rulesFile == "" || frame == "" {
		fmt.Fprintln(os.Stderr, "usage: gofw test -r rules.yaml <hex_frame>")
		return 1
	}
	rs, err := config.Load(rulesFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}
	frame = strings.ReplaceAll(frame, " ", "")
	frame = strings.ReplaceAll(frame, ":", "")
	data, err := hex.DecodeString(frame)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: invalid hex: %v\n", err)
		return 1
	}
	p := &packet.Packet{}
	p.Parse(data, "test")
	eng := engine.NewEngine(rs)
	d := eng.Decide(p)
	fmt.Printf("packet : %s\n", p.Summary())
	fmt.Printf("action : %s\n", d.Action)
	fmt.Printf("state  : %s\n", d.ConnState)
	fmt.Printf("rule   : %s\n", d.Rule)
	return 0
}

// ---------------------------------------------------------------------------
// conns / reload (控制面客户端)
// ---------------------------------------------------------------------------
func cmdConns(args []string) int {
	if len(args) == 0 || args[0] != "list" {
		fmt.Fprintln(os.Stderr, "usage: gofw conns list [--ctl-sock PATH]")
		return 1
	}
	return ctlRequest(args[1:], "conns")
}

func cmdReload(args []string) int {
	return ctlRequest(args, "reload")
}

// ctlRequest 向控制 socket 发送命令并打印响应。
func ctlRequest(args []string, cmd string) int {
	fs := newFlagSet(args)
	sock := fs.string("", "ctl-sock", "/tmp/gofw.sock")
	conn, err := net.Dial("unix", sock)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot connect to %s: %v (is gofw running?)\n", sock, err)
		return 1
	}
	defer conn.Close()
	fmt.Fprintln(conn, cmd)
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for scanner.Scan() {
		fmt.Println(scanner.Text())
	}
	return 0
}

// serveControl 启动 Unix socket 控制面。
func serveControl(sockPath string, engPtr *atomic.Pointer[engine.Engine], rsPtr *atomic.Pointer[rules.RuleSet], rulesFile string, enf enforce.Enforcer, stop <-chan struct{}) {
	os.Remove(sockPath)
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		log.Printf("control socket listen failed: %v", err)
		return
	}
	go func() {
		<-stop
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-stop:
				return
			default:
			}
			log.Printf("control accept error: %v", err)
			continue
		}
		go handleControl(conn, engPtr, rsPtr, rulesFile, enf)
	}
}

func handleControl(conn net.Conn, engPtr *atomic.Pointer[engine.Engine], rsPtr *atomic.Pointer[rules.RuleSet], rulesFile string, enf enforce.Enforcer) {
	defer conn.Close()
	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		return
	}
	cmd := strings.TrimSpace(scanner.Text())
	enc := json.NewEncoder(conn)
	switch cmd {
	case "conns":
		conns := engPtr.Load().Conntrack.Dump()
		enc.Encode(conns)
	case "stats":
		eng := engPtr.Load()
		out := map[string]interface{}{
			"engine": eng.Stats(),
			"rules":  eng.RuleStats(),
		}
		enc.Encode(out)
	case "reload":
		newRS, err := config.Load(rulesFile)
		if err != nil {
			enc.Encode(map[string]string{"status": "error", "error": err.Error()})
			return
		}
		engPtr.Load().SetRuleset(newRS)
		rsPtr.Store(newRS)
		enf.Apply(newRS)
		enc.Encode(map[string]interface{}{"status": "ok", "rules": newRS.Len()})
	default:
		enc.Encode(map[string]string{"status": "error", "error": "unknown command: " + cmd})
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
func validAction(a string) bool {
	switch a {
	case rules.ActionAccept, rules.ActionDrop, rules.ActionReject, rules.ActionLog:
		return true
	}
	return false
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

func tcpFlagSet(items []string) uint8 {
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

func saveRules(rs *rules.RuleSet, path string) error {
	return config.Save(rs, path)
}

// splitIfaces 将逗号分隔的接口列表拆分为切片。
func splitIfaces(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// enableIPForwarding 启用内核 IPv4/IPv6 转发（网关模式）。
func enableIPForwarding() error {
	for _, path := range []string{
		"/proc/sys/net/ipv4/ip_forward",
		"/proc/sys/net/ipv6/conf/all/forwarding",
	} {
		if err := os.WriteFile(path, []byte("1"), 0644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}
	return nil
}

// loadAlertConfig 从 YAML 加载告警配置。
func loadAlertConfig(path string) (*alert.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg alert.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// loadHAConfig 从 YAML 加载 HA 配置。
func loadHAConfig(path string) (*ha.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ha.Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
