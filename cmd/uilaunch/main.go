// 仅用于本地预览 gofw 的 Web 管理界面（不抓包、不下发内核规则）。
// 用法: go run ./cmd/uilaunch -r rules.yaml -web :18081
// 可选 --demo 开启合成流量，让实时拦截流 / 吞吐曲线有数据可看（仅预览用）。
package main

import (
	"flag"
	"log"
	"math/rand"
	"net"
	"sync/atomic"
	"time"

	"gofw/config"
	"gofw/engine"
	"gofw/geoip"
	"gofw/packet"
	"gofw/rules"
	"gofw/webui"
)

func main() {
	rulesFile := flag.String("r", "", "rules.yaml 路径")
	webAddr := flag.String("web", ":18080", "Web UI 监听地址")
	demo := flag.Bool("demo", true, "生成合成流量用于演示实时拦截流")
	flag.Parse()

	if *rulesFile == "" {
		log.Fatal("error: -r rules.yaml is required")
	}

	rs, err := config.Load(*rulesFile)
	if err != nil {
		log.Fatalf("error loading rules: %v", err)
	}
	log.Printf("loaded %d rules (default=%s)", rs.Len(), rs.DefaultAction)

	var rsPtr atomic.Pointer[rules.RuleSet]
	rsPtr.Store(rs)

	var engPtr atomic.Pointer[engine.Engine]
	eng := engine.NewEngine(rs)
	eng.SetGeoIP(geoip.NewWithBuiltin())
	engPtr.Store(eng)

	// 预览用：应用规则时只更新引擎，不触碰内核。
	applyFn := func(newRS *rules.RuleSet) {
		engPtr.Load().SetRuleset(newRS)
		rsPtr.Store(newRS)
	}

	if *demo {
		go feed(eng)
	}

	srv := webui.New(&engPtr, &rsPtr, *webAddr, *rulesFile, applyFn)
	log.Printf("gofw Web UI 预览模式 → http://localhost%s  (密码: gofw-demo)", *webAddr)
	if err := srv.Start(); err != nil {
		log.Fatalf("web UI error: %v", err)
	}
}

// feed 合成流量喂给引擎，使实时拦截流 / 统计有数据。仅演示用。
func feed(eng *engine.Engine) {
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	cidr := net.IPNet{IP: net.IPv4(203, 0, 113, 0), Mask: net.CIDRMask(24, 32)}
	for {
		p := &packet.Packet{
			Proto:   packet.ProtoTCP,
			SrcPort: uint16(1024 + rng.Intn(60000)),
			DstPort: 80,
		}
		if rng.Float32() < 0.18 {
			// 命中已知恶意网段 → DROP
			p.SrcIP = cidr.IP.To4()
			p.SrcIP[3] = byte(1 + rng.Intn(254))
		} else {
			// 普通来访 → ACCEPT
			b := byte(1 + rng.Intn(254))
			p.SrcIP = net.IPv4(11+byte(rng.Intn(50)), b, byte(rng.Intn(255)), byte(rng.Intn(255)))
		}
		p.DstIP = net.IPv4(10, 0, 0, 10)
		eng.Decide(p)
		time.Sleep(time.Duration(40+rng.Intn(80)) * time.Millisecond)
	}
}
