// Package webui 提供 Web 管理界面和 REST API。
package webui

import (
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gofw/config"
	"gofw/engine"
	"gofw/geoctl"
	"gofw/rules"
)

//go:embed index.html
var dashboardHTML string

//go:embed favicon.ico
var faviconData []byte

const sessionTTL = 24 * time.Hour

// Server Web 管理服务器。
type Server struct {
	engPtr    *atomic.Pointer[engine.Engine]
	rsPtr     *atomic.Pointer[rules.RuleSet]
	addr      string
	rulesFile string               // 规则文件路径，用于持久化
	apply     func(*rules.RuleSet) // 应用新规则集的回调（热替换 + nftables）
	mu        sync.Mutex           // 写操作互斥锁，防止并发修改导致丢失更新

	password string             // 非空时启用登录鉴权（来自环境变量 GOFW_WEB_PASSWORD）
	sessions map[string]int64   // sid -> 过期时间戳
	sessMu   sync.Mutex

	// 地理围栏扩展（通过 SetGeo 注入，均为可选；nil 时相关 API 返回降级信息）
	geoCtl    *geoctl.Tracker
	reloadGeo func() (int, error) // 重新加载 GeoIP CSV，返回条目数
	geoPath   string              // GeoIP 库文件路径（展示用）
	geoSource string              // 库来源 "external" / "builtin"
	backend   string              // 执行后端 "kernel"(nftables 真实丢包) / "monitor"(旁路记录)
}

// New 创建 Web 管理服务器。
// apply 回调负责将新规则集热替换到引擎并下发 nftables。
func New(engPtr *atomic.Pointer[engine.Engine], rsPtr *atomic.Pointer[rules.RuleSet], addr, rulesFile string, apply func(*rules.RuleSet)) *Server {
	s := &Server{
		engPtr:    engPtr,
		rsPtr:     rsPtr,
		addr:      addr,
		rulesFile: rulesFile,
		apply:     apply,
		password:  strings.TrimSpace(os.Getenv("GOFW_WEB_PASSWORD")),
	}
	if s.password != "" {
		s.sessions = make(map[string]int64)
	}
	return s
}

// SetGeo 注入地理围栏扩展依赖（由 main.go 装配，可选）。
// source 为库来源（external/builtin），backend 为执行后端（kernel/monitor）。
func (s *Server) SetGeo(ctl *geoctl.Tracker, reload func() (int, error), path, source, backend string) {
	s.geoCtl = ctl
	s.reloadGeo = reload
	s.geoPath = path
	s.geoSource = source
	s.backend = backend
}

// Start 启动 HTTP 服务器。
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.handleLogout)
	mux.HandleFunc("/api/events", s.auth(s.handleEvents))
	mux.HandleFunc("/api/stats", s.auth(s.handleStats))
	mux.HandleFunc("/api/rules", s.auth(s.handleRules))
	mux.HandleFunc("/api/rules/", s.auth(s.handleRules)) // 处理 /api/rules/{index} 子路径
	mux.HandleFunc("/api/conns", s.auth(s.handleConns))
	mux.HandleFunc("/api/config", s.auth(s.handleConfig))
	mux.HandleFunc("/api/reload", s.auth(s.handleReload))
	mux.HandleFunc("/api/system", s.auth(s.handleSystem))
	mux.HandleFunc("/api/ipgroups", s.auth(s.handleIPGroups))
	mux.HandleFunc("/api/ipgroups/", s.auth(s.handleIPGroups))
	// 地理围栏扩展 API
	mux.HandleFunc("/api/geofence", s.auth(s.handleGeofence))
	mux.HandleFunc("/api/geofence/", s.auth(s.handleGeofence))
	mux.HandleFunc("/api/geoip/countries", s.auth(s.handleGeoCountries))
	mux.HandleFunc("/api/geoip/stats", s.auth(s.handleGeoStats))
	mux.HandleFunc("/api/geoip/reload", s.auth(s.handleGeoReload))
	mux.HandleFunc("/api/bans", s.auth(s.handleBans))
	mux.HandleFunc("/api/bans/", s.auth(s.handleBans))
	mux.HandleFunc("/favicon.ico", s.handleFavicon)
	mux.HandleFunc("/", s.auth(s.handleIndex))

	srv := &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}
	return srv.ListenAndServe()
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	io.WriteString(w, dashboardHTML)
}

// handleFavicon 返回内嵌的盾牌图标（编译进二进制，无需外部文件）。
func (s *Server) handleFavicon(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/x-icon")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(faviconData)
}

// auth 中间件：未设置密码时放行；设置密码时，仅对 /api/* 校验会话 cookie，
// 登录接口本身匿名可达，页面（含登录框）始终返回以便前端引导登录。
func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	if s.password == "" {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/login" || !strings.HasPrefix(r.URL.Path, "/api/") {
			next(w, r)
			return
		}
		c, err := r.Cookie("gofw_sid")
		if err != nil || !s.validSession(c.Value) {
			writeError(w, http.StatusUnauthorized, "not authenticated")
			return
		}
		next(w, r)
	}
}

func (s *Server) validSession(sid string) bool {
	s.sessMu.Lock()
	defer s.sessMu.Unlock()
	exp, ok := s.sessions[sid]
	if !ok || exp < time.Now().Unix() {
		delete(s.sessions, sid)
		return false
	}
	return true
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if s.password == "" {
		writeJSON(w, map[string]interface{}{"ok": true, "auth": false, "note": "no password configured"})
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	if subtle.ConstantTimeCompare([]byte(body.Password), []byte(s.password)) != 1 {
		writeError(w, http.StatusUnauthorized, "invalid password")
		return
	}
	sid := randHex(32)
	s.sessMu.Lock()
	s.sessions[sid] = time.Now().Add(sessionTTL).Unix()
	s.sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     "gofw_sid",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   int(sessionTTL.Seconds()),
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, map[string]interface{}{"ok": true})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("gofw_sid"); err == nil {
		s.sessMu.Lock()
		delete(s.sessions, c.Value)
		s.sessMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "gofw_sid", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, map[string]interface{}{"ok": true})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	eng := s.engPtr.Load()
	out := map[string]interface{}{
		"engine": eng.Stats(),
		"rules":  eng.RuleStats(),
	}
	writeJSON(w, out)
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	eng := s.engPtr.Load()
	writeJSON(w, map[string]interface{}{
		"events": eng.Recent(),
		"count":  len(eng.Recent()),
	})
}

func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleRulesList(w, r)
	case http.MethodPost:
		s.handleRuleAdd(w, r)
	case http.MethodPut:
		s.handleRuleUpdate(w, r)
	case http.MethodDelete:
		s.handleRuleDelete(w, r)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRulesList(w http.ResponseWriter, r *http.Request) {
	eng := s.engPtr.Load()
	rs := s.rsPtr.Load()
	var ruleList []map[string]interface{}
	for i, rl := range rs.Rules {
		rm := ruleToMap(rl)
		rm["index"] = i
		ruleList = append(ruleList, rm)
	}
	var groups []map[string]interface{}
	for name, m := range rs.IPGroups {
		groups = append(groups, map[string]interface{}{"name": name, "cidr": m.String()})
	}
	writeJSON(w, map[string]interface{}{
		"default":   rs.DefaultAction,
		"rules":     ruleList,
		"ip_groups": groups,
		"stats":     eng.RuleStats(),
	})
}

// ruleToMap 将引擎 Rule 完整序列化为前端表单可用的结构（覆盖全部引擎字段）。
func ruleToMap(rl *rules.Rule) map[string]interface{} {
	m := map[string]interface{}{
		"action":  rl.Action,
		"name":    rl.Name,
		"comment": rl.Comment,
		"detail":  rl.String(),
		"hits":    rl.HitCount(),
		"bytes":   rl.HitBytes(),
	}
	if rl.SrcIP.String() != "any" {
		m["src_ip"] = rl.SrcIP.String()
	}
	if rl.DstIP.String() != "any" {
		m["dst_ip"] = rl.DstIP.String()
	}
	if rl.SrcMAC.String() != "any" {
		m["src_mac"] = rl.SrcMAC.String()
	}
	if rl.DstMAC.String() != "any" {
		m["dst_mac"] = rl.DstMAC.String()
	}
	if rl.Protocol != nil {
		switch *rl.Protocol {
		case 6:
			m["protocol"] = "tcp"
		case 17:
			m["protocol"] = "udp"
		case 1:
			m["protocol"] = "icmp"
		case 58:
			m["protocol"] = "icmpv6"
		}
	}
	if rl.SrcPort != nil && rl.SrcPort.String() != "any" {
		m["src_port"] = rl.SrcPort.String()
	}
	if rl.DstPort != nil && rl.DstPort.String() != "any" {
		m["dst_port"] = rl.DstPort.String()
	}
	if rl.TCPFlags != 0 {
		m["tcp_flags"] = rules.TCPFlagsToString(rl.TCPFlags)
		if rl.TCPFlagsMask != 0 && rl.TCPFlagsMask != rl.TCPFlags {
			m["tcp_flags_mask"] = rules.TCPFlagsToString(rl.TCPFlagsMask)
		}
	}
	if rl.Direction != rules.DirAny {
		m["direction"] = rl.Direction
	}
	if rl.State != "" {
		m["state"] = rl.State
	}
	if rl.VLAN != nil {
		m["vlan"] = int(*rl.VLAN)
	}
	if rl.Time != nil && rl.Time.String() != "" {
		m["time"] = rl.Time.String()
	}
	if rl.RateLimit != nil && rl.RateLimit.Rate > 0 {
		m["rate_limit"] = rl.RateLimit.Rate
		m["burst"] = rl.RateLimit.Burst
		m["per_src"] = rl.RateLimit.PerSrc
	}
	if rl.Bandwidth != nil && rl.Bandwidth.BytesPerSec > 0 {
		m["bandwidth"] = float64(rl.Bandwidth.BytesPerSec) * 8 / 1024 / 1024
		m["burst_bytes"] = rl.Bandwidth.Burst
		m["per_src"] = m["per_src"] == true || rl.Bandwidth.PerSrc
	}
	if rl.ConnLimit != nil && rl.ConnLimit.Max > 0 {
		m["conn_limit"] = rl.ConnLimit.Max
		m["per_src"] = m["per_src"] == true || rl.ConnLimit.PerSrc
	}
	if rl.GeoIP != nil {
		if s := rl.GeoIP.String(); s != "" {
			m["geoip"] = s
		}
	}
	if rl.AppProto != "" {
		m["app_proto"] = rl.AppProto
	}
	if rl.IPGroup != "" {
		m["ip_group"] = rl.IPGroup
	}
	if rl.NAT != nil {
		m["nat"] = map[string]interface{}{
			"type":        rl.NAT.Type,
			"to_src_ip":   rl.NAT.ToSrcIP,
			"to_src_port": int(rl.NAT.ToSrcPort),
			"to_dst_ip":   rl.NAT.ToDstIP,
			"to_dst_port": int(rl.NAT.ToDstPort),
		}
	}
	return m
}

// handleSystem 返回引擎模块能力状态，供「能力中心」页展示。
func (s *Server) handleSystem(w http.ResponseWriter, r *http.Request) {
	eng := s.engPtr.Load()
	geoLoaded, geoCount, geoV4, geoV6, geoCountries := false, 0, 0, 0, 0
	if eng.GeoIP != nil {
		geoLoaded = eng.GeoIP.Loaded()
		geoCount = eng.GeoIP.Count()
		var codes []string
		_, geoV4, geoV6, codes = eng.GeoIP.Stats()
		geoCountries = len(codes)
	}
	// 地理围栏是否启用：按托管规则标记判定，与 /api/geofence 同源，不靠页面猜测。
	guardCount, fenceCount := 0, 0
	if rs := s.rsPtr.Load(); rs != nil {
		for _, rl := range rs.Rules {
			if strings.HasPrefix(rl.Comment, markGuard) {
				guardCount++
			}
			if strings.HasPrefix(rl.Comment, markGeo) {
				fenceCount++
			}
		}
	}
	// 自动封禁配置取运行实例真实值。
	var banCfg interface{}
	if s.geoCtl != nil {
		banCfg = s.geoCtl.GetConfig()
	}
	backend := s.backend
	if backend == "" {
		backend = "monitor"
	}
	writeJSON(w, map[string]interface{}{
		"backend": backend,
		"geoip": map[string]interface{}{
			"loaded":    geoLoaded,
			"count":     geoCount,
			"v4":        geoV4,
			"v6":        geoV6,
			"countries": geoCountries,
			"source":    s.geoSource,
			"path":      s.geoPath,
		},
		"geofence": map[string]interface{}{
			"active": fenceCount > 0,
			"guards": guardCount,
			"fences": fenceCount,
		},
		"autoban": banCfg,
		"dpi": map[string]interface{}{
			"enabled": true,
			"protocols": []string{"http", "tls", "ssh", "ftp", "smtp", "imap",
				"mysql", "postgresql", "redis", "mongodb", "dns", "ntp", "snmp", "sip"},
		},
		"conntrack": eng.Conntrack.Stats(),
		"frag":      map[string]interface{}{"enabled": true},
		"engine":    eng.Stats(),
	})
}

// handleIPGroups 管理 IP 地址簿（ip_groups）。GET 列表，POST 新增/更新，DELETE 删除。
func (s *Server) handleIPGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		rs := s.rsPtr.Load()
		var groups []map[string]interface{}
		for name, m := range rs.IPGroups {
			groups = append(groups, map[string]interface{}{"name": name, "cidr": m.String()})
		}
		writeJSON(w, map[string]interface{}{"groups": groups})
	case http.MethodPost:
		var body struct {
			Name string `json:"name"`
			CIDR string `json:"cidr"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		body.Name = strings.TrimSpace(body.Name)
		body.CIDR = strings.TrimSpace(body.CIDR)
		if body.Name == "" || body.CIDR == "" {
			writeError(w, http.StatusBadRequest, "name and cidr are required")
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		newRS := s.cloneRuleset()
		newRS.IPGroups[body.Name] = rules.ParseIPMatcher(body.CIDR)
		if err := s.commit(newRS); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, map[string]interface{}{"status": "ok", "name": body.Name})
	case http.MethodDelete:
		name, ok := parseName(r.URL.Path)
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid name")
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		newRS := s.cloneRuleset()
		delete(newRS.IPGroups, name)
		if err := s.commit(newRS); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, map[string]interface{}{"status": "ok"})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// parseName 从 /api/ipgroups/{name} 解析名称。
func parseName(path string) (string, bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) != 3 || parts[0] != "api" || parts[1] != "ipgroups" {
		return "", false
	}
	if parts[2] == "" {
		return "", false
	}
	return parts[2], true
}

// handleRuleAdd POST /api/rules - 添加一条规则。
// 请求体为 JSON，字段与 YAML 配置一致（action, src_ip, dst_ip, protocol, dst_port, ...）。
func (s *Server) handleRuleAdd(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	rule, err := config.ParseRuleJSON(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// 加锁防止并发修改导致丢失更新
	s.mu.Lock()
	defer s.mu.Unlock()
	rs := s.cloneRuleset()
	rs.Add(rule)
	if err := s.commit(rs); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]interface{}{
		"status": "added",
		"index":  len(rs.Rules) - 1,
		"rule":   rule.String(),
	})
}

// handleRuleUpdate PUT /api/rules/{index} - 替换指定索引的规则。
func (s *Server) handleRuleUpdate(w http.ResponseWriter, r *http.Request) {
	idx, ok := parseIndex(r.URL.Path)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid index")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	rule, err := config.ParseRuleJSON(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// 加锁：边界检查与修改在同一临界区内，避免 TOCTOU 竞态
	s.mu.Lock()
	defer s.mu.Unlock()
	newRS := s.cloneRuleset()
	if idx < 0 || idx >= len(newRS.Rules) {
		writeError(w, http.StatusNotFound, "rule index out of range")
		return
	}
	newRS.Rules[idx] = rule
	if err := s.commit(newRS); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]interface{}{
		"status": "updated",
		"index":  idx,
		"rule":   rule.String(),
	})
}

// handleRuleDelete DELETE /api/rules/{index} - 删除指定索引的规则。
func (s *Server) handleRuleDelete(w http.ResponseWriter, r *http.Request) {
	idx, ok := parseIndex(r.URL.Path)
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid index")
		return
	}
	// 加锁：边界检查与修改在同一临界区内
	s.mu.Lock()
	defer s.mu.Unlock()
	newRS := s.cloneRuleset()
	if idx < 0 || idx >= len(newRS.Rules) {
		writeError(w, http.StatusNotFound, "rule index out of range")
		return
	}
	newRS.Rules = append(newRS.Rules[:idx], newRS.Rules[idx+1:]...)
	if err := s.commit(newRS); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]interface{}{
		"status": "deleted",
		"index":  idx,
	})
}

// handleConfig GET 返回原始规则文件；PUT 解析并持久化 + 热应用。
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if s.rulesFile == "" {
			writeError(w, http.StatusNotFound, "no rules file")
			return
		}
		data, err := os.ReadFile(s.rulesFile)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Write(data)
	case http.MethodPut:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "read body: "+err.Error())
			return
		}
		newRS, err := config.LoadFromData(body)
		if err != nil {
			writeError(w, http.StatusBadRequest, "parse error: "+err.Error())
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		if err := s.commit(newRS); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, map[string]interface{}{"status": "saved", "rules": newRS.Len()})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// cloneRuleset 深拷贝当前规则集（保留默认动作和地址簿）。
func (s *Server) cloneRuleset() *rules.RuleSet {
	rs := s.rsPtr.Load()
	newRS := rules.NewRuleSet()
	newRS.DefaultAction = rs.DefaultAction
	for k, v := range rs.IPGroups {
		newRS.IPGroups[k] = v
	}
	for _, r := range rs.Rules {
		newRS.Rules = append(newRS.Rules, r)
	}
	return newRS
}

// commit 保存规则集到文件并热应用到引擎。
func (s *Server) commit(rs *rules.RuleSet) error {
	if s.rulesFile != "" {
		if err := config.Save(rs, s.rulesFile); err != nil {
			return fmt.Errorf("save rules: %w", err)
		}
	}
	if s.apply != nil {
		s.apply(rs)
	} else {
		s.rsPtr.Store(rs)
	}
	return nil
}

// parseIndex 从 URL 路径 /api/rules/{index} 解析索引。
func parseIndex(path string) (int, bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) != 3 || parts[0] != "api" || parts[1] != "rules" {
		return 0, false
	}
	idx, err := atoiSafe(parts[2])
	if err != nil {
		return 0, false
	}
	return idx, true
}

func atoiSafe(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("invalid")
		}
		n = n*10 + int(c-'0')
	}
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	return n, nil
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *Server) handleConns(w http.ResponseWriter, r *http.Request) {
	eng := s.engPtr.Load()
	conns := eng.Conntrack.Dump()
	writeJSON(w, map[string]interface{}{
		"connections": conns,
		"total":       len(conns),
	})
}

func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"status": "reload triggerred"})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "fallback"
	}
	const hexc = "0123456789abcdef"
	out := make([]byte, n*2)
	for i, x := range b {
		out[i*2] = hexc[x>>4]
		out[i*2+1] = hexc[x&0x0f]
	}
	return string(out)
}
