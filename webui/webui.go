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
	"gofw/rules"
)

//go:embed index.html
var dashboardHTML string

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
		ruleList = append(ruleList, map[string]interface{}{
			"index":   i,
			"action":  rl.Action,
			"detail":  rl.String(),
			"hits":    rl.HitCount(),
			"bytes":   rl.HitBytes(),
			"comment": rl.Comment,
		})
	}
	writeJSON(w, map[string]interface{}{
		"default": rs.DefaultAction,
		"rules":   ruleList,
		"stats":   eng.RuleStats(),
	})
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
