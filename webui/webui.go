// Package webui 提供 Web 管理界面和 REST API。
package webui

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"gofw/config"
	"gofw/engine"
	"gofw/rules"
)

// Server Web 管理服务器。
type Server struct {
	engPtr    *atomic.Pointer[engine.Engine]
	rsPtr     *atomic.Pointer[rules.RuleSet]
	addr      string
	rulesFile string               // 规则文件路径，用于持久化
	apply     func(*rules.RuleSet) // 应用新规则集的回调（热替换 + nftables）
	mu        sync.Mutex           // 写操作互斥锁，防止并发修改导致丢失更新
}

// New 创建 Web 管理服务器。
// apply 回调负责将新规则集热替换到引擎并下发 nftables。
func New(engPtr *atomic.Pointer[engine.Engine], rsPtr *atomic.Pointer[rules.RuleSet], addr, rulesFile string, apply func(*rules.RuleSet)) *Server {
	return &Server{engPtr: engPtr, rsPtr: rsPtr, addr: addr, rulesFile: rulesFile, apply: apply}
}

// Start 启动 HTTP 服务器。
func (s *Server) Start() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleDashboard)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/rules", s.handleRules)
	mux.HandleFunc("/api/rules/", s.handleRules) // 处理 /api/rules/{index} 子路径
	mux.HandleFunc("/api/conns", s.handleConns)
	mux.HandleFunc("/api/reload", s.handleReload)

	srv := &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}
	return srv.ListenAndServe()
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	rs := s.rsPtr.Load()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, dashboardHTML, rs.Len(), rs.DefaultAction)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	eng := s.engPtr.Load()
	out := map[string]interface{}{
		"engine": eng.Stats(),
		"rules":  eng.RuleStats(),
	}
	writeJSON(w, out)
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
	idx, err := strconv.Atoi(parts[2])
	if err != nil {
		return 0, false
	}
	return idx, true
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

var dashboardHTML = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>gofw Dashboard</title>
<style>
body{font-family:monospace;background:#1a1a2e;color:#e0e0e0;margin:20px}
h1{color:#0f3460;border-bottom:2px solid #16213e;padding-bottom:10px}
.card{background:#16213e;padding:15px;margin:10px 0;border-radius:8px}
.stat{font-size:24px;color:#e94560;font-weight:bold}
table{width:100%%;border-collapse:collapse;margin-top:10px}
th,td{padding:8px;text-align:left;border-bottom:1px solid #0f3460}
th{background:#0f3460}
</style></head><body>
<h1>gofw 防火墙管理面板</h1>
<div class="card"><b>规则数:</b> <span class="stat">%d</span> &nbsp; <b>默认动作:</b> <span class="stat">%s</span></div>
<div class="card"><b>实时统计 API:</b> <a href="/api/stats" style="color:#e94560">/api/stats</a> | 
<a href="/api/rules" style="color:#e94560">/api/rules</a> | 
<a href="/api/conns" style="color:#e94560">/api/conns</a></div>
<script>setTimeout(function(){location.reload()},5000)</script>
</body></html>`
