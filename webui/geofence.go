package webui

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"gofw/geoctl"
	"gofw/rules"
)

// 地理围栏规则标记：所有由本功能生成的规则都用 comment 前缀标识，
// 便于精确清除、重建，绝不误删用户手工维护的规则。
const (
	markGuard = "[gofw-guard] " // 防锁死护栏（放行管理通道）
	markGeo   = "[gofw-geo] "   // 地理围栏封锁规则
)

// guardProfile 防锁死护栏参数。默认值覆盖本机管理通道，
// 前端可覆盖；无论 preset 如何，护栏都会被强制前置且不可关闭。
type guardProfile struct {
	MgmtPorts string `json:"mgmt_ports"` // 管理端口，逗号分隔
	LanCIDR   string `json:"lan_cidr"`   // 管理网段 CIDR
}

func defaultGuard() guardProfile {
	return guardProfile{MgmtPorts: "22,888,18706,18081", LanCIDR: "192.168.58.0/24"}
}

func (g guardProfile) normalized() guardProfile {
	if strings.TrimSpace(g.MgmtPorts) == "" {
		g.MgmtPorts = defaultGuard().MgmtPorts
	}
	if strings.TrimSpace(g.LanCIDR) == "" {
		g.LanCIDR = defaultGuard().LanCIDR
	}
	return g
}

// isManaged 报告规则是否由地理围栏功能生成。
func isManaged(r *rules.Rule) bool {
	return strings.HasPrefix(r.Comment, markGuard) || strings.HasPrefix(r.Comment, markGeo)
}

func uint8ptr(v uint8) *uint8 { return &v }

// buildGuardRules 生成防锁死护栏规则。顺序即优先级（首个匹配生效）：
//  1. 已建立连接一律放行（避免打断现有 SSH / 后台会话）
//  2. loopback 放行
//  3. 管理端口放行（保证 SSH / 面板 / 后台始终可达）
//  4. 管理网段放行（保证局域网管理流量可达）
//
// 这些 ACCEPT 规则排在所有地理封锁 DROP 规则之前，因此无论封锁
// 规则多严格（含"仅放行某国"这种取反规则），管理通道都不会被误杀。
func buildGuardRules(g guardProfile) []*rules.Rule {
	g = g.normalized()
	out := make([]*rules.Rule, 0, 4)

	r1 := rules.NewRule(rules.ActionAccept)
	r1.State = "established"
	r1.Comment = markGuard + "allow established/related (keep admin sessions)"
	out = append(out, r1)

	r2 := rules.NewRule(rules.ActionAccept)
	r2.SrcIP = rules.ParseIPMatcher("127.0.0.0/8")
	r2.DstIP = rules.ParseIPMatcher("127.0.0.0/8")
	r2.Comment = markGuard + "allow loopback"
	out = append(out, r2)

	r3 := rules.NewRule(rules.ActionAccept)
	r3.Protocol = uint8ptr(6) // tcp
	r3.DstPort = rules.ParsePortSpec(g.MgmtPorts)
	r3.Direction = rules.DirIn
	r3.Comment = markGuard + "allow management ports " + g.MgmtPorts
	out = append(out, r3)

	r4 := rules.NewRule(rules.ActionAccept)
	r4.SrcIP = rules.ParseIPMatcher(g.LanCIDR)
	r4.Direction = rules.DirIn
	r4.Comment = markGuard + "allow LAN management " + g.LanCIDR
	out = append(out, r4)

	return out
}

// geoApplyRequest 一键预设请求。
type geoApplyRequest struct {
	Preset    string       `json:"preset"` // blacklist / whitelist / ports / clear
	Countries []string     `json:"countries"`
	Ports     string       `json:"ports"` // 仅作用于这些目的端口（preset=ports 或选填）
	Direction string       `json:"direction"`
	Guard     guardProfile `json:"guard"`
}

func (q geoApplyRequest) normalized() geoApplyRequest {
	q.Preset = strings.ToLower(strings.TrimSpace(q.Preset))
	codes := make([]string, 0, len(q.Countries))
	seen := make(map[string]bool)
	for _, c := range q.Countries {
		c = strings.ToUpper(strings.TrimSpace(c))
		if len(c) == 2 && !seen[c] {
			seen[c] = true
			codes = append(codes, c)
		}
	}
	sort.Strings(codes)
	q.Countries = codes
	q.Ports = strings.TrimSpace(q.Ports)
	if q.Direction == "" {
		q.Direction = rules.DirIn
	}
	q.Guard = q.Guard.normalized()
	return q
}

// handleGeofence
//
//	GET    /api/geofence            当前状态（库信息、已生效规则、护栏、后端模式）
//	POST   /api/geofence/apply      应用一键预设
//	POST   /api/geofence/clear      清空地理围栏（恢复原规则集）
//	DELETE /api/geofence            同 clear
func (s *Server) handleGeofence(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/geofence")
	switch {
	case r.Method == http.MethodGet && (path == "" || path == "/"):
		s.geoStatus(w)
	case r.Method == http.MethodPost && path == "/apply":
		s.geoApply(w, r)
	case (r.Method == http.MethodPost && path == "/clear") || r.Method == http.MethodDelete:
		s.geoClear(w)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) geoStatus(w http.ResponseWriter) {
	eng := s.engPtr.Load()
	rs := s.rsPtr.Load()

	total, v4, v6, _ := 0, 0, 0, []string{}
	var countries []map[string]interface{}
	if eng.GeoIP != nil {
		total, v4, v6, _ = eng.GeoIP.Stats()
		countries = eng.GeoIP.Countries()
	}

	var guards, fences []map[string]interface{}
	for i, rl := range rs.Rules {
		if !isManaged(rl) {
			continue
		}
		item := ruleToMap(rl)
		item["index"] = i
		if strings.HasPrefix(rl.Comment, markGuard) {
			guards = append(guards, item)
		} else {
			fences = append(fences, item)
		}
	}

	mode := "monitor"
	if s.backendCtl != nil {
		mode = s.backendCtl.Mode()
	} else if s.backend != "" {
		mode = s.backend
	}

	writeJSON(w, map[string]interface{}{
		"db": map[string]interface{}{
			"loaded":    eng.GeoIP != nil && eng.GeoIP.Loaded(),
			"count":     total,
			"v4":        v4,
			"v6":        v6,
			"countries": countries,
			"path":      s.geoPath,
			"source":    s.geoSource,
		},
		"mode":   mode,
		"guards": guards,
		"fences": fences,
		"active": len(fences) > 0,
	})
}

func (s *Server) geoApply(w http.ResponseWriter, r *http.Request) {
	var q geoApplyRequest
	if err := jsonDecode(r, &q); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	q = q.normalized()

	if q.Preset == "clear" {
		s.geoClear(w)
		return
	}
	// guard：只安装防锁死护栏、不生成任何 DROP 规则。
	// 这是切换内核真实丢包前的强制前置条件，也适合单独用来做「安全底線」。
	if q.Preset == "guard" {
		s.geoInstallGuard(w, q)
		return
	}
	if q.Preset != "blacklist" && q.Preset != "whitelist" && q.Preset != "ports" {
		writeError(w, http.StatusBadRequest, "preset must be blacklist / whitelist / ports / guard / clear")
		return
	}
	if len(q.Countries) == 0 {
		writeError(w, http.StatusBadRequest, "countries is required")
		return
	}
	if q.Preset == "ports" && q.Ports == "" {
		writeError(w, http.StatusBadRequest, "preset=ports 需要 ports 参数")
		return
	}

	eng := s.engPtr.Load()
	// 校验国家码存在于库，避免生成空集合导致取反规则误杀全网
	if eng.GeoIP == nil || !eng.GeoIP.Loaded() {
		writeError(w, http.StatusPreconditionFailed, "GeoIP 库未加载，无法应用地理围栏")
		return
	}
	known := make(map[string]bool)
	for _, c := range eng.GeoIP.Countries() {
		if code, ok := c["code"].(string); ok {
			known[code] = true
		}
	}
	for _, c := range q.Countries {
		if !known[c] {
			writeError(w, http.StatusBadRequest, "国家 "+c+" 不在当前 GeoIP 库中")
			return
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	newRS := s.cloneRuleset()
	// 先清除旧的托管规则，保证幂等
	kept := make([]*rules.Rule, 0, len(newRS.Rules))
	for _, rl := range newRS.Rules {
		if !isManaged(rl) {
			kept = append(kept, rl)
		}
	}

	// 构造地理封锁规则。
	// 顺序关键：规则是"首个匹配生效"，封锁规则必须排在原业务放行规则
	// （如 accept 80,443）之前，否则 whitelist / blacklist 会被抢先命中而失效。
	// 最终顺序 = 护栏 ACCEPT → 地理封锁 DROP → 原有业务规则。
	fence := rules.NewRule(rules.ActionDrop)
	fence.Direction = q.Direction
	switch q.Preset {
	case "blacklist":
		// allow:<codes> 命中列表国家 → drop（屏蔽这些国家）
		fence.GeoIP = rules.ParseGeoIPSpec("allow:" + strings.Join(q.Countries, ","))
		fence.Comment = markGeo + "blacklist " + strings.Join(q.Countries, ",")
	case "whitelist":
		// <codes> 为 deny 模式，命中"不属于列表国家" → drop（仅放行这些国家）
		fence.GeoIP = rules.ParseGeoIPSpec(strings.Join(q.Countries, ","))
		fence.Comment = markGeo + "whitelist only " + strings.Join(q.Countries, ",")
	case "ports":
		fence.GeoIP = rules.ParseGeoIPSpec("allow:" + strings.Join(q.Countries, ","))
		fence.Comment = markGeo + "ports " + q.Ports + " from " + strings.Join(q.Countries, ",")
	}
	if q.Ports != "" {
		fence.Protocol = uint8ptr(6) // tcp
		fence.DstPort = rules.ParsePortSpec(q.Ports)
	}

	// 护栏永远置顶（不可关闭），封锁紧随其后，最后是原有规则
	guard := buildGuardRules(q.Guard)
	merged := make([]*rules.Rule, 0, len(guard)+1+len(kept))
	merged = append(merged, guard...)
	merged = append(merged, fence)
	merged = append(merged, kept...)
	newRS.Rules = merged

	if err := s.commit(newRS); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.alog("geofence", "应用地理围栏预设 "+q.Preset, map[string]interface{}{"countries": q.Countries, "ports": q.Ports, "guards": len(guard), "rules": newRS.Len()})
	writeJSON(w, map[string]interface{}{
		"status": "applied", "preset": q.Preset,
		"countries": q.Countries, "ports": q.Ports,
		"guards": len(guard), "rules": newRS.Len(),
		"note": "防锁死护栏已强制前置；管理端口与 LAN 网段保持放行",
	})
}

// geoInstallGuard 只写 4 条护栏 ACCEPT、清除所有地理封锁规则，不影响任何业务流量。
// 切换内核后端前必须先执行它：否则白名单 / 黑名单可能把 SSH 与 18081 一起挡掉。
func (s *Server) geoInstallGuard(w http.ResponseWriter, q geoApplyRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	newRS := s.cloneRuleset()
	kept := make([]*rules.Rule, 0, len(newRS.Rules))
	for _, rl := range newRS.Rules {
		if !isManaged(rl) {
			kept = append(kept, rl)
		}
	}
	guard := buildGuardRules(q.Guard)
	merged := make([]*rules.Rule, 0, len(guard)+len(kept))
	merged = append(merged, guard...)
	merged = append(merged, kept...)
	newRS.Rules = merged
	if err := s.commit(newRS); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.alog("geofence", "安装防锁死护栏（无封锁规则）", map[string]interface{}{"guards": len(guard), "rules": newRS.Len()})
	writeJSON(w, map[string]interface{}{
		"status": "applied", "preset": "guard",
		"guards": len(guard), "rules": newRS.Len(),
		"note": "仅安装护栏，未生成任何 DROP；现在可以预检并切换内核后端",
	})
}

func (s *Server) geoClear(w http.ResponseWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	newRS := s.cloneRuleset()
	kept := make([]*rules.Rule, 0, len(newRS.Rules))
	for _, rl := range newRS.Rules {
		if !isManaged(rl) {
			kept = append(kept, rl)
		}
	}
	newRS.Rules = kept
	if err := s.commit(newRS); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.alog("geofence", "清空地理围栏，恢复原始规则集", map[string]interface{}{"rules": newRS.Len()})
	writeJSON(w, map[string]interface{}{"status": "cleared", "rules": newRS.Len()})
}

// ---- GeoIP 库：国家清单 / 命中统计 / 热加载 ----

func (s *Server) handleGeoCountries(w http.ResponseWriter, r *http.Request) {
	eng := s.engPtr.Load()
	if eng.GeoIP == nil || !eng.GeoIP.Loaded() {
		writeError(w, http.StatusPreconditionFailed, "GeoIP 库未加载")
		return
	}
	_, v4, v6, codes := eng.GeoIP.Stats()
	writeJSON(w, map[string]interface{}{
		"countries": eng.GeoIP.Countries(),
		"total":     eng.GeoIP.Count(),
		"v4":        v4, "v6": v6, "country_codes": codes,
		"path": s.geoPath, "source": s.geoSource,
	})
}

func (s *Server) handleGeoStats(w http.ResponseWriter, r *http.Request) {
	if s.geoCtl == nil {
		writeJSON(w, map[string]interface{}{"stats": []interface{}{}, "bans": []interface{}{}, "available": false})
		return
	}
	writeJSON(w, map[string]interface{}{
		"stats":     s.geoCtl.CountryStats(),
		"bans":      s.geoCtl.Bans(),
		"config":    s.geoCtl.GetConfig(),
		"available": true,
	})
}

func (s *Server) handleGeoReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.reloadGeo == nil {
		writeError(w, http.StatusNotImplemented, "GeoIP 热加载未启用（未配置文件路径）")
		return
	}
	n, err := s.reloadGeo()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reload failed: "+err.Error())
		return
	}
	s.alog("geoip", "手动热加载 GeoIP 库", map[string]interface{}{"entries": n})
	writeJSON(w, map[string]interface{}{"status": "reloaded", "count": n})
}

// ---- 临时封禁 ----

func (s *Server) handleBans(w http.ResponseWriter, r *http.Request) {
	if s.geoCtl == nil {
		writeError(w, http.StatusNotImplemented, "自动封禁未启用")
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, map[string]interface{}{
			"bans": s.geoCtl.Bans(), "config": s.geoCtl.GetConfig(),
		})
	case http.MethodPost:
		var body struct {
			Action  string         `json:"action"` // add / unban / config
			IP      string         `json:"ip"`
			TTL     int            `json:"ttl"`
			Config  *geoctl.Config `json:"config"`
			Country string         `json:"country"`
		}
		if err := jsonDecode(r, &body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		switch body.Action {
		case "add":
			b, err := s.geoCtl.BanManual(body.IP, body.Country, body.TTL)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			s.alog("ban", "手动封禁 "+body.IP, map[string]interface{}{"ttl": body.TTL, "country": body.Country})
			writeJSON(w, map[string]interface{}{"status": "banned", "ban": b})
		case "unban":
			ok := s.geoCtl.Unban(body.IP)
			s.alog("ban", "解封 "+body.IP, map[string]interface{}{"removed": ok})
			writeJSON(w, map[string]interface{}{"status": "ok", "removed": ok})
		case "config":
			if body.Config == nil {
				writeError(w, http.StatusBadRequest, "config is required")
				return
			}
			cfg := s.geoCtl.SetConfig(*body.Config)
			s.alog("ban", "更新自动封禁配置", map[string]interface{}{"enabled": cfg.Enabled, "threshold": cfg.Threshold})
			writeJSON(w, map[string]interface{}{"status": "ok", "config": cfg})
		default:
			writeError(w, http.StatusBadRequest, "action must be add / unban / config")
		}
	case http.MethodDelete:
		ip := strings.TrimPrefix(r.URL.Path, "/api/bans/")
		ok := s.geoCtl.Unban(ip)
		writeJSON(w, map[string]interface{}{"status": "ok", "removed": ok})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// jsonDecode 是 encoding/json 的薄封装，集中处理请求体解码。
func jsonDecode(r *http.Request, v interface{}) error {
	return json.NewDecoder(r.Body).Decode(v)
}
