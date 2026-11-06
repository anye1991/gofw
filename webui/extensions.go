package webui

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gofw/audit"
	"gofw/config"
)

// BackendController 由 enforce.Switchable 实现，webui 只依赖这个窄接口，避免包循环。
type BackendController interface {
	Mode() string
	Preflight() (ok bool, detail string)
	SwitchTo(mode string) error
	ArmRollback(d time.Duration)
	Confirm()
	RollbackRemaining() int
}

// SetExtensions 注入系统增强依赖（均由 main.go 装配，可缺省）。
func (s *Server) SetExtensions(log *audit.Logger, ctl BackendController, syncSecret, authFile string) {
	s.auditLog = log
	s.backendCtl = ctl
	s.syncSecret = strings.TrimSpace(syncSecret)
	s.authFile = strings.TrimSpace(authFile)
	if s.authFile != "" && s.currentPassword() == "" {
		if b, err := os.ReadFile(s.authFile); err == nil {
			if p := strings.TrimSpace(string(b)); p != "" {
				s.setPassword(p)
			}
		}
	}
}

func (s *Server) authSource() string {
	if os.Getenv("GOFW_WEB_PASSWORD") != "" {
		return "env"
	}
	if s.authFile != "" {
		if _, err := os.Stat(s.authFile); err == nil {
			return "file"
		}
	}
	return "none"
}

// ---- 运行时执行后端切换 ----

func (s *Server) handleBackend(w http.ResponseWriter, r *http.Request) {
	if s.backendCtl == nil {
		writeJSON(w, map[string]interface{}{
			"available": false, "mode": s.backend,
			"note": "运行时切换未装配（单后端模式），需升级到支持 Switchable 的二进制",
		})
		return
	}
	guards := 0
	if rs := s.rsPtr.Load(); rs != nil {
		for _, rl := range rs.Rules {
			if strings.HasPrefix(rl.Comment, markGuard) {
				guards++
			}
		}
	}
	writeJSON(w, map[string]interface{}{
		"available":          true,
		"mode":               s.backendCtl.Mode(),
		"guards":             guards,
		"rollback_remaining": s.backendCtl.RollbackRemaining(),
		"rules":              s.rsPtr.Load().Len(),
		"note":               "点「预检」才会执行 nft 语法 / 权限校验，避免轮询时反复构造大脚本",
	})
}

func (s *Server) handleBackendAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if s.backendCtl == nil {
		writeError(w, http.StatusNotImplemented, "运行时切换未装配")
		return
	}
	action := strings.TrimPrefix(r.URL.Path, "/api/backend/")

	switch action {
	case "preflight":
		ok, detail := s.backendCtl.Preflight()
		writeJSON(w, map[string]interface{}{"ok": ok, "detail": detail})
		return
	case "confirm":
		s.backendCtl.Confirm()
		s.alog("backend", "确认保留内核模式，取消自动回滚", map[string]interface{}{"mode": "kernel"})
		writeJSON(w, map[string]interface{}{"status": "confirmed", "mode": s.backendCtl.Mode()})
		return
	case "rollback":
		if err := s.backendCtl.SwitchTo("monitor"); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.backendCtl.Confirm()
		s.alog("backend", "手动回滚到监控模式", nil)
		writeJSON(w, map[string]interface{}{"status": "rolled_back", "mode": "monitor"})
		return
	case "switch":
		var body struct {
			Mode    string `json:"mode"`
			Confirm bool   `json:"confirm"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		body.Mode = strings.ToLower(strings.TrimSpace(body.Mode))
		if body.Mode != "kernel" && body.Mode != "monitor" {
			writeError(w, http.StatusBadRequest, "mode must be kernel / monitor")
			return
		}
		// 二次确认：切到真实丢包必须显式确认，避免误点。
		if body.Mode == "kernel" && !body.Confirm {
			writeError(w, http.StatusPreconditionFailed, "切换到内核真实丢包需要二次确认（confirm=true）")
			return
		}
		if err := s.backendCtl.SwitchTo(body.Mode); err != nil {
			s.alog("backend", "切换失败："+err.Error(), map[string]interface{}{"target": body.Mode})
			writeError(w, http.StatusPreconditionFailed, err.Error())
			return
		}
		if body.Mode == "kernel" {
			s.backendCtl.ArmRollback(30 * time.Second)
			s.alog("backend", "切换到 nftables 内核真实丢包，30 秒自动回滚保护已启动", nil)
		} else {
			s.backendCtl.Confirm()
			s.alog("backend", "切换到旁路监控，内核规则已清除", nil)
		}
		writeJSON(w, map[string]interface{}{
			"status": "switched", "mode": s.backendCtl.Mode(),
			"rollback_remaining": s.backendCtl.RollbackRemaining(),
		})
		return
	default:
		writeError(w, http.StatusNotFound, "unknown action")
	}
}

// ---- 审计日志 ----

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if s.auditLog == nil {
		writeJSON(w, map[string]interface{}{"enabled": false, "entries": []interface{}{}, "note": "审计日志未启用"})
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	entries, err := s.auditLog.Query(limit, r.URL.Query().Get("kind"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, map[string]interface{}{
		"enabled": true, "path": s.auditLog.Path(),
		"entries": entries, "count": len(entries),
	})
}

// ---- Web 登录保护 ----

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	src := s.authSource()
	if r.Method == http.MethodGet {
		writeJSON(w, map[string]interface{}{
			"enabled":    s.currentPassword() != "",
			"source":     src,
			"env_locked": src == "env",
			"note":       "未启用时任何能访问 Web 端口的人都能修改规则；启用后 /api/* 需会话 cookie",
			"session_count": func() int {
				s.sessMu.Lock()
				defer s.sessMu.Unlock()
				return len(s.sessions)
			}(),
		})
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		Action   string `json:"action"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}

	switch body.Action {
	case "enable":
		if s.currentPassword() != "" {
			writeError(w, http.StatusConflict, "登录保护已启用")
			return
		}
		pw := strings.TrimSpace(body.Password)
		if pw == "" {
			pw = randHex(10) // 20 位随机十六进制，只展示这一次
		}
		if len(pw) < 8 {
			writeError(w, http.StatusBadRequest, "密码至少 8 位")
			return
		}
		if err := s.persistPassword(pw); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.setPassword(pw)
		// 给本次操作者直接建立会话，否则启用后当前页面所有 API 立刻 401。
		s.issueSession(w)
		s.alog("auth", "启用 Web 登录保护", map[string]interface{}{"source": "file"})
		writeJSON(w, map[string]interface{}{
			"status": "enabled", "password": pw,
			"note": "请立刻保存该密码：仅本次返回，之后需用它登录。忘记时可删除服务器上的 web 密码文件后重启。",
		})
	case "password":
		if s.currentPassword() == "" {
			writeError(w, http.StatusPreconditionFailed, "请先启用登录保护")
			return
		}
		if len(strings.TrimSpace(body.Password)) < 8 {
			writeError(w, http.StatusBadRequest, "密码至少 8 位")
			return
		}
		if err := s.persistPassword(body.Password); err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.setPassword(body.Password)
		// 旧会话全部失效，但给当前操作者发新 cookie，避免把自己锁在页面外。
		s.sessMu.Lock()
		s.sessions = make(map[string]int64)
		s.sessMu.Unlock()
		s.issueSession(w)
		s.alog("auth", "修改 Web 登录密码，旧会话全部失效", nil)
		writeJSON(w, map[string]interface{}{"status": "changed"})
	case "disable":
		if s.currentPassword() == "" {
			writeJSON(w, map[string]interface{}{"status": "already_disabled"})
			return
		}
		if src == "env" {
			writeError(w, http.StatusConflict, "密码由环境变量 GOFW_WEB_PASSWORD 提供，请在 systemd 单元里移除后重启，不能在线停用")
			return
		}
		if s.authFile != "" {
			os.Remove(s.authFile)
		}
		s.setPassword("")
		s.alog("auth", "停用 Web 登录保护", nil)
		writeJSON(w, map[string]interface{}{"status": "disabled"})
	default:
		writeError(w, http.StatusBadRequest, "action must be enable / password / disable")
	}
}

// issueSession 给当前响应写入一个新的登录会话 cookie。
func (s *Server) issueSession(w http.ResponseWriter) {
	sid := randHex(32)
	s.sessMu.Lock()
	s.sessions[sid] = time.Now().Add(sessionTTL).Unix()
	s.sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: "gofw_sid", Value: sid, Path: "/", HttpOnly: true,
		MaxAge: int(sessionTTL.Seconds()), SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) persistPassword(pw string) error {
	if s.authFile == "" {
		return fmt.Errorf("未配置密码持久化文件")
	}
	if err := os.MkdirAll(filepath.Dir(s.authFile), 0755); err != nil {
		return err
	}
	return os.WriteFile(s.authFile, []byte(strings.TrimSpace(pw)), 0600)
}

// ---- 多机策略同步（HMAC-SHA256 签名） ----

func syncSign(secret, payload string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Server) exportBundle() map[string]interface{} {
	if s.syncSecret == "" {
		return map[string]interface{}{
			"enabled": false,
			"note":    "未配置 --sync-secret（或 GOFW_SYNC_SECRET），策略同步已禁用",
		}
	}
	data, err := os.ReadFile(s.rulesFile)
	if err != nil {
		return map[string]interface{}{"enabled": true, "error": err.Error()}
	}
	yaml := string(data)
	return map[string]interface{}{
		"enabled": true,
		"version": time.Now().UnixNano(),
		"rules":   s.rsPtr.Load().Len(),
		"yaml":    yaml,
		"sig":     syncSign(s.syncSecret, yaml),
		"note":    "把整包复制到对端「导入策略包」；签名校验通过才会应用",
	}
}

func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, s.exportBundle())
	case http.MethodPost:
		var body struct {
			Action string `json:"action"`
			YAML   string `json:"yaml"`
			Sig    string `json:"sig"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json")
			return
		}
		if strings.TrimSpace(body.Action) == "export" {
			writeJSON(w, s.exportBundle())
			return
		}
		if s.syncSecret == "" {
			writeError(w, http.StatusPreconditionFailed, "策略同步未配置密钥，无法导入")
			return
		}
		if body.YAML == "" || body.Sig == "" {
			writeError(w, http.StatusBadRequest, "yaml 与 sig 都是必需的")
			return
		}
		want := syncSign(s.syncSecret, body.YAML)
		if subtle.ConstantTimeCompare([]byte(want), []byte(strings.TrimSpace(body.Sig))) != 1 {
			s.alog("sync", "拒绝导入：签名校验失败", nil)
			writeError(w, http.StatusForbidden, "签名校验失败：策略包被篡改或两端密钥不一致")
			return
		}
		newRS, err := config.LoadFromData([]byte(body.YAML))
		if err != nil {
			writeError(w, http.StatusBadRequest, "策略包解析失败: "+err.Error())
			return
		}
		s.mu.Lock()
		err = s.commit(newRS)
		s.mu.Unlock()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.alog("sync", "导入对端策略包并热应用", map[string]interface{}{"rules": newRS.Len()})
		writeJSON(w, map[string]interface{}{"status": "applied", "rules": newRS.Len()})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// ---- GeoIP 精度与归属查询 ----

func (s *Server) handleGeoMeta(w http.ResponseWriter, r *http.Request) {
	eng := s.engPtr.Load()
	if eng.GeoIP == nil {
		writeJSON(w, map[string]interface{}{"loaded": false, "has_meta": false})
		return
	}
	cities, asns, loaded := eng.GeoIP.MetaSummary()
	level := "country"
	if cities > 0 || asns > 0 {
		level = "city/asn"
	}
	writeJSON(w, map[string]interface{}{
		"loaded": loaded, "has_meta": cities > 0 || asns > 0,
		"level": level, "cities": cities, "asns": asns,
		"format": "CIDR,country[,city[,asn]] — 两列库只有国家码；三/四列库才会带出城市与 ASN",
		"note":   "当前线上为 DBIP Country Lite（国家/地区级）。城市 / ASN 规则字段已可用，但需要导入带扩展列的库才会命中，不会臆造精度。",
	})
}

func (s *Server) handleGeoLookup(w http.ResponseWriter, r *http.Request) {
	eng := s.engPtr.Load()
	if eng.GeoIP == nil || !eng.GeoIP.Loaded() {
		writeError(w, http.StatusPreconditionFailed, "GeoIP 库未加载")
		return
	}
	ip := net.ParseIP(strings.TrimSpace(r.URL.Query().Get("ip")))
	if ip == nil {
		writeError(w, http.StatusBadRequest, "invalid ip")
		return
	}
	country, city, asn := eng.GeoIP.LookupFull(ip)
	writeJSON(w, map[string]interface{}{
		"ip": ip.String(), "country": country, "city": city, "asn": asn,
		"precision": func() string {
			if city != "" || asn != "" {
				return "city/asn"
			}
			return "country"
		}(),
	})
}
