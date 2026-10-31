// Web UI 规则 CRUD API 端到端测试。
package webui_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"gofw/config"
	"gofw/engine"
	"gofw/rules"
	"gofw/webui"
)

// freePort 获取一个空闲端口。
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("获取空闲端口失败: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

// startServer 启动 webui 服务器并返回 base URL。
func startServer(t *testing.T, rulesFile string) (string, func()) {
	t.Helper()
	rs, err := config.Load(rulesFile)
	if err != nil {
		t.Fatalf("加载规则失败: %v", err)
	}
	var engPtr atomic.Pointer[engine.Engine]
	var rsPtr atomic.Pointer[rules.RuleSet]
	engPtr.Store(engine.NewEngine(rs))
	rsPtr.Store(rs)

	apply := func(newRS *rules.RuleSet) {
		engPtr.Load().SetRuleset(newRS)
		rsPtr.Store(newRS)
	}
	addr := freePort(t)
	srv := webui.New(&engPtr, &rsPtr, addr, rulesFile, apply)
	go func() {
		_ = srv.Start()
	}()
	// 等待服务器就绪
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	return "http://" + addr, func() {}
}

// httpReq 发起 HTTP 请求并返回状态码和响应体。
func httpReq(t *testing.T, method, url, body string) (int, string) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = bytes.NewBufferString(body)
	}
	req, err := http.NewRequest(method, url, r)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// ruleCount 从 GET /api/rules 响应中解析规则数量。
func ruleCount(t *testing.T, body string) int {
	t.Helper()
	var out struct {
		Rules []map[string]interface{} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("解析规则列表失败: %v, body=%s", err, body)
	}
	return len(out.Rules)
}

// TestRuleCRUD 测试规则的增删改查完整流程。
func TestRuleCRUD(t *testing.T) {
	// 准备临时规则文件
	tmp, err := os.CreateTemp("", "rules_*.yaml")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString("default: drop\nrules:\n  - action: accept\n    protocol: tcp\n    dst_port: 80\n    comment: http\n"); err != nil {
		t.Fatalf("写入临时规则失败: %v", err)
	}
	tmp.Close()

	base, cleanup := startServer(t, tmp.Name())
	defer cleanup()

	// 1. GET 初始列表 - 应有 1 条规则
	code, body := httpReq(t, http.MethodGet, base+"/api/rules", "")
	if code != http.StatusOK {
		t.Fatalf("GET /api/rules 状态码=%d, 期望 200, body=%s", code, body)
	}
	if n := ruleCount(t, body); n != 1 {
		t.Fatalf("初始规则数=%d, 期望 1", n)
	}
	t.Logf("初始规则列表: %s", body)

	// 2. POST 新增规则
	newRule := `{"action":"drop","protocol":"tcp","dst_port":3306,"app_proto":"mysql","comment":"block mysql"}`
	code, body = httpReq(t, http.MethodPost, base+"/api/rules", newRule)
	if code != http.StatusOK {
		t.Fatalf("POST 新增规则状态码=%d, 期望 200, body=%s", code, body)
	}
	var addResp struct {
		Status string `json:"status"`
		Index  int    `json:"index"`
	}
	if err := json.Unmarshal([]byte(body), &addResp); err != nil {
		t.Fatalf("解析 POST 响应失败: %v", err)
	}
	if addResp.Status != "added" || addResp.Index != 1 {
		t.Errorf("POST 响应 status=%q index=%d, 期望 added/1", addResp.Status, addResp.Index)
	}
	t.Logf("POST 新增响应: %s", body)

	// 3. GET 确认新增后有 2 条规则
	code, body = httpReq(t, http.MethodGet, base+"/api/rules", "")
	if code != http.StatusOK {
		t.Fatalf("GET 确认状态码=%d", code)
	}
	if n := ruleCount(t, body); n != 2 {
		t.Fatalf("新增后规则数=%d, 期望 2", n)
	}

	// 4. PUT 更新 index=1 的规则
	updateRule := `{"action":"reject","protocol":"tcp","dst_port":3306,"comment":"reject mysql"}`
	code, body = httpReq(t, http.MethodPut, base+"/api/rules/1", updateRule)
	if code != http.StatusOK {
		t.Fatalf("PUT 更新状态码=%d, 期望 200, body=%s", code, body)
	}
	var updResp struct {
		Status string `json:"status"`
		Index  int    `json:"index"`
	}
	if err := json.Unmarshal([]byte(body), &updResp); err != nil {
		t.Fatalf("解析 PUT 响应失败: %v", err)
	}
	if updResp.Status != "updated" || updResp.Index != 1 {
		t.Errorf("PUT 响应 status=%q index=%d, 期望 updated/1", updResp.Status, updResp.Index)
	}

	// 5. GET 确认更新后的动作
	code, body = httpReq(t, http.MethodGet, base+"/api/rules", "")
	var listResp struct {
		Rules []map[string]interface{} `json:"rules"`
	}
	json.Unmarshal([]byte(body), &listResp)
	if listResp.Rules[1]["action"] != "REJECT" {
		t.Errorf("更新后规则1动作=%v, 期望 REJECT", listResp.Rules[1]["action"])
	}
	t.Logf("更新后规则列表: %s", body)

	// 6. DELETE 删除 index=1 的规则
	code, body = httpReq(t, http.MethodDelete, base+"/api/rules/1", "")
	if code != http.StatusOK {
		t.Fatalf("DELETE 状态码=%d, 期望 200, body=%s", code, body)
	}
	var delResp struct {
		Status string `json:"status"`
		Index  int    `json:"index"`
	}
	if err := json.Unmarshal([]byte(body), &delResp); err != nil {
		t.Fatalf("解析 DELETE 响应失败: %v", err)
	}
	if delResp.Status != "deleted" || delResp.Index != 1 {
		t.Errorf("DELETE 响应 status=%q index=%d, 期望 deleted/1", delResp.Status, delResp.Index)
	}

	// 7. GET 确认删除后剩 1 条规则
	code, body = httpReq(t, http.MethodGet, base+"/api/rules", "")
	if n := ruleCount(t, body); n != 1 {
		t.Fatalf("删除后规则数=%d, 期望 1", n)
	}

	// 8. DELETE 非法索引应返回 404
	code, body = httpReq(t, http.MethodDelete, base+"/api/rules/999", "")
	if code != http.StatusNotFound {
		t.Errorf("DELETE 非法索引状态码=%d, 期望 404, body=%s", code, body)
	}

	// 9. PUT 非法索引应返回 404
	code, body = httpReq(t, http.MethodPut, base+"/api/rules/999", `{"action":"drop"}`)
	if code != http.StatusNotFound {
		t.Errorf("PUT 非法索引状态码=%d, 期望 404, body=%s", code, body)
	}

	// 10. POST 非法 JSON 应返回 400
	code, body = httpReq(t, http.MethodPost, base+"/api/rules", `{"action":"INVALID_ACTION"}`)
	if code != http.StatusBadRequest {
		t.Errorf("POST 非法动作状态码=%d, 期望 400, body=%s", code, body)
	}

	t.Log("所有 CRUD 测试通过")
}

// TestRulePersistence 验证规则修改后持久化到文件。
func TestRulePersistence(t *testing.T) {
	tmp, err := os.CreateTemp("", "rules_*.yaml")
	if err != nil {
		t.Fatalf("创建临时文件失败: %v", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString("default: drop\nrules:\n  - action: accept\n    protocol: tcp\n    dst_port: 80\n"); err != nil {
		t.Fatalf("写入临时规则失败: %v", err)
	}
	tmp.Close()

	base, cleanup := startServer(t, tmp.Name())
	defer cleanup()

	// 新增一条规则
	httpReq(t, http.MethodPost, base+"/api/rules",
		`{"action":"drop","protocol":"udp","dst_port":53,"comment":"block dns"}`)

	// 重新从文件加载，确认持久化
	rs, err := config.Load(tmp.Name())
	if err != nil {
		t.Fatalf("重新加载规则文件失败: %v", err)
	}
	if rs.Len() != 2 {
		t.Fatalf("持久化后规则数=%d, 期望 2", rs.Len())
	}
	if rs.Rules[1].DstPort == nil || !rs.Rules[1].DstPort.Matches(53) {
		t.Errorf("持久化的规则1端口不匹配 53")
	}
	t.Logf("持久化验证通过, 文件内容:\n%s", mustRead(tmp.Name()))
}

func mustRead(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return err.Error()
	}
	return string(b)
}
