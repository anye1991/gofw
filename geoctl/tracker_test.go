package geoctl

import (
	"net"
	"testing"
)

// 防锁死护栏：管理/内网/回环网段的 IP 绝不允许被手动封禁，
// 也不允许通过 IsBanned / 内核集合生效。这是切到内核模式前必须锁死的行为。
func TestBanManualRejectsSafeRanges(t *testing.T) {
	tr := New()

	publicIPs := []string{"203.0.113.9", "8.8.8.8", "2001:4860:4860::8888"}
	for _, ip := range publicIPs {
		if _, err := tr.BanManual(ip, "US", 60); err != nil {
			t.Fatalf("public IP %s should be bannable, got error: %v", ip, err)
		}
	}

	safeIPs := []string{
		"192.168.58.1", "192.168.58.128", // 管理网段
		"127.0.0.1", "::1",               // 回环
		"10.1.2.3", "172.16.5.9",         // RFC1918
		"169.254.1.1", "fe80::1",         // 链路本地
	}
	for _, ip := range safeIPs {
		if _, err := tr.BanManual(ip, "", 60); err == nil {
			t.Errorf("safe IP %s must be rejected by BanManual", ip)
		}
		if tr.IsBanned(net.ParseIP(ip)) {
			t.Errorf("safe IP %s must never be reported as banned", ip)
		}
	}
}

// 自定义 --ban-safe-cidr 追加的网段同样受保护。
func TestAddSafeCIDRProtectsManualBan(t *testing.T) {
	tr := New()
	if err := tr.AddSafeCIDR("100.64.0.0/10"); err != nil {
		t.Fatalf("AddSafeCIDR failed: %v", err)
	}
	if _, err := tr.BanManual("100.64.1.1", "", 60); err == nil {
		t.Error("IP in custom safe CIDR must be rejected")
	}
	if err := tr.AddSafeCIDR("not-a-cidr"); err == nil {
		t.Error("invalid CIDR should return an error")
	}
}

// 内核下发集合不能包含豁免地址；公网地址需按地址族正确拆分。
func TestActiveBansSplitSkipsSafe(t *testing.T) {
	tr := New()
	if _, err := tr.BanManual("203.0.113.9", "US", 0); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.BanManual("2001:db8::1", "JP", 0); err != nil {
		t.Fatal(err)
	}
	// 直接塞入一条豁免地址（模拟旧数据），验证集合层兜底过滤
	tr.mu.Lock()
	tr.bans["192.168.58.1"] = &Ban{IP: "192.168.58.1", Enforce: true}
	tr.mu.Unlock()

	v4, v6 := tr.ActiveBansSplit()
	for _, ip := range v4 {
		if net.ParseIP(ip).IsPrivate() || net.ParseIP(ip).IsLoopback() {
			t.Errorf("safe IP leaked into v4 ban set: %s", ip)
		}
	}
	if len(v4) != 1 || v4[0] != "203.0.113.9" {
		t.Errorf("unexpected v4 bans: %v", v4)
	}
	if len(v6) != 1 || v6[0] != "2001:db8::1" {
		t.Errorf("unexpected v6 bans: %v", v6)
	}
}

// 自动封禁同样不能触发在豁免网段上。
func TestObserveNeverAutoBansSafeIP(t *testing.T) {
	tr := New()
	tr.SetConfig(Config{Enabled: true, Threshold: 2, WindowSec: 10, BanSec: 300})
	for i := 0; i < 10; i++ {
		tr.Observe(net.ParseIP("192.168.58.1"), "??", "drop", true)
		tr.Observe(net.ParseIP("127.0.0.1"), "??", "drop", true)
	}
	if len(tr.Bans()) != 0 {
		t.Errorf("safe IPs must never be auto-banned, got: %+v", tr.Bans())
	}
	for i := 0; i < 3; i++ {
		tr.Observe(net.ParseIP("203.0.113.77"), "US", "drop", true)
	}
	if !tr.IsBanned(net.ParseIP("203.0.113.77")) {
		t.Error("public IP exceeding threshold should be auto-banned")
	}
}
