// VRRP 协议报文编解码与状态机单元测试。
package ha

import (
	"encoding/binary"
	"net"
	"testing"
)

// TestIPChecksum 验证 RFC 1071 校验和计算。
func TestIPChecksum(t *testing.T) {
	// 空数据校验和应为 0xffff（对 0 取反）
	if got := ipChecksum(nil); got != 0xffff {
		t.Errorf("空数据校验和=%04x, 期望 ffff", got)
	}

	// 全 0 数据校验和为 0xffff
	if got := ipChecksum(make([]byte, 8)); got != 0xffff {
		t.Errorf("全零数据校验和=%04x, 期望 ffff", got)
	}

	// 已知数据校验和验证：标准 IP 头校验和示例
	// 构造一个简单的 VRRP 报文（校验和字段先置 0）
	data := []byte{
		0x21, 0x01, 0x64, 0x01, // ver=2,type=1; vrid=1; prio=100; count=1
		0x00, 0x01, // auth=0, advert=1
		0x00, 0x00, // checksum 占位
		10, 0, 0, 1, // VIP 10.0.0.1
	}
	cs := ipChecksum(data)
	// 将校验和写回后，整个报文的校验和应为 0（自校验）
	binary.BigEndian.PutUint16(data[6:8], cs)
	if verify := ipChecksum(data); verify != 0 {
		t.Errorf("校验和自验证失败: 计算=%04x, 写入后全报文校验和=%04x (期望 0)", cs, verify)
	}
}

// TestVRRPMarshalParseRoundTrip 验证 VRRP 报文的序列化/反序列化往返。
func TestVRRPMarshalParseRoundTrip(t *testing.T) {
	cases := []struct {
		name     string
		pkt      *vrrpPacket
		wantVRID uint8
		wantPrio uint8
		wantCnt  uint8
		wantInt  uint8
		wantVIPs []string
	}{
		{
			name: "单 VIP",
			pkt: &vrrpPacket{
				VRID:         1,
				Priority:     100,
				CountIPAddrs: 1,
				AdvertInt:    1,
				IPAddrs:      []net.IP{net.ParseIP("10.0.0.1")},
			},
			wantVRID: 1,
			wantPrio: 100,
			wantCnt:  1,
			wantInt:  1,
			wantVIPs: []string{"10.0.0.1"},
		},
		{
			name: "多 VIP",
			pkt: &vrrpPacket{
				VRID:         50,
				Priority:     200,
				CountIPAddrs: 3,
				AdvertInt:    2,
				IPAddrs: []net.IP{
					net.ParseIP("192.168.1.1"),
					net.ParseIP("192.168.1.2"),
					net.ParseIP("172.16.0.1"),
				},
			},
			wantVRID: 50,
			wantPrio: 200,
			wantCnt:  3,
			wantInt:  2,
			wantVIPs: []string{"192.168.1.1", "192.168.1.2", "172.16.0.1"},
		},
		{
			name: "无 VIP（count=0）",
			pkt: &vrrpPacket{
				VRID:         255,
				Priority:     255,
				CountIPAddrs: 0,
				AdvertInt:    1,
				IPAddrs:      nil,
			},
			wantVRID: 255,
			wantPrio: 255,
			wantCnt:  0,
			wantInt:  1,
			wantVIPs: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			data := c.pkt.marshal()

			// 验证报文头固定字段
			ver := data[0] >> 4
			typ := data[0] & 0x0f
			if ver != 2 || typ != 1 {
				t.Errorf("version/type=%d/%d, 期望 2/1", ver, typ)
			}

			// 反序列化
			parsed, err := parseVRRP(data)
			if err != nil {
				t.Fatalf("parseVRRP 失败: %v", err)
			}
			if parsed.VRID != c.wantVRID {
				t.Errorf("VRID=%d, 期望 %d", parsed.VRID, c.wantVRID)
			}
			if parsed.Priority != c.wantPrio {
				t.Errorf("Priority=%d, 期望 %d", parsed.Priority, c.wantPrio)
			}
			if parsed.CountIPAddrs != c.wantCnt {
				t.Errorf("CountIPAddrs=%d, 期望 %d", parsed.CountIPAddrs, c.wantCnt)
			}
			if parsed.AdvertInt != c.wantInt {
				t.Errorf("AdvertInt=%d, 期望 %d", parsed.AdvertInt, c.wantInt)
			}
			if len(parsed.IPAddrs) != len(c.wantVIPs) {
				t.Fatalf("VIP 数量=%d, 期望 %d", len(parsed.IPAddrs), len(c.wantVIPs))
			}
			for i, vip := range parsed.IPAddrs {
				if !vip.Equal(net.ParseIP(c.wantVIPs[i])) {
					t.Errorf("VIP[%d]=%s, 期望 %s", i, vip, c.wantVIPs[i])
				}
			}
			// 校验和应正确（parseVRRP 已验证）
			if parsed.Checksum == 0 {
				t.Error("校验和不应为 0")
			}
		})
	}
}

// TestParseVRRPErrors 验证解析错误场景。
func TestParseVRRPErrors(t *testing.T) {
	// 报文过短
	if _, err := parseVRRP([]byte{0x21, 0x01}); err == nil {
		t.Error("短报文应返回错误")
	}

	// 错误的 version/type
	badVer := make([]byte, 8)
	badVer[0] = (3 << 4) | 1 // version=3
	if _, err := parseVRRP(badVer); err == nil {
		t.Error("错误 version 应返回错误")
	}
	badVer[0] = (2 << 4) | 2 // type=2
	if _, err := parseVRRP(badVer); err == nil {
		t.Error("错误 type 应返回错误")
	}

	// CountIPAddrs 声明 1 但报文被截断
	truncated := []byte{0x21, 0x01, 0x64, 0x01, 0x00, 0x01, 0x00, 0x00}
	// 只给了 8 字节，count=1 需要 12 字节
	if _, err := parseVRRP(truncated); err == nil {
		t.Error("截断报文应返回错误")
	}

	// 校验和错误（构造合法报文后篡改校验和）
	valid := (&vrrpPacket{VRID: 1, Priority: 100, CountIPAddrs: 1, AdvertInt: 1,
		IPAddrs: []net.IP{net.ParseIP("10.0.0.1")}}).marshal()
	binary.BigEndian.PutUint16(valid[6:8], 0x1234) // 篡改校验和
	if _, err := parseVRRP(valid); err == nil {
		t.Error("校验和错误应返回错误")
	}
}

// TestVRRPPriorityZero 验证 priority=0 报文（Master 释放）正确解析。
func TestVRRPPriorityZero(t *testing.T) {
	pkt := &vrrpPacket{
		VRID:         1,
		Priority:     0, // Master 主动释放
		CountIPAddrs: 1,
		AdvertInt:    1,
		IPAddrs:      []net.IP{net.ParseIP("10.0.0.1")},
	}
	data := pkt.marshal()
	parsed, err := parseVRRP(data)
	if err != nil {
		t.Fatalf("解析 priority=0 报文失败: %v", err)
	}
	if parsed.Priority != 0 {
		t.Errorf("Priority=%d, 期望 0", parsed.Priority)
	}
}

// TestBytesGreater 验证 IPv4 地址比较。
func TestBytesGreater(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"10.0.0.2", "10.0.0.1", true},
		{"10.0.0.1", "10.0.0.2", false},
		{"192.168.1.1", "10.0.0.1", true},
		{"10.0.0.1", "10.0.0.1", false}, // 相等
		{"0.0.0.0", "255.255.255.255", false},
	}
	for _, c := range cases {
		got := bytesGreater(net.ParseIP(c.a), net.ParseIP(c.b))
		if got != c.want {
			t.Errorf("bytesGreater(%s, %s)=%v, 期望 %v", c.a, c.b, got, c.want)
		}
	}
}

// TestVRRPStateMachine 验证 VRRP 配置解析与初始状态。
func TestVRRPStateMachine(t *testing.T) {
	// VRRP 配置（VRID>0 启用 VRRP）
	cfg := &Config{
		Enabled:   true,
		Mode:      "backup",
		VRID:      1,
		Priority:  100,
		AdvertInt: 1,
		VIP:       "10.0.0.1",
		Interface: "eth0",
	}
	m := NewManager(cfg)
	if m.State() != StateBackup {
		t.Errorf("初始状态=%s, 期望 BACKUP", m.State())
	}
	if m.cfg.VRID != 1 || m.cfg.Priority != 100 {
		t.Errorf("VRID=%d Priority=%d, 期望 1/100", m.cfg.VRID, m.cfg.Priority)
	}

	// Priority=255 的配置（VIP 拥有者）
	cfgOwner := &Config{
		Enabled:  true,
		Mode:     "backup",
		VRID:     1,
		Priority: 255,
	}
	if cfgOwner.Priority != 255 {
		t.Errorf("owner Priority=%d, 期望 255", cfgOwner.Priority)
	}

	// 测试 PromoteForTest
	m2 := NewManager(&Config{Enabled: true, Mode: "backup", VIP: "", Interface: ""})
	promoted := make(chan struct{}, 1)
	m2.SetCallbacks(func() { promoted <- struct{}{} }, nil)
	m2.PromoteForTest()
	if m2.State() != StateMaster {
		t.Errorf("PromoteForTest 后状态=%s, 期望 MASTER", m2.State())
	}
	select {
	case <-promoted:
	default:
		t.Error("onPromote 回调未触发")
	}
}
