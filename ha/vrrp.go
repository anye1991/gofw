// Package ha VRRPv2 协议实现（RFC 3768）。
// 基于 IP 协议号 112，组播地址 224.0.0.18，TTL 必须为 255。
package ha

import (
	"encoding/binary"
	"errors"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
)

// VRRP 常量。
const (
	vrrpVersion   = 2
	vrrpTypeAdv   = 1 // Advertisement
	vrrpProtoNum  = 112
	vrrpMulticast = "224.0.0.18"
	vrrpTTL       = 255
	vrrpAuthNone  = 0
)

// vrrpPacket VRRP 通告报文。
type vrrpPacket struct {
	VersionType  uint8    // 高 4 位 version，低 4 位 type
	VRID         uint8    // 虚拟路由器 ID (1-255)
	Priority     uint8    // 优先级 (0-255)
	CountIPAddrs uint8    // VIP 数量
	AuthType     uint8    // 认证类型 (0=无)
	AdvertInt    uint8    // 通告间隔（秒）
	Checksum     uint16   // 校验和
	IPAddrs      []net.IP // VIP 列表
}

// marshal 序列化为 VRRP 报文（含校验和计算）。
func (p *vrrpPacket) marshal() []byte {
	n := 8 + len(p.IPAddrs)*4
	buf := make([]byte, n)
	buf[0] = (vrrpVersion << 4) | vrrpTypeAdv
	buf[1] = p.VRID
	buf[2] = p.Priority
	buf[3] = byte(len(p.IPAddrs))
	buf[4] = vrrpAuthNone
	buf[5] = p.AdvertInt
	// checksum 先置 0
	buf[6] = 0
	buf[7] = 0
	for i, ip := range p.IPAddrs {
		copy(buf[8+i*4:], ip.To4())
	}
	p.Checksum = ipChecksum(buf)
	binary.BigEndian.PutUint16(buf[6:8], p.Checksum)
	return buf
}

// parseVRRP 从 IP payload 解析 VRRP 报文。
func parseVRRP(data []byte) (*vrrpPacket, error) {
	if len(data) < 8 {
		return nil, errors.New("vrrp packet too short")
	}
	ver := data[0] >> 4
	typ := data[0] & 0x0f
	if ver != vrrpVersion || typ != vrrpTypeAdv {
		return nil, errors.New("not a VRRPv2 advertisement")
	}
	p := &vrrpPacket{
		VersionType:  data[0],
		VRID:         data[1],
		Priority:     data[2],
		CountIPAddrs: data[3],
		AuthType:     data[4],
		AdvertInt:    data[5],
		Checksum:     binary.BigEndian.Uint16(data[6:8]),
	}
	addrLen := int(p.CountIPAddrs) * 4
	if len(data) < 8+addrLen {
		return nil, errors.New("vrrp packet truncated")
	}
	for i := 0; i < int(p.CountIPAddrs); i++ {
		p.IPAddrs = append(p.IPAddrs, net.IP(data[8+i*4:8+i*4+4]).To4())
	}
	// 校验和验证（可选，失败仅记录不丢弃，避免误判）
	saved := p.Checksum
	data[6], data[7] = 0, 0
	calc := ipChecksum(data)
	data[6], data[7] = byte(saved>>8), byte(saved)
	if calc != saved {
		return p, errors.New("vrrp checksum mismatch")
	}
	return p, nil
}

// ipChecksum 计算 IP 校验和（RFC 1071）。
func ipChecksum(data []byte) uint16 {
	var sum uint32
	n := len(data)
	for i := 0; i+1 < n; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if n%2 == 1 {
		sum += uint32(data[n-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// vrrpConn VRRP 原始套接字连接。
type vrrpConn struct {
	conn    net.PacketConn
	ifaceIP net.IP // 本地发送接口 IP
}

// newVRRPConn 创建 VRRP 套接字。iface 用于绑定接收接口；localIP 为发送源 IP。
func newVRRPConn(ifaceName, localIP string) (*vrrpConn, error) {
	conn, err := net.ListenPacket("ip4:112", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	// 设置 TTL=255（VRRP 要求）
	if rawConn, ok := conn.(*net.IPConn); ok {
		if sc, err := rawConn.SyscallConn(); err == nil {
			sc.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, vrrpTTL)
				syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_TTL, vrrpTTL)
				// 绑定到指定接口接收组播
				if ifaceName != "" {
					if ifi, err := net.InterfaceByName(ifaceName); err == nil {
						_ = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MULTICAST_IF, int(ifi.Index))
					}
				}
			})
		}
	}
	ip := net.ParseIP(localIP)
	if ip == nil {
		ip = net.IPv4zero
	}
	return &vrrpConn{conn: conn, ifaceIP: ip}, nil
}

// send 发送 VRRP 通告到组播地址。
func (c *vrrpConn) send(p *vrrpPacket) error {
	data := p.marshal()
	addr := &net.IPAddr{IP: net.ParseIP(vrrpMulticast)}
	_, err := c.conn.WriteTo(data, addr)
	return err
}

// recv 接收一个 VRRP 报文（阻塞）。返回报文体和源 IP。
func (c *vrrpConn) recv() (*vrrpPacket, net.IP, error) {
	buf := make([]byte, 1500)
	n, addr, err := c.conn.ReadFrom(buf)
	if err != nil {
		return nil, nil, err
	}
	pkt, err := parseVRRP(buf[:n])
	if err != nil {
		return nil, nil, err
	}
	var src net.IP
	if ipa, ok := addr.(*net.IPAddr); ok {
		src = ipa.IP
	}
	return pkt, src, nil
}

func (c *vrrpConn) close() error {
	return c.conn.Close()
}

// vrrpRunner VRRP 状态机运行器。
type vrrpRunner struct {
	mu       sync.Mutex
	cfg      *Config
	conn     *vrrpConn
	lastAdv  time.Time
	masterIP net.IP // 当前主节点 IP（来自收到的最高优先级通告）
}

// startVRRP 启动 VRRP 协议。返回 false 表示无法启用（如无权限），回退到 TCP 探测。
func (m *Manager) startVRRP() bool {
	if m.cfg.VRID <= 0 {
		return false
	}
	if m.cfg.Priority <= 0 {
		m.cfg.Priority = 100
	}
	if m.cfg.AdvertInt <= 0 {
		m.cfg.AdvertInt = 1
	}
	conn, err := newVRRPConn(m.cfg.Interface, m.cfg.PeerIP)
	if err != nil {
		log.Printf("[ha] VRRP socket init failed (need CAP_NET_RAW?): %v, falling back to TCP probe", err)
		return false
	}
	runner := &vrrpRunner{cfg: m.cfg, conn: conn, lastAdv: time.Now()}
	m.vrrp = runner
	log.Printf("[ha] VRRP started vrid=%d priority=%d advert_int=%ds", m.cfg.VRID, m.cfg.Priority, m.cfg.AdvertInt)

	// 优先级 255（VIP 拥有者）直接成为 Master
	if m.cfg.Priority >= 255 {
		m.promote()
	}
	go runner.recvLoop(m)
	go runner.advertLoop(m)
	go runner.masterDownLoop(m)
	return true
}

// recvLoop 接收并处理 VRRP 通告。
func (r *vrrpRunner) recvLoop(m *Manager) {
	for {
		pkt, src, err := r.conn.recv()
		if err != nil {
			select {
			case <-m.stop:
				return
			default:
			}
			continue
		}
		// 仅处理同一 VRID 的报文
		if pkt.VRID != uint8(r.cfg.VRID) {
			continue
		}
		r.mu.Lock()
		r.lastAdv = time.Now()
		r.masterIP = src
		myPrio := uint8(r.cfg.Priority)

		// 优先级 0 表示对端 Master 主动释放
		if pkt.Priority == 0 {
			r.mu.Unlock()
			m.promote()
			continue
		}
		// 对端优先级更高 -> 降级
		if pkt.Priority > myPrio {
			r.mu.Unlock()
			m.demote()
			continue
		}
		// 优先级相同，比较源 IP（大的优先）
		if pkt.Priority == myPrio && src != nil && r.conn.ifaceIP != nil && bytesGreater(src, r.conn.ifaceIP) {
			r.mu.Unlock()
			m.demote()
			continue
		}
		// 对端优先级更低，忽略（保持当前状态）
		r.mu.Unlock()
	}
}

// advertLoop Master 状态下周期性发送通告。
func (r *vrrpRunner) advertLoop(m *Manager) {
	ticker := time.NewTicker(time.Duration(r.cfg.AdvertInt) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			// 停止时若为 Master，发送 priority=0 通告让备节点接管
			if m.IsMaster() {
				r.sendAdv(0)
			}
			r.conn.close()
			return
		case <-ticker.C:
			if m.IsMaster() {
				r.sendAdv(uint8(r.cfg.Priority))
			}
		}
	}
}

// masterDownLoop Backup 状态下监控 Master 是否存活。
func (r *vrrpRunner) masterDownLoop(m *Manager) {
	// Master_Down_Interval = 3 * Advert_Int + Skew_Time
	// Skew_Time = ((256 - Priority) * Advert_Int) / 256
	skew := time.Duration((256-r.cfg.Priority)*r.cfg.AdvertInt) * time.Second / 256
	downInterval := time.Duration(3*r.cfg.AdvertInt)*time.Second + skew
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			if m.IsMaster() {
				continue
			}
			r.mu.Lock()
			elapsed := time.Since(r.lastAdv)
			r.mu.Unlock()
			if elapsed > downInterval {
				log.Printf("[ha] VRRP master down (no adv for %v), promoting", elapsed)
				m.promote()
			}
		}
	}
}

// sendAdv 发送一条 VRRP 通告。
func (r *vrrpRunner) sendAdv(priority uint8) {
	vip := net.ParseIP(r.cfg.VIP)
	addrs := []net.IP{}
	if vip != nil {
		addrs = append(addrs, vip)
	}
	pkt := &vrrpPacket{
		VRID:         uint8(r.cfg.VRID),
		Priority:     priority,
		CountIPAddrs: uint8(len(addrs)),
		AdvertInt:    uint8(r.cfg.AdvertInt),
		IPAddrs:      addrs,
	}
	if err := r.conn.send(pkt); err != nil {
		log.Printf("[ha] VRRP send failed: %v", err)
	}
}

// bytesGreater 比较两个 IPv4 地址大小（按字节序）。
func bytesGreater(a, b net.IP) bool {
	a4, b4 := a.To4(), b.To4()
	if a4 == nil || b4 == nil {
		return false
	}
	for i := 0; i < 4; i++ {
		if a4[i] != b4[i] {
			return a4[i] > b4[i]
		}
	}
	return false
}
