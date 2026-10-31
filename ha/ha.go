// Package ha 提供高可用主备切换。
package ha

import (
	"log"
	"net"
	"os/exec"
	"sync/atomic"
	"time"
)

// Config HA 配置。
type Config struct {
	Enabled   bool   `yaml:"enabled"`
	Mode      string `yaml:"mode"`       // "master" / "backup" / "auto"
	PeerIP    string `yaml:"peer_ip"`    // 对端 IP（VRRP 下作为本地发送源 IP）
	PeerPort  int    `yaml:"peer_port"`  // 对端端口（TCP 探测模式）
	VIP       string `yaml:"vip"`        // 虚拟 IP
	Interface string `yaml:"interface"`  // VIP 绑定的网卡
	CheckPort int    `yaml:"check_port"` // 健康检查端口（TCP 探测模式）
	Interval  int    `yaml:"interval"`   // 健康检查间隔（秒，TCP 探测模式）
	FailCount int    `yaml:"fail_count"` // 连续失败多少次切换（TCP 探测模式）

	// VRRP 协议参数（RFC 3768）。VRID>0 时启用 VRRP，否则回退 TCP 探测。
	VRID      int `yaml:"vrid"`       // 虚拟路由器 ID (1-255)
	Priority  int `yaml:"priority"`   // 优先级 (1-254, 255=VIP 拥有者; 默认 100)
	AdvertInt int `yaml:"advert_int"` // 通告间隔秒数（默认 1）
}

// State HA 状态。
type State int32

const (
	StateUnknown State = iota
	StateMaster
	StateBackup
)

func (s State) String() string {
	switch s {
	case StateMaster:
		return "MASTER"
	case StateBackup:
		return "BACKUP"
	}
	return "UNKNOWN"
}

// Manager HA 管理器。
type Manager struct {
	cfg       *Config
	state     int32 // 原子，State 枚举
	failCount int32
	stop      chan struct{}
	vrrp      *vrrpRunner // VRRP 运行器（启用 VRRP 时非空）
	onPromote func()      // 提升为主时回调
	onDemote  func()      // 降级为备时回调
}

// NewManager 创建 HA 管理器。
func NewManager(cfg *Config) *Manager {
	if cfg == nil {
		cfg = &Config{Enabled: false}
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 2
	}
	if cfg.FailCount <= 0 {
		cfg.FailCount = 3
	}
	if cfg.PeerPort <= 0 {
		cfg.PeerPort = 7878
	}
	m := &Manager{cfg: cfg, stop: make(chan struct{})}
	switch cfg.Mode {
	case "master":
		atomic.StoreInt32(&m.state, int32(StateMaster))
	case "backup":
		atomic.StoreInt32(&m.state, int32(StateBackup))
	default:
		atomic.StoreInt32(&m.state, int32(StateBackup))
	}
	return m
}

// SetCallbacks 设置主备切换回调。
func (m *Manager) SetCallbacks(onPromote, onDemote func()) {
	m.onPromote = onPromote
	m.onDemote = onDemote
}

// PromoteForTest 测试用：手动触发提升为主（调用真实 promote 逻辑，含 VIP 操作）。
func (m *Manager) PromoteForTest() {
	m.promote()
}

// State 返回当前 HA 状态。
func (m *Manager) State() State {
	return State(atomic.LoadInt32(&m.state))
}

// IsMaster 返回是否为主节点。
func (m *Manager) IsMaster() bool {
	return m.State() == StateMaster
}

// Start 启动 HA 健康检查。优先使用 VRRP 协议，否则回退到 TCP 探测。
func (m *Manager) Start() {
	if !m.cfg.Enabled {
		return
	}
	log.Printf("[ha] started, mode=%s, peer=%s:%d, vip=%s", m.cfg.Mode, m.cfg.PeerIP, m.cfg.PeerPort, m.cfg.VIP)

	// 优先启动 VRRP
	if m.startVRRP() {
		return
	}

	// 回退到 TCP 探测模式
	// 如果配置为 master，立即提升
	if m.cfg.Mode == "master" {
		m.promote()
	}
	go m.healthCheckLoop()
}

// Stop 停止 HA。
func (m *Manager) Stop() {
	close(m.stop)
}

func (m *Manager) healthCheckLoop() {
	ticker := time.NewTicker(time.Duration(m.cfg.Interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			m.checkPeer()
		}
	}
}

func (m *Manager) checkPeer() {
	if m.cfg.PeerIP == "" {
		return
	}
	alive := m.tcpProbe(m.cfg.PeerIP, m.cfg.PeerPort)
	if alive {
		atomic.StoreInt32(&m.failCount, 0)
		// 对端存活，如果自己是 master 且对端也认为自己是 master，则保持
		return
	}
	fc := atomic.AddInt32(&m.failCount, 1)
	log.Printf("[ha] peer %s:%d unreachable (fail=%d/%d)", m.cfg.PeerIP, m.cfg.PeerPort, fc, m.cfg.FailCount)
	if fc >= int32(m.cfg.FailCount) {
		// 对端连续失败，提升自己为主
		m.promote()
	}
}

// tcpProbe TCP 探测对端是否存活。
func (m *Manager) tcpProbe(ip string, port int) bool {
	addr := net.JoinHostPort(ip, itoa(port))
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (m *Manager) promote() {
	if atomic.CompareAndSwapInt32(&m.state, int32(StateBackup), int32(StateMaster)) {
		log.Printf("[ha] promoted to MASTER")
		if m.cfg.VIP != "" && m.cfg.Interface != "" {
			m.addVIP()
		}
		if m.onPromote != nil {
			m.onPromote()
		}
	}
}

func (m *Manager) demote() {
	if atomic.CompareAndSwapInt32(&m.state, int32(StateMaster), int32(StateBackup)) {
		log.Printf("[ha] demoted to BACKUP")
		if m.cfg.VIP != "" && m.cfg.Interface != "" {
			m.delVIP()
		}
		if m.onDemote != nil {
			m.onDemote()
		}
	}
}

// addVIP 添加虚拟 IP。
func (m *Manager) addVIP() {
	cmd := exec.Command("ip", "addr", "add", m.cfg.VIP+"/32", "dev", m.cfg.Interface)
	if err := cmd.Run(); err != nil {
		log.Printf("[ha] add VIP %s failed: %v", m.cfg.VIP, err)
	} else {
		log.Printf("[ha] VIP %s added to %s", m.cfg.VIP, m.cfg.Interface)
	}
}

// delVIP 删除虚拟 IP。
func (m *Manager) delVIP() {
	cmd := exec.Command("ip", "addr", "del", m.cfg.VIP+"/32", "dev", m.cfg.Interface)
	cmd.Run()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
