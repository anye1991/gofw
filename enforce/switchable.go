package enforce

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gofw/engine"
	"gofw/geoip"
	"gofw/rules"
)

// guardMarker 与 webui 包地理围栏的护栏标记保持一致。
// 运行时切换内核前必须确认它已置顶，否则拒绝切换（防锁死）。
const guardMarker = "[gofw-guard] "

type enforcerBox struct {
	enf  Enforcer
	mode string // "monitor" / "kernel"
}

// Switchable 是运行时可切换的执行后端包装。
//
// 设计要点：
//   - 决策热路径 OnDecision 只读一个 atomic 指针，不加锁；
//   - 切换在互斥区内完成「预检 → 清旧表 → 下发新表 → 原子替换」，失败保持原后端；
//   - 切到 kernel 后可调 ArmRollback 启动倒计时，超时自动切回 monitor，
//     即使误把管理通道挡掉，30 秒后也会自行恢复，不需要人能登进机器。
type Switchable struct {
	cur   atomic.Pointer[enforcerBox]
	mu    sync.Mutex
	rsPtr *atomic.Pointer[rules.RuleSet]

	geoDB       *geoip.DB
	banProvider func() (v4, v6 []string)
	onChange    func(mode string)

	rollbackMu    sync.Mutex
	rollbackTimer *time.Timer
	rollbackAt    time.Time
}

func NewSwitchable(initial Enforcer, rsPtr *atomic.Pointer[rules.RuleSet], geoDB *geoip.DB, banProvider func() (v4, v6 []string), onChange func(string)) *Switchable {
	mode := "monitor"
	if _, ok := initial.(*NftablesEnforcer); ok {
		mode = "kernel"
	}
	s := &Switchable{rsPtr: rsPtr, geoDB: geoDB, banProvider: banProvider, onChange: onChange}
	s.cur.Store(&enforcerBox{enf: initial, mode: mode})
	return s
}

func (s *Switchable) box() *enforcerBox { return s.cur.Load() }

// Mode 返回当前真实执行后端，不依赖启动参数或页面猜测。
func (s *Switchable) Mode() string { return s.box().mode }

func (s *Switchable) Name() string { return "Switchable[" + s.box().enf.Name() + "]" }

func (s *Switchable) Available() bool { return s.box().enf.Available() }

func (s *Switchable) Apply(rs *rules.RuleSet) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.box().enf.Apply(rs)
}

func (s *Switchable) OnDecision(d engine.Decision) { s.box().enf.OnDecision(d) }

func (s *Switchable) Flush() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.box().enf.Flush()
}

// Preflight 在真正切换前做完整的只读自检，返回逐项结果文本。
// 任何一项不通过都拒绝切到内核，尤其是护栏缺失。
func (s *Switchable) Preflight() (ok bool, detail string) {
	var sb strings.Builder
	fail := func(format string, a ...interface{}) {
		sb.WriteString("✗ " + fmt.Sprintf(format, a...) + "\n")
	}
	pass := func(format string, a ...interface{}) {
		sb.WriteString("✓ " + fmt.Sprintf(format, a...) + "\n")
	}

	path, err := exec.LookPath("nft")
	if err != nil {
		fail("找不到 nft 命令：%v", err)
		return false, sb.String()
	}
	pass("nft 可执行文件：%s", path)

	if err := exec.Command(path, "list", "tables").Run(); err != nil {
		fail("当前进程无 nftables 管理权限（需 root / CAP_NET_ADMIN）：%v", err)
		return false, sb.String()
	}
	pass("nftables 管理权限：具备")

	rs := s.rsPtr.Load()
	guards := 0
	for _, r := range rs.Rules {
		if strings.HasPrefix(r.Comment, guardMarker) {
			guards++
		}
	}
	headGuard := true
	for i := 0; i < guards && i < len(rs.Rules); i++ {
		if !strings.HasPrefix(rs.Rules[i].Comment, guardMarker) {
			headGuard = false
			break
		}
	}
	if guards < 4 || !headGuard {
		fail("防锁死护栏不足或未置顶（当前 %d 条，要求 ≥4 且排在最前）；请先在「地理围栏」点「仅安装护栏」", guards)
		return false, sb.String()
	}
	pass("防锁死护栏：%d 条且全部置顶（管理端口 / LAN / 回环 / 已建立连接放行）", guards)

	nft := NewNftables(s.geoDB, s.banProvider)
	if err := nft.Validate(rs); err != nil {
		fail("规则集语法校验：%v", err)
		return false, sb.String()
	}
	pass("规则集 nft -c -f 语法校验：通过（%d 条规则，default=%s）", rs.Len(), rs.DefaultAction)

	sb.WriteString("→ 可以切换。切换后 30 秒内若未点「确认保留」，会自动回滚到 monitor。")
	return true, sb.String()
}

// SwitchTo 在运行时切换后端；失败时保持原后端不变。
func (s *Switchable) SwitchTo(mode string) error {
	if mode != "monitor" && mode != "kernel" {
		return fmt.Errorf("unknown backend %q", mode)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	old := s.box()
	if old.mode == mode {
		return nil
	}
	rs := s.rsPtr.Load()

	if mode == "kernel" {
		if ok, detail := s.preflightLocked(); !ok {
			return fmt.Errorf("预检未通过，已拒绝切换：\n%s", detail)
		}
		nft := NewNftables(s.geoDB, s.banProvider)
		if !nft.Available() {
			return fmt.Errorf("nftables 后端不可用")
		}
		// 先清掉可能存在的旧表，保证是替换不是追加。
		old.enf.Flush()
		if !nft.Apply(rs) {
			return fmt.Errorf("nftables 下发失败，已保持原后端")
		}
		s.cur.Store(&enforcerBox{enf: nft, mode: "kernel"})
		log.Printf("[backend] switched monitor -> kernel (nftables, real drop)")
	} else {
		// 切回 monitor 必须删除内核表，否则内核侧规则会残留继续丢包。
		old.enf.Flush()
		m := &MonitorEnforcer{}
		if !m.Apply(rs) {
			return fmt.Errorf("monitor 后端初始化失败")
		}
		s.cur.Store(&enforcerBox{enf: m, mode: "monitor"})
		log.Printf("[backend] switched kernel -> monitor (kernel table flushed)")
	}
	if s.onChange != nil {
		s.onChange(mode)
	}
	return nil
}

// preflightLocked 供 SwitchTo 在已持锁时复用，避免重复加锁。
func (s *Switchable) preflightLocked() (bool, string) {
	var sb strings.Builder
	path, err := exec.LookPath("nft")
	if err != nil {
		return false, "找不到 nft 命令"
	}
	if err := exec.Command(path, "list", "tables").Run(); err != nil {
		return false, "无 nftables 管理权限（需 root / CAP_NET_ADMIN）"
	}
	rs := s.rsPtr.Load()
	guards := 0
	for _, r := range rs.Rules {
		if strings.HasPrefix(r.Comment, guardMarker) {
			guards++
		}
	}
	if guards < 4 {
		return false, fmt.Sprintf("防锁死护栏仅 %d 条（要求 ≥4 且置顶），请先安装护栏", guards)
	}
	for i := 0; i < guards; i++ {
		if !strings.HasPrefix(rs.Rules[i].Comment, guardMarker) {
			return false, "防锁死护栏未置顶，请先重新应用地理围栏"
		}
	}
	if err := NewNftables(s.geoDB, s.banProvider).Validate(rs); err != nil {
		sb.WriteString(err.Error())
		return false, sb.String()
	}
	return true, ""
}

// ArmRollback 启动自动回滚倒计时。倒计时内必须调用 Confirm，否则自动切回 monitor。
func (s *Switchable) ArmRollback(d time.Duration) {
	s.rollbackMu.Lock()
	defer s.rollbackMu.Unlock()
	if s.rollbackTimer != nil {
		s.rollbackTimer.Stop()
	}
	s.rollbackAt = time.Now().Add(d)
	s.rollbackTimer = time.AfterFunc(d, func() {
		if s.Mode() == "monitor" {
			return
		}
		if err := s.SwitchTo("monitor"); err != nil {
			log.Printf("[backend] AUTO ROLLBACK FAILED: %v", err)
		} else {
			log.Printf("[backend] AUTO ROLLBACK: 未在 %v 内确认，已自动切回 monitor", d)
		}
		s.rollbackMu.Lock()
		s.rollbackAt = time.Time{}
		s.rollbackMu.Unlock()
	})
}

// Confirm 确认当前内核模式可用，取消自动回滚。
func (s *Switchable) Confirm() {
	s.rollbackMu.Lock()
	defer s.rollbackMu.Unlock()
	if s.rollbackTimer != nil {
		s.rollbackTimer.Stop()
		s.rollbackTimer = nil
	}
	s.rollbackAt = time.Time{}
}

// RollbackRemaining 返回自动回滚剩余秒数，0 表示未启动。
func (s *Switchable) RollbackRemaining() int {
	s.rollbackMu.Lock()
	defer s.rollbackMu.Unlock()
	if s.rollbackAt.IsZero() {
		return 0
	}
	left := int(time.Until(s.rollbackAt).Seconds())
	if left < 0 {
		return 0
	}
	return left
}
