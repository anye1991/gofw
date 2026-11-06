package enforce

import (
	"sync/atomic"
	"time"
)

// decisionLogLimiter 限制「每包决策日志」的写入速率。
//
// 背景（线上实测故障）：MonitorEnforcer.OnDecision 对每个抓到的包都 log.Printf 一行；
// main 用 io.MultiWriter(os.Stderr, file) 把每行同时写进 systemd journal 与日志文件，
// 等于每行两次磁盘写。网卡在 AF_PACKET 混杂模式下会抓到整个网段的包，Web 页面轮询
// 自身又在制造流量，形成正反馈：包越多 → 日志越多 → journald / 磁盘 IO 越忙 →
// 整机越卡 → 请求超时重试 → 包更多。
//
// 低配 VM 上的表现是「内核活着、用户态假死」：ping 通、TCP 端口能连，但 SSH/Web
// 一个字节都不回；内核日志里没有 OOM / hung task，journald 出现时间戳倒挂，
// systemd 反复报 service stop timeout。这不是进程崩溃，是 IO 被日志拖死。
//
// 因此默认对每包日志做固定窗口限速；启动、统计、告警、审计、错误等管理类日志
// 不经过这里，完全不受影响。被抑制的行数可通过 SuppressedDecisionLogs 取走，
// 由周期性 stats 如实汇总，不假装都记下来了。
type decisionLogLimiter struct {
	rate       atomic.Int64 // 每秒允许行数：0=关闭每包日志，<0=不限（调试用）
	winStart   atomic.Int64 // 当前窗口起始（unix nano）
	used       atomic.Int64 // 本窗口已用额度
	suppressed atomic.Int64 // 累计被抑制行数
}

var decisionLog decisionLogLimiter

func init() {
	// 安全默认：即使调用方没显式设置参数，也不会退回「每包全量写」的旧行为。
	decisionLog.rate.Store(20)
}

// SetDecisionLogRate 设置每包决策日志每秒最大行数，默认 20。
// 0 = 完全关闭每包日志（只保留统计 / 告警 / 错误）；负数 = 不限（仅调试时用）。
func SetDecisionLogRate(rate int) {
	decisionLog.rate.Store(int64(rate))
	decisionLog.winStart.Store(0)
	decisionLog.used.Store(0)
}

// SuppressedDecisionLogs 取出并清零被抑制的行数，用于周期性统计输出。
func SuppressedDecisionLogs() int64 { return decisionLog.suppressed.Swap(0) }

// allow 判断当前这行每包日志是否允许写出。并发安全，热路径无锁。
func (l *decisionLogLimiter) allow() bool {
	rate := l.rate.Load()
	if rate == 0 {
		l.suppressed.Add(1)
		return false
	}
	if rate < 0 {
		return true
	}

	now := time.Now().UnixNano()
	start := l.winStart.Load()
	if now-start >= int64(time.Second) {
		if l.winStart.CompareAndSwap(start, now) {
			l.used.Store(0)
		}
	}

	for {
		used := l.used.Load()
		if used >= rate {
			l.suppressed.Add(1)
			return false
		}
		if l.used.CompareAndSwap(used, used+1) {
			return true
		}
	}
}
