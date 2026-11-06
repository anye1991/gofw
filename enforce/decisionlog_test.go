package enforce

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 每包日志限速是防「日志拖死整机」的关键保护，锁死其行为。
func TestDecisionLogRateLimit(t *testing.T) {
	SetDecisionLogRate(3)
	defer SetDecisionLogRate(20)
	SuppressedDecisionLogs() // 清零

	allowed := 0
	for i := 0; i < 10; i++ {
		if decisionLog.allow() {
			allowed++
		}
	}
	if allowed != 3 {
		t.Errorf("expected 3 allowed lines in one window, got %d", allowed)
	}
	if got := SuppressedDecisionLogs(); got != 7 {
		t.Errorf("expected 7 suppressed lines, got %d", got)
	}
}

// 窗口滚过后额度必须重置，否则限速会变成「启动后只写 N 行」。
func TestDecisionLogWindowReset(t *testing.T) {
	SetDecisionLogRate(2)
	defer SetDecisionLogRate(20)
	SuppressedDecisionLogs()

	if !decisionLog.allow() || !decisionLog.allow() {
		t.Fatal("first two lines should be allowed")
	}
	if decisionLog.allow() {
		t.Fatal("third line should be suppressed")
	}
	// 模拟下一秒到来（不真的 sleep，保持测试快）。
	decisionLog.winStart.Store(time.Now().Add(-2 * time.Second).UnixNano())
	for i := 0; i < 2; i++ {
		if !decisionLog.allow() {
			t.Errorf("line %d in the new window should be allowed", i+1)
		}
	}
}

func TestDecisionLogOff(t *testing.T) {
	SetDecisionLogRate(0)
	defer SetDecisionLogRate(20)
	SuppressedDecisionLogs()

	for i := 0; i < 5; i++ {
		if decisionLog.allow() {
			t.Error("rate=0 must suppress every per-packet log line")
		}
	}
	if got := SuppressedDecisionLogs(); got != 5 {
		t.Errorf("expected 5 suppressed, got %d", got)
	}
}

func TestDecisionLogUnlimited(t *testing.T) {
	SetDecisionLogRate(-1)
	defer SetDecisionLogRate(20)
	SuppressedDecisionLogs()

	for i := 0; i < 50; i++ {
		if !decisionLog.allow() {
			t.Fatal("negative rate must allow all lines")
		}
	}
	if got := SuppressedDecisionLogs(); got != 0 {
		t.Errorf("unlimited mode must not suppress, got %d", got)
	}
}

// 热路径可能被多个抓包 worker 并发调用，固定窗口不能因竞态超发。
func TestDecisionLogConcurrent(t *testing.T) {
	SetDecisionLogRate(10)
	defer SetDecisionLogRate(20)
	SuppressedDecisionLogs()

	var allowed atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if decisionLog.allow() {
				allowed.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := allowed.Load(); got != 10 {
		t.Errorf("expected exactly 10 allowed under concurrency, got %d", got)
	}
}
