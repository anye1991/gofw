// Package audit 提供纯标准库的 JSONL 审计日志：轮转写入 + 最近记录查询。
// 记录规则变更、地理围栏、封禁、后端切换、登录等管理动作，不记录_packet_流水，
// 避免在高包量下把磁盘打满；文件按大小轮转并限制保留份数。
package audit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultMaxBytes = 8 << 20 // 单文件 8 MiB
	defaultKeep     = 5       // 保留 5 份，约 40 MiB 上限
)

type Entry struct {
	Time   string                 `json:"time"`
	Kind   string                 `json:"kind"`
	Actor  string                 `json:"actor"`
	Detail string                 `json:"detail"`
	Fields map[string]interface{} `json:"fields,omitempty"`
}

type Logger struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	keep     int
	f        *os.File
	size     int64
}

// New 创建审计日志；path 为空时返回 nil（调用方需判空）。
func New(path string) (*Logger, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create audit dir: %w", err)
	}
	l := &Logger{path: path, maxBytes: defaultMaxBytes, keep: defaultKeep}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Logger) open() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.f, l.size = f, st.Size()
	return nil
}

func (l *Logger) Path() string { return l.path }

// Close 关闭当前日志文件（主要用于测试与优雅退出）。
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// Log 写一条审计记录。写入失败只影响审计，不影响业务。
func (l *Logger) Log(kind, actor, detail string, fields map[string]interface{}) {
	if l == nil {
		return
	}
	e := Entry{
		Time: time.Now().Format("2006-01-02 15:04:05"),
		Kind: kind, Actor: actor, Detail: detail, Fields: fields,
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	line := append(b, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		if err := l.open(); err != nil {
			return
		}
	}
	if l.size+int64(len(line)) > l.maxBytes {
		l.rotate()
	}
	if _, err := l.f.Write(line); err != nil {
		return
	}
	l.size += int64(len(line))
}

func (l *Logger) rotate() {
	if l.f != nil {
		l.f.Close()
		l.f = nil
	}
	// .(keep-1) 最老的一份直接丢弃，其余依次后移
	for i := l.keep - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", l.path, i)
		if i == l.keep-1 {
			os.Remove(src)
			continue
		}
		dst := fmt.Sprintf("%s.%d", l.path, i+1)
		os.Rename(src, dst)
	}
	os.Rename(l.path, l.path+".1")
	if err := l.open(); err != nil {
		return
	}
}

// files 返回按时间从旧到新的日志文件列表（当前文件最后）。
func (l *Logger) files() []string {
	var out []string
	for i := l.keep - 1; i >= 1; i-- {
		p := fmt.Sprintf("%s.%d", l.path, i)
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	if _, err := os.Stat(l.path); err == nil {
		out = append(out, l.path)
	}
	return out
}

// Query 返回最近 limit 条记录（倒序，最新在前），kind 非空时按类型过滤。
func (l *Logger) Query(limit int, kind string) ([]Entry, error) {
	if l == nil {
		return []Entry{}, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	ring := make([]Entry, 0, limit)
	for _, p := range l.files() {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var e Entry
			if json.Unmarshal([]byte(line), &e) != nil {
				continue
			}
			if kind != "" && e.Kind != kind {
				continue
			}
			if len(ring) < limit {
				ring = append(ring, e)
			} else {
				// 保留最新：丢弃最老的一条
				copy(ring, ring[1:])
				ring[limit-1] = e
			}
		}
		f.Close()
	}
	// ring 内按文件顺序（旧→新）追加，反转后即最新在前。
	for i, j := 0, len(ring)-1; i < j; i, j = i+1, j-1 {
		ring[i], ring[j] = ring[j], ring[i]
	}
	return ring, nil
}
