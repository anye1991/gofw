package audit

import (
	"path/filepath"
	"testing"
)

func TestLogQueryAndRotate(t *testing.T) {
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// 缩小阈值以触发轮转
	l.maxBytes = 300
	l.keep = 3
	l.Log("startup", "system", "gofw 启动", map[string]interface{}{"rules": 27})
	for i := 0; i < 12; i++ {
		l.Log("rules", "web", "规则变更", map[string]interface{}{"i": i})
	}
	all, err := l.Query(100, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) == 0 {
		t.Fatal("expected entries")
	}
	if all[0].Kind != "rules" {
		t.Errorf("newest entry should be last-written kind=rules, got %q", all[0].Kind)
	}
	kinds, err := l.Query(100, "startup")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range kinds {
		if e.Kind != "startup" {
			t.Errorf("kind filter leaked %q", e.Kind)
		}
	}
	// 轮转后文件数受限
	files := l.files()
	if len(files) > l.keep {
		t.Errorf("rotated files %d exceed keep=%d", len(files), l.keep)
	}
}

func TestNilLoggerIsSafe(t *testing.T) {
	var l *Logger
	l.Log("x", "y", "z", nil)
	if e, err := l.Query(10, ""); err != nil || len(e) != 0 {
		t.Errorf("nil logger should be a no-op, got %v %v", e, err)
	}
}
