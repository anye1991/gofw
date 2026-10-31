package main

import (
	"strconv"
	"strings"
)

// flagSet 是一个极简的命令行参数解析器，支持:
//   - 短选项: -r file, -p tcp
//   - 长选项: --rules file, --src-ip 1.2.3.4
//   - bool 长选项: --monitor
//   - 位置参数（非选项开头的参数）
type flagSet struct {
	args     []string
	short    map[string]string
	long     map[string]string
	boolLong map[string]bool
	pos      []string
	parsed   bool
}

func newFlagSet(args []string) *flagSet {
	return &flagSet{
		args:     args,
		short:    make(map[string]string),
		long:     make(map[string]string),
		boolLong: make(map[string]bool),
	}
}

func (f *flagSet) parse() {
	if f.parsed {
		return
	}
	f.parsed = true
	for i := 0; i < len(f.args); i++ {
		a := f.args[i]
		if !strings.HasPrefix(a, "-") {
			f.pos = append(f.pos, a)
			continue
		}
		if a == "--" {
			f.pos = append(f.pos, f.args[i+1:]...)
			break
		}
		if strings.HasPrefix(a, "--") {
			name := a[2:]
			if idx := strings.Index(name, "="); idx >= 0 {
				f.long[name[:idx]] = name[idx+1:]
				continue
			}
			// 可能是 bool 或带值
			if i+1 < len(f.args) && !strings.HasPrefix(f.args[i+1], "-") {
				f.long[name] = f.args[i+1]
				i++
			} else {
				f.boolLong[name] = true
			}
			continue
		}
		// 短选项 -x 或 -xvalue
		name := a[1:]
		if len(name) > 1 {
			// 组合或 -xvalue
			if i+1 < len(f.args) && !strings.HasPrefix(f.args[i+1], "-") {
				f.short[string(name[0])] = f.args[i+1]
				i++
			} else {
				f.short[string(name[0])] = name[1:]
			}
			continue
		}
		if i+1 < len(f.args) && !strings.HasPrefix(f.args[i+1], "-") {
			f.short[name] = f.args[i+1]
			i++
		} else {
			f.boolLong[name] = true
		}
	}
}

func (f *flagSet) string(short, long, def string) string {
	f.parse()
	if short != "" {
		if v, ok := f.short[short]; ok {
			return v
		}
	}
	if long != "" {
		if v, ok := f.long[long]; ok {
			return v
		}
	}
	return def
}

func (f *flagSet) int(short, long string, def int) int {
	s := f.string(short, long, "")
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return v
}

func (f *flagSet) float(short, long string, def float64) float64 {
	s := f.string(short, long, "")
	if s == "" {
		return def
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return def
	}
	return v
}

func (f *flagSet) bool(short, long string, def bool) bool {
	f.parse()
	if short != "" {
		if _, ok := f.short[short]; ok {
			return true
		}
	}
	if long != "" {
		if _, ok := f.long[long]; ok {
			return true
		}
		if v, ok := f.boolLong[long]; ok {
			return v
		}
	}
	return def
}

func (f *flagSet) positional(idx int) string {
	f.parse()
	if idx < 0 || idx >= len(f.pos) {
		return ""
	}
	return f.pos[idx]
}
