package config

import (
	"os"
	"sort"
	"strings"
)

// yaml.Marshal 会重建整个 YAML 文档，导致人工维护的分段注释与空行丢失。
// 后台每次保存规则（配置源 PUT、地理围栏 apply/clear）都会触发 Save，
// 若不处理，运维写的 "# ===== L3/L4 精确阻断 =====" 这类说明会被悄悄抹掉。
//
// preserveComments 以「注释之后紧邻的规则 comment 值」为锚点，把旧文件里的
// 注释行迁移到新生成的文档中。锚点规则被删除时，注释保留到文件尾而不是丢弃。

const (
	noteHead = "\x00head" // 文件顶部注释（在任何顶层键之前）
	noteTail = "\x00tail" // 文件尾部注释或锚点已失效
)

type commentNote struct {
	lines  []string
	anchor string
}

func yamlCommentValue(line string) (string, bool) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, "comment:") {
		return "", false
	}
	v := strings.TrimSpace(strings.TrimPrefix(t, "comment:"))
	v = strings.Trim(v, "\"'")
	return v, true
}

func normalizeLines(b []byte) []string {
	return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
}

// collectComments 提取旧文件中的连续注释组，并确定各自的锚点。
func collectComments(old []byte) []commentNote {
	lines := normalizeLines(old)
	var notes []commentNote
	seenTopKey := false
	for i := 0; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(t, "#") {
			// 顶层键（顶格、非列表项）出现后，注释不再属于文件头
			if t != "" && !strings.HasPrefix(lines[i], " ") &&
				!strings.HasPrefix(lines[i], "\t") && !strings.HasPrefix(t, "- ") {
				seenTopKey = true
			}
			continue
		}
		group := []string{lines[i]}
		j := i + 1
		for j < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[j]), "#") {
			group = append(group, lines[j])
			j++
		}
		anchor := noteTail
		if !seenTopKey {
			anchor = noteHead
		} else {
			for k := j; k < len(lines); k++ {
				if v, ok := yamlCommentValue(lines[k]); ok {
					anchor = v
					break
				}
			}
		}
		notes = append(notes, commentNote{lines: group, anchor: anchor})
		i = j - 1
	}
	return notes
}

// preserveComments 把 path 原文件里的注释按锚点插回新生成的 YAML。
// 任何异常都退化为原样返回 data，绝不影响保存本身。
func preserveComments(path string, data []byte) []byte {
	old, err := os.ReadFile(path)
	if err != nil {
		return data
	}
	notes := collectComments(old)
	if len(notes) == 0 {
		return data
	}

	newLines := normalizeLines(data)

	// comment 值 -> 该 comment 所在行；重复 comment 取首次出现
	commentPos := make(map[string]int)
	for idx, line := range newLines {
		if v, ok := yamlCommentValue(line); ok && v != "" {
			if _, exists := commentPos[v]; !exists {
				commentPos[v] = idx
			}
		}
	}

	// 从 comment 行回溯到所属规则块的起始行（"- action:" / "- name:"）
	blockStart := func(idx int) int {
		for k := idx; k >= 0; k-- {
			t := strings.TrimSpace(newLines[k])
			if strings.HasPrefix(t, "- action:") || strings.HasPrefix(t, "- name:") {
				return k
			}
			if k < idx && t != "" && !strings.HasPrefix(newLines[k], " ") &&
				!strings.HasPrefix(newLines[k], "\t") {
				break
			}
		}
		return idx
	}

	inserts := make(map[int][]string)
	var head, tail []string
	for _, n := range notes {
		switch n.anchor {
		case noteHead:
			head = append(head, n.lines...)
		case noteTail:
			tail = append(tail, n.lines...)
		default:
			if idx, ok := commentPos[n.anchor]; ok {
				pos := blockStart(idx)
				inserts[pos] = append(inserts[pos], n.lines...)
			} else {
				// 锚点规则被删掉了：注释保留到文件尾，不静默丢失
				tail = append(tail, n.lines...)
			}
		}
	}

	// 从后往前插入，避免行号偏移
	keys := make([]int, 0, len(inserts))
	for k := range inserts {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for i := len(keys) - 1; i >= 0; i-- {
		pos := keys[i]
		block := inserts[pos]
		out := make([]string, 0, len(newLines)+len(block))
		out = append(out, newLines[:pos]...)
		out = append(out, block...)
		out = append(out, newLines[pos:]...)
		newLines = out
	}
	if len(head) > 0 {
		newLines = append(append([]string{}, head...), newLines...)
	}
	if len(tail) > 0 {
		newLines = append(newLines, tail...)
	}
	return []byte(strings.Join(newLines, "\n"))
}
