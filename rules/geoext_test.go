// Copyright (c) 2026 暗夜铭少 (Nights-Shadow)
// 仓库: https://gitee.com/nights-shadow/gofw
//
// 本源代码文件依据《木兰宽松许可证，第2版》(Mulan PSL v2) 授权使用。
// 你应当已随本项目获得许可证副本；若未获得，请访问 https://license.coscl.org.cn/MulanPSL2
// SPDX-License-Identifier: MulanPSL-2.0

package rules

import "testing"

func TestMatchStringList(t *testing.T) {
	cases := []struct {
		spec, value string
		want        bool
	}{
		{"", "beijing", true},
		{"Beijing", "beijing", true},
		{"Beijing,Shanghai", "shanghai", true},
		{"Beijing,Shanghai", "guangzhou", false},
		{"!Beijing", "beijing", false},
		{"!Beijing", "guangzhou", true},
		{"Bei*", "beijing", true},
		{"*", "anything", true},
		{"Beijing", "", false}, // 库无城市数据时不应误命中
		{"!Beijing", "", true}, // 取反语义与 GeoIP deny 一致
	}
	for _, c := range cases {
		if got := MatchStringList(c.spec, c.value); got != c.want {
			t.Errorf("MatchStringList(%q,%q)=%v want %v", c.spec, c.value, got, c.want)
		}
	}
}

func TestRuleCityASNMatch(t *testing.T) {
	r := NewRule(ActionDrop)
	r.GeoCity = "Beijing,Shanghai"
	r.GeoASN = "AS4134,AS4837"

	ctx := MatchContext{SrcCountry: "CN"}
	if r.Match(ctx) {
		t.Fatal("两列库无城市/ASN 数据时，城市+ASN 规则不应误命中任何包")
	}
	ctx.City = "Beijing"
	if r.Match(ctx) {
		t.Fatal("ASN 未满足时不应命中")
	}
	ctx.ASN = "AS4134"
	if !r.Match(ctx) {
		t.Fatal("城市与 ASN 都满足时应命中")
	}
	ctx.City = "Guangzhou"
	if r.Match(ctx) {
		t.Fatal("城市不匹配时不应命中")
	}
}
