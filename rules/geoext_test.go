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
