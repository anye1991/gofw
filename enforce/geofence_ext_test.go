package enforce

import (
	"os"
	"strings"
	"testing"

	"gofw/geoip"
	"gofw/rules"
)

// v6TestDB 构造一个同时含 IPv4 与 IPv6 网段的测试国家库（国家码 XX）。
func v6TestDB(t *testing.T) *geoip.DB {
	t.Helper()
	csv := "198.51.100.0/24,XX\n" +
		"2001:db8:1::/48,XX\n" +
		"2001:db8:2::/48,XX\n"
	path := t.TempDir() + "/geoip_v6.csv"
	if err := os.WriteFile(path, []byte(csv), 0644); err != nil {
		t.Fatal(err)
	}
	db := geoip.New()
	if err := db.LoadFromCSV(path); err != nil {
		t.Fatal(err)
	}
	if db.Count() != 3 {
		t.Fatalf("expected 3 entries, got %d", db.Count())
	}
	return db
}

// IPv6 GeoIP：一条 geoip 规则应同时产出 ipv4_addr 与 ipv6_addr 两个集合，
// 并分别用 ip saddr / ip6 saddr 引用，两族语句都存在。
func TestBuildScriptGeoIPv6Sets(t *testing.T) {
	rs := rules.NewRuleSet()
	rs.Add(&rules.Rule{Action: rules.ActionDrop, GeoIP: rules.ParseGeoIPSpec("allow:XX"), Direction: rules.DirIn})
	n := &NftablesEnforcer{geoDB: v6TestDB(t)}
	script := n.buildScript(rs)
	t.Log(script)
	for _, want := range []string{
		"set geoip_XX {", "type ipv4_addr",
		"set geoip_XX_v6 {", "type ipv6_addr",
		"ip saddr @geoip_XX drop", "ip6 saddr @geoip_XX_v6 drop",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("missing %q in script:\n%s", want, script)
		}
	}
}

// 动态封禁集合：注入 provider 后应生成 ban 集合，并在三条链首都插入 drop。
func TestBuildScriptBanSets(t *testing.T) {
	rs := rules.NewRuleSet()
	rs.Add(rules.NewRule(rules.ActionAccept))
	n := &NftablesEnforcer{}
	n.SetBanProvider(func() (v4, v6 []string) {
		return []string{"203.0.113.7"}, []string{"2001:db8::1"}
	})
	script := n.buildScript(rs)
	t.Log(script)
	for _, want := range []string{
		"set gofw_ban_v4 {", "set gofw_ban_v6 {",
		"ip saddr @gofw_ban_v4 drop", "ip6 saddr @gofw_ban_v6 drop",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("missing %q in script:\n%s", want, script)
		}
	}
	// 三条链都应带封禁语句
	if c := strings.Count(script, "ip saddr @gofw_ban_v4 drop"); c != 3 {
		t.Errorf("ban v4 drop should appear in 3 chains, got %d", c)
	}
}

// 无封禁时不应生成空的 ban 集合（空集合会导致 nft 语法/语义问题）。
func TestBuildScriptNoBans(t *testing.T) {
	rs := rules.NewRuleSet()
	rs.Add(rules.NewRule(rules.ActionAccept))
	n := &NftablesEnforcer{}
	n.SetBanProvider(func() (v4, v6 []string) { return nil, nil })
	script := n.buildScript(rs)
	if strings.Contains(script, "gofw_ban") {
		t.Errorf("no bans should produce no ban set, got:\n%s", script)
	}
}
