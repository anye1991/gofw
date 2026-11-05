package geoip

import (
	"net"
	"os"
	"testing"
)

// linearLookup 是改造前的参考实现：按前缀长度降序全表扫描，首个命中生效。
func linearLookup(db *DB, ip net.IP) string {
	for _, e := range db.entries {
		if e.network.Contains(ip) {
			return e.country
		}
	}
	return ""
}

func testRecords() []string {
	return []string{
		"10.0.0.0/8,PRIVATE",
		"10.1.0.0/16,VPN",
		"10.1.2.0/24,OFFICE",
		"192.168.0.0/16,LAN",
		"8.8.8.0/24,US",
		"203.0.113.0/24,TESTNET,TestCity,AS64500",
		"2001:db8::/32,V6DOC",
		"2001:db8:1::/48,V6SUB",
		"2001:4860::/32,GOOGLE",
		"2a00:1450::/29,GOOGLE2",
	}
}

// 索引查询必须与原先的线性扫描结果完全一致，且更具体的网段优先。
func TestIndexedLookupMatchesLinear(t *testing.T) {
	db := New()
	db.loadRecords(testRecords())

	ips := []string{
		"10.1.2.3", "10.1.3.4", "10.2.0.1", "192.168.58.128",
		"8.8.8.8", "8.8.4.4", "203.0.113.9", "1.1.1.1",
		"2001:db8::1", "2001:db8:1::abcd", "2001:db8:2::1",
		"2001:4860:4860::8888", "2a00:1450:4001::1", "2606:4700::1",
	}
	for _, s := range ips {
		ip := net.ParseIP(s)
		got, want := db.Lookup(ip), linearLookup(db, ip)
		if got != want {
			t.Errorf("Lookup(%s) = %q, linear = %q", s, got, want)
		}
	}

	// 显式锁定「具体优先」语义
	if got := db.Lookup(net.ParseIP("10.1.2.3")); got != "OFFICE" {
		t.Errorf("10.1.2.3 should match /24 OFFICE, got %q", got)
	}
	if got := db.Lookup(net.ParseIP("2001:db8:1::abcd")); got != "V6SUB" {
		t.Errorf("2001:db8:1::abcd should match /48 V6SUB, got %q", got)
	}
	// IPv4 地址不应被 IPv6 网段误匹配，反之亦然
	if got := db.Lookup(net.ParseIP("8.8.8.8")); got != "US" {
		t.Errorf("unexpected IPv4 result %q", got)
	}
	if got := db.Lookup(net.ParseIP("2001:4860:4860::8888")); got != "GOOGLE" {
		t.Errorf("unexpected IPv6 result %q", got)
	}
}

// 可选 city/ASN 列走索引后仍能取回对应的元数据。
func TestLookupFullWithIndex(t *testing.T) {
	db := New()
	db.loadRecords(testRecords())
	c, city, asn := db.LookupFull(net.ParseIP("203.0.113.9"))
	if c != "TESTNET" || city != "TestCity" || asn != "AS64500" {
		t.Errorf("LookupFull = %q/%q/%q", c, city, asn)
	}
	c, city, asn = db.LookupFull(net.ParseIP("8.8.8.8"))
	if c != "US" || city != "" || asn != "" {
		t.Errorf("two-column record should have empty meta, got %q/%q/%q", c, city, asn)
	}
}

// Reload（库热更新）后索引必须整体重建，不能残留旧数据。
func TestReloadRebuildsIndex(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/geo.csv"
	write := func(content string) {
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("192.0.2.0/24,OLD\n")
	db := New()
	if _, err := db.Reload(path); err != nil {
		t.Fatal(err)
	}
	if got := db.Lookup(net.ParseIP("192.0.2.1")); got != "OLD" {
		t.Fatalf("before reload: got %q", got)
	}

	write("192.0.2.0/24,NEW\n2001:db8::/32,V6NEW\n")
	if _, err := db.Reload(path); err != nil {
		t.Fatal(err)
	}
	if got := db.Lookup(net.ParseIP("192.0.2.1")); got != "NEW" {
		t.Errorf("stale IPv4 index after reload: %q", got)
	}
	if got := db.Lookup(net.ParseIP("2001:db8::1")); got != "V6NEW" {
		t.Errorf("IPv6 index not rebuilt after reload: %q", got)
	}
	if got := db.Lookup(net.ParseIP("198.51.100.1")); got != "" {
		t.Errorf("unmatched IP should be empty, got %q", got)
	}
}

// Stats / Countries / CIDRsForCountrySplit 在两套地址族混合时统计正确。
func TestStatsMixedFamilies(t *testing.T) {
	db := New()
	db.loadRecords(testRecords())
	total, v4, v6, codes := db.Stats()
	if total != 10 || v4 != 6 || v6 != 4 {
		t.Errorf("stats = total:%d v4:%d v6:%d", total, v4, v6)
	}
	if len(codes) != 10 {
		t.Errorf("country codes = %d, want 10", len(codes))
	}
	v4c, v6c := db.CIDRsForCountrySplit("GOOGLE")
	if len(v4c) != 0 || len(v6c) != 1 || v6c[0] != "2001:4860::/32" {
		t.Errorf("GOOGLE split = v4:%v v6:%v", v4c, v6c)
	}
	v4c, v6c = db.CIDRsForCountrySplit("PRIVATE")
	if len(v4c) != 1 || len(v6c) != 0 {
		t.Errorf("PRIVATE split = v4:%v v6:%v", v4c, v6c)
	}
}
