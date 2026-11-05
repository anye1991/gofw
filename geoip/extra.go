package geoip

import (
	"net"
	"net/netip"
	"sort"
	"strings"
)

// GeoMeta 是 IP 库可选的扩展元数据（城市 / 自治域 / 运营商）。
// 标准库文件格式为 "CIDR,country"（两列）；若额外提供
// "CIDR,country,city,asn" 三/四列，则自动带出，供上层做更细粒度策略。
// 两列库时 City/ASN 为空字符串，属正常情况，不影响任何现有功能。
type GeoMeta struct {
	City string `json:"city"`
	ASN  string `json:"asn"`
}

// Stats 返回库的汇总：总条目、IPv4 条目、IPv6 条目、已收录国家码（升序）。
// 数据在加载时预计算，这里只做只读返回，避免后台轮询全表扫描。
func (db *DB) Stats() (total, v4, v6 int, countries []string) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.statTotal, db.statV4, db.statV6, db.statCodes
}

// Countries 返回库中全部国家码及其条目数（按国家码升序）。
// 供后台「国家选择」下拉直接使用，避免前端硬编码国家列表。
func (db *DB) Countries() []map[string]interface{} {
	db.mu.RLock()
	defer db.mu.RUnlock()
	return db.countryList
}

// CIDRsForCountrySplit 返回指定国家的网段，并按地址族分开。
// IPv4 网段用于 nftables 的 ipv4_addr 集合，IPv6 网段用于 ipv6_addr 集合；
// 两者不能混在同一个 set 里，因此执行层必须分开声明。
func (db *DB) CIDRsForCountrySplit(code string) (v4, v6 []string) {
	code = strings.ToUpper(strings.TrimSpace(code))
	if code == "" {
		return nil, nil
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	if !db.loaded {
		return nil, nil
	}
	for _, e := range db.entries {
		if e.country != code {
			continue
		}
		s := e.network.String()
		if e.network.IP.To4() == nil {
			v6 = append(v6, s)
		} else {
			v4 = append(v4, s)
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return dedup(v4), dedup(v6)
}

func dedup(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

// LookupFull 查询 IP 的国家码，以及库中可选的城市 / ASN 元数据。
// 供城市级、ASN/运营商级策略接入使用；库为两列时后两项为空。
func (db *DB) LookupFull(ip net.IP) (country, city, asn string) {
	if ip == nil {
		return "", "", ""
	}
	db.mu.RLock()
	defer db.mu.RUnlock()
	pe := db.lookupEntry(ip)
	if pe == nil {
		return "", "", ""
	}
	// 仅在库确实带扩展列时才重建 CIDR key，避免百万级条目常驻额外字符串。
	if len(db.meta) == 0 {
		return pe.country, "", ""
	}
	key := netip.PrefixFrom(pe.addr, pe.bits).String()
	m := db.meta[key]
	return pe.country, m.City, m.ASN
}
