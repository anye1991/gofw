// Package geoctl 提供地理围栏的运行时统计与临时自动封禁。
// 独立于 engine / enforce，仅依赖标准库，避免包循环引用。
package geoctl

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// Config 自动封禁参数。默认关闭（Enabled=false），避免误伤管理通道。
type Config struct {
	Enabled   bool `json:"enabled"`    // 自动封禁总开关
	Threshold int  `json:"threshold"`  // 窗口内 DROP 次数达到该值即封禁
	WindowSec int  `json:"window_sec"` // 统计窗口（秒）
	BanSec    int  `json:"ban_sec"`    // 封禁时长（秒）
}

func DefaultConfig() Config {
	return Config{Enabled: false, Threshold: 20, WindowSec: 10, BanSec: 300}
}

func (c *Config) normalize() {
	if c.Threshold <= 0 {
		c.Threshold = 20
	}
	if c.WindowSec <= 0 {
		c.WindowSec = 10
	}
	if c.BanSec <= 0 {
		c.BanSec = 300
	}
}

// CountryStat 单个来源国的命中统计。
type CountryStat struct {
	Country string `json:"country"`
	Packets uint64 `json:"packets"`
	Dropped uint64 `json:"dropped"`
}

// Ban 一条封禁记录。
type Ban struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	Reason  string `json:"reason"`  // manual / auto
	Hits    int    `json:"hits"`    // 触发时的窗口内丢弃次数
	Until   int64  `json:"until"`   // 到期 unix 秒；0 表示永久
	Auto    bool   `json:"auto"`    // 是否自动封禁产生
	Enforce bool   `json:"enforce"` // 是否参与实际拦截
}

type countryCounter struct{ packets, dropped uint64 }
type dropWindow struct {
	count int
	start time.Time
}

// Tracker 汇总来源国命中、维护临时封禁表。
// 所有导出方法并发安全；Observe 位于决策热路径，仅持一把短锁。
type Tracker struct {
	mu        sync.Mutex
	cfg       Config
	countries map[string]*countryCounter
	windows   map[string]*dropWindow
	bans      map[string]*Ban
	safe      []*net.IPNet // 永不封禁的网段（管理/内网/回环）
	version   uint64       // 封禁表每次变化自增，供外部判断是否需要重新下发内核
}

func New() *Tracker {
	t := &Tracker{
		cfg:       DefaultConfig(),
		countries: make(map[string]*countryCounter),
		windows:   make(map[string]*dropWindow),
		bans:      make(map[string]*Ban),
	}
	// 默认豁免：回环 + RFC1918 私有网段 + 链路本地。
	// 这些地址既不在 GeoIP 库里，也是本机管理流量来源，封禁它们只会锁死自己。
	for _, s := range []string{
		"127.0.0.0/8", "::1/128",
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"169.254.0.0/16", "fe80::/10", "fc00::/7",
	} {
		if _, n, err := net.ParseCIDR(s); err == nil {
			t.safe = append(t.safe, n)
		}
	}
	return t
}

func (t *Tracker) isSafe(ip net.IP) bool {
	if ip == nil {
		return true
	}
	for _, n := range t.safe {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// AddSafeCIDR 追加永不封禁的网段（如管理网段）。
func (t *Tracker) AddSafeCIDR(cidr string) error {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}
	t.mu.Lock()
	t.safe = append(t.safe, n)
	t.mu.Unlock()
	return nil
}

// Config 返回当前自动封禁配置。
func (t *Tracker) GetConfig() Config {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cfg
}

// SetConfig 更新自动封禁配置。关闭时清除自动产生的封禁项。
func (t *Tracker) SetConfig(c Config) Config {
	c.normalize()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.cfg = c
	if !c.Enabled {
		for k, b := range t.bans {
			if b.Auto {
				delete(t.bans, k)
				t.version++
			}
		}
	}
	return t.cfg
}

// Observe 记录一次决策结果。位于 Decide 热路径末尾，开销为一次短锁。
// 自动封禁仅对「未被豁免」且「非已封禁」的公网源 IP 生效。
func (t *Tracker) Observe(ip net.IP, country, action string, dropped bool) {
	if country == "" {
		country = "??"
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	c := t.countries[country]
	if c == nil {
		c = &countryCounter{}
		t.countries[country] = c
	}
	c.packets++
	if dropped {
		c.dropped++
	}
	if !dropped || !t.cfg.Enabled || ip == nil || t.isSafe(ip) {
		return
	}
	key := ip.String()
	if _, banned := t.bans[key]; banned {
		return
	}
	now := time.Now()
	w := t.windows[key]
	if w == nil || now.Sub(w.start) > time.Duration(t.cfg.WindowSec)*time.Second {
		w = &dropWindow{start: now}
		t.windows[key] = w
	}
	w.count++
	if w.count >= t.cfg.Threshold {
		t.bans[key] = &Ban{
			IP: key, Country: country, Reason: "auto", Hits: w.count,
			Until: now.Add(time.Duration(t.cfg.BanSec) * time.Second).Unix(),
			Auto:  true, Enforce: true,
		}
		delete(t.windows, key)
		t.version++
	}
}

// ObserveBanned 为「已命中封禁」的包补记统计，不重复触发封禁判定。
func (t *Tracker) ObserveBanned(country string) {
	if country == "" {
		country = "??"
	}
	t.mu.Lock()
	c := t.countries[country]
	if c == nil {
		c = &countryCounter{}
		t.countries[country] = c
	}
	c.packets++
	c.dropped++
	t.mu.Unlock()
}

// IsBanned 报告 IP 当前是否处于有效封禁中（过期项会被惰性清理）。
func (t *Tracker) IsBanned(ip net.IP) bool {
	if ip == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	// 兜底：即使封禁表里存在豁免网段（旧数据/外部写入），也绝不对其生效。
	if t.isSafe(ip) {
		return false
	}
	b := t.bans[ip.String()]
	if b == nil {
		return false
	}
	if b.Until > 0 && time.Now().Unix() >= b.Until {
		delete(t.bans, ip.String())
		t.version++
		return false
	}
	return b.Enforce
}

// BanManual 手动封禁一个 IP。ttlSec<=0 表示永久。
// 管理/内网/回环网段一律拒绝封禁——这是防锁死护栏的一部分，
// 手动操作同样不能绕过，否则切到内核模式后会把管理通道自己封掉。
func (t *Tracker) BanManual(ipStr, country string, ttlSec int) (*Ban, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %q", ipStr)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.isSafe(ip) {
		return nil, fmt.Errorf("IP %s 属于永不封禁网段（管理/内网/回环），拒绝封禁", ipStr)
	}
	b := &Ban{IP: ip.String(), Country: country, Reason: "manual", Enforce: true}
	if ttlSec > 0 {
		b.Until = time.Now().Add(time.Duration(ttlSec) * time.Second).Unix()
	}
	t.bans[b.IP] = b
	t.version++
	return b, nil
}

// Unban 解除封禁。
func (t *Tracker) Unban(ipStr string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.bans[ipStr]; ok {
		delete(t.bans, ipStr)
		t.version++
		return true
	}
	return false
}

// Prune 清理过期封禁，返回封禁表是否发生变化。
func (t *Tracker) Prune() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now().Unix()
	changed := false
	for k, b := range t.bans {
		if b.Until > 0 && now >= b.Until {
			delete(t.bans, k)
			changed = true
		}
	}
	if changed {
		t.version++
	}
	return changed
}

// CountryStats 返回来源国命中排行（按包量降序）。
func (t *Tracker) CountryStats() []CountryStat {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]CountryStat, 0, len(t.countries))
	for k, c := range t.countries {
		out = append(out, CountryStat{Country: k, Packets: c.packets, Dropped: c.dropped})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Packets > out[j].Packets })
	return out
}

// Bans 返回当前有效封禁列表（按到期时间降序）。
func (t *Tracker) Bans() []Ban {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now().Unix()
	out := make([]Ban, 0, len(t.bans))
	for _, b := range t.bans {
		if b.Until > 0 && now >= b.Until {
			continue
		}
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Until > out[j].Until })
	return out
}

// Version 返回封禁表变更计数，供外部判断是否需要重新下发内核规则。
func (t *Tracker) Version() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.version
}

// ActiveBansSplit 返回参与拦截的有效封禁 IP，按地址族分开，
// 供 nftables 分别写入 ipv4_addr / ipv6_addr 集合。
func (t *Tracker) ActiveBansSplit() (v4, v6 []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now().Unix()
	for k, b := range t.bans {
		if !b.Enforce || (b.Until > 0 && now >= b.Until) {
			continue
		}
		ip := net.ParseIP(k)
		if ip == nil || t.isSafe(ip) {
			continue // 内核集合同样不能包含管理/内网/回环地址
		}
		if ip.To4() != nil {
			v4 = append(v4, k)
		} else {
			v6 = append(v6, k)
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return
}
