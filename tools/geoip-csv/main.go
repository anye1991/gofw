// Command geoip-csv 将免费全球 GeoIP 数据源转换为 gofw 的 rules.yaml.geoip 格式。
//
// 输出格式（每行）: CIDR,国家码
//   例: 1.0.0.0/24,CN
// 与 geoip.DB.LoadFromCSV 直接兼容（国家码会被转大写，无需表头）。
//
// 支持的数据源（--format）:
//   sapics    sapics/ip-location-db 的 country-ipv4.csv（start_ip,end_ip,country_code，无表头）
//   ip2location  IP2Location LITE DB11 CSV（带表头，含引号：country_code,country_name,start_ip,end_ip,...）
//   cidr       已为 CIDR,国家码 的中间产物（仅做国家码清洗/去重）
//
// 数据源获取（免费、无需鉴权）:
//   sapics: https://raw.githubusercontent.com/sapics/ip-location-db/master/country-ipv4.csv
//   IP2Location LITE DB11: https://lite.ip2location.com/database-ip-country
//
// 用法:
//   geoip-csv -in country-ipv4.csv -out rules.yaml.geoip -format sapics
//   curl -s URL | geoip-csv -format sapics -out rules.yaml.geoip
package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strings"
)

func main() {
	in := flag.String("in", "", "输入文件（缺省从 stdin 读）")
	out := flag.String("out", "", "输出文件（缺省写到 stdout）")
	format := flag.String("format", "sapics", "输入格式: sapics | ip2location | cidr")
	minPrefix := flag.Int("minprefix", 0, "最小前缀长度下限（如 24 表示合并丢弃小于 /24 的碎片，0=全部保留）")
	flag.Parse()

	var r io.Reader = os.Stdin
	if *in != "" {
		f, err := os.Open(*in)
		if err != nil {
			log.Fatalf("open input: %v", err)
		}
		defer f.Close()
		r = f
	}

	var w io.Writer = os.Stdout
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			log.Fatalf("create output: %v", err)
		}
		defer f.Close()
		w = f
	}

	// code -> set of CIDR 字符串（去重）
	byCode := map[string]map[string]struct{}{}
	add := func(code, cidr string) {
		code = strings.ToUpper(strings.TrimSpace(code))
		cidr = strings.TrimSpace(cidr)
		if code == "" || cidr == "" {
			return
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return
		}
		if *minPrefix > 0 {
			if _, bits := ipMaskBits(cidr); bits < *minPrefix {
				return
			}
		}
		m, ok := byCode[code]
		if !ok {
			m = map[string]struct{}{}
			byCode[code] = m
		}
		m[cidr] = struct{}{}
	}

	switch *format {
	case "sapics":
		parseSapics(r, add)
	case "ip2location":
		parseIP2Location(r, add)
	case "cidr":
		parseCIDR(r, add)
	default:
		log.Fatalf("unknown format: %s", *format)
	}

	// 输出：国家码排序，同国家内 CIDR 字典序排序，确定可预期
	codes := make([]string, 0, len(byCode))
	for c := range byCode {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	bw := bufio.NewWriter(w)
	defer bw.Flush()
	total := 0
	for _, c := range codes {
		cidrs := make([]string, 0, len(byCode[c]))
		for cidr := range byCode[c] {
			cidrs = append(cidrs, cidr)
		}
		sort.Strings(cidrs)
		for _, cidr := range cidrs {
			fmt.Fprintf(bw, "%s,%s\n", cidr, c)
		}
		total += len(cidrs)
	}
	log.Printf("done: %d 个国家/地区, %d 条 CIDR", len(codes), total)
}

// parseSapics: 每行 start_ip,end_ip,country_code（无表头）
func parseSapics(r io.Reader, add func(string, string)) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 3 {
			continue
		}
		start, end, code := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
		emitRange(start, end, code, add)
	}
}

// parseIP2Location: 带表头与引号，country_code,country_name,start_ip,end_ip,...
func parseIP2Location(r io.Reader, add func(string, string)) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	first := true
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Printf("csv read: %v", err)
			return
		}
		if first {
			first = false
			// 跳过表头
			if len(rec) > 0 && strings.EqualFold(strings.Trim(rec[0], "\""), "country_code") {
				continue
			}
		}
		// 找到 start_ip / end_ip / country_code 列（取引号内）
		get := func(i int) string {
			if i >= len(rec) {
				return ""
			}
			return strings.Trim(rec[i], "\"")
		}
		// 列顺序: 0 country_code, 1 country_name, 2 start_ip, 3 end_ip
		code, start, end := get(0), get(2), get(3)
		if code == "" || start == "" || end == "" {
			continue
		}
		emitRange(start, end, code, add)
	}
}

// parseCIDR: 已是 CIDR,国家码
func parseCIDR(r io.Reader, add func(string, string)) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		parts := strings.Split(line, ",")
		if len(parts) < 2 {
			// 可能是空格分隔
			parts = strings.Fields(line)
			if len(parts) < 2 {
				continue
			}
		}
		add(parts[1], parts[0])
	}
}

// emitRange 把 [start,end] 区间无损分解为最少的 CIDR 块后交给 add。
func emitRange(startS, endS, code string, add func(string, string)) {
	start := net.ParseIP(startS)
	end := net.ParseIP(endS)
	if start == nil || end == nil {
		return
	}
	start4 := start.To4()
	end4 := end.To4()
	if start4 == nil || end4 == nil {
		return // 仅支持 IPv4
	}
	s := uint32(start4[0])<<24 | uint32(start4[1])<<16 | uint32(start4[2])<<8 | uint32(start4[3])
	e := uint32(end4[0])<<24 | uint32(end4[1])<<16 | uint32(end4[2])<<8 | uint32(end4[3])
	if e < s {
		return
	}
	for s <= e {
		// 以 s 为起点能取的最大对齐 CIDR
		hostBits := bitsTrailingZeros(s)
		if hostBits > 32 {
			hostBits = 32
		}
		maxSize := uint64(1) << uint(hostBits)
		// 超出区间则缩小
		for maxSize > uint64(e-s)+1 {
			maxSize >>= 1
			hostBits--
		}
		mask := 32 - hostBits
		ip := uint32ToIP(s)
		cidr := fmt.Sprintf("%s/%d", ip.String(), mask)
		add(code, cidr)
		if maxSize == 0 {
			break
		}
		s += uint32(maxSize)
		if s == 0 { // 溢出（覆盖到 255.255.255.255 之后），结束
			break
		}
	}
}

func bitsTrailingZeros(v uint32) int {
	n := 0
	if v == 0 {
		return 32
	}
	for v&1 == 0 {
		n++
		v >>= 1
	}
	return n
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func ipMaskBits(cidr string) (int, int) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return 0, 0
	}
	ones, bits := ipnet.Mask.Size()
	return ones, bits
}
