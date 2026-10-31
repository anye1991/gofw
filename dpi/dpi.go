// Package dpi 实现深度包检测，识别应用层协议。
package dpi

import (
	"bytes"
	"strings"

	"gofw/packet"
)

// Detector 应用层协议检测器。
type Detector struct{}

// NewDetector 创建 DPI 检测器。
func NewDetector() *Detector {
	return &Detector{}
}

// Detect 识别包的应用层协议。返回协议名（小写），未识别返回空字符串。
func (d *Detector) Detect(p *packet.Packet) string {
	if p == nil || p.Raw == nil {
		return ""
	}
	// 需要 L4 payload
	if !p.HasL4 || p.L4Offset <= 0 || p.L4Offset >= len(p.Raw) {
		return ""
	}
	// 提取 L7 payload（跳过 L4 头）
	payload := l7Payload(p)
	if len(payload) == 0 {
		return ""
	}

	switch p.Proto {
	case packet.ProtoTCP:
		return detectTCP(payload, p.SrcPort, p.DstPort)
	case packet.ProtoUDP:
		return detectUDP(payload, p.SrcPort, p.DstPort)
	}
	return ""
}

// l7Payload 提取应用层 payload，跳过 TCP/UDP 头。
func l7Payload(p *packet.Packet) []byte {
	l4 := p.Raw[p.L4Offset:]
	switch p.Proto {
	case packet.ProtoTCP:
		if len(l4) < 20 {
			return nil
		}
		dataOff := int(l4[12]>>4) * 4
		if dataOff < 20 || dataOff > len(l4) {
			return nil
		}
		return l4[dataOff:]
	case packet.ProtoUDP:
		if len(l4) < 8 {
			return nil
		}
		return l4[8:]
	}
	return l4
}

// detectTCP 基于端口和 payload 特征识别 TCP 应用协议。
func detectTCP(payload []byte, sport, dport uint16) string {
	// 先按 payload 特征匹配（更准确）
	if isHTTP(payload) {
		return "http"
	}
	if isTLS(payload) {
		return "tls"
	}
	if isSSH(payload) {
		return "ssh"
	}
	if isFTP(payload) {
		return "ftp"
	}
	if isSMTP(payload) {
		return "smtp"
	}
	if isMySQL(payload) {
		return "mysql"
	}
	// 回退到端口匹配
	switch dport {
	case 80, 8080, 8000, 8888:
		return "http"
	case 443, 8443:
		return "tls"
	case 22:
		return "ssh"
	case 21:
		return "ftp"
	case 25, 587:
		return "smtp"
	case 110, 995:
		return "pop3"
	case 143, 993:
		return "imap"
	case 3306:
		return "mysql"
	case 5432:
		return "postgresql"
	case 6379:
		return "redis"
	case 27017:
		return "mongodb"
	}
	switch sport {
	case 80, 8080, 8000, 8888:
		return "http"
	case 443, 8443:
		return "tls"
	case 22:
		return "ssh"
	}
	return ""
}

// detectUDP 基于端口和 payload 特征识别 UDP 应用协议。
func detectUDP(payload []byte, sport, dport uint16) string {
	if isDNS(payload) {
		return "dns"
	}
	switch dport {
	case 53:
		return "dns"
	case 123:
		return "ntp"
	case 161, 162:
		return "snmp"
	case 5060:
		return "sip"
	}
	return ""
}

// isHTTP 检测 HTTP 请求/响应。
func isHTTP(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	// 请求方法
	methods := [][]byte{[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("DELETE "),
		[]byte("HEAD "), []byte("OPTIONS "), []byte("PATCH "), []byte("CONNECT ")}
	for _, m := range methods {
		if bytes.HasPrefix(b, m) {
			return true
		}
	}
	// 响应
	if bytes.HasPrefix(b, []byte("HTTP/")) {
		return true
	}
	return false
}

// isTLS 检测 TLS ClientHello/ServerHello。
func isTLS(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	// TLS record: content_type(1)=0x16(handshake), version(2), length(2)
	if b[0] != 0x16 {
		return false
	}
	// version: TLS 1.0=0x0301, 1.1=0x0302, 1.2=0x0303, 1.3=0x0304
	if b[1] != 0x03 {
		return false
	}
	return true
}

// isSSH 检测 SSH 握手（"SSH-" 前缀）。
func isSSH(b []byte) bool {
	return bytes.HasPrefix(b, []byte("SSH-"))
}

// isFTP 检测 FTP。
func isFTP(b []byte) bool {
	s := string(b)
	if len(s) > 0 && (s[0] >= '0' && s[0] <= '9') {
		// FTP 响应码
		return strings.HasPrefix(s, "220") || strings.HasPrefix(s, "331") || strings.HasPrefix(s, "230")
	}
	return strings.HasPrefix(s, "USER ") || strings.HasPrefix(s, "PASS ")
}

// isSMTP 检测 SMTP。
func isSMTP(b []byte) bool {
	s := string(b)
	return strings.HasPrefix(s, "220 ") || strings.HasPrefix(s, "EHLO ") || strings.HasPrefix(s, "HELO ")
}

// isDNS 检测 DNS 报文。
func isDNS(b []byte) bool {
	if len(b) < 12 {
		return false
	}
	// DNS header: ID(2), flags(2), qdcount(2), ancount(2), nscount(2), arcount(2)
	// flags 的 QR 位（第 15 位）为 0 表示查询，1 表示响应
	// 简化检查：qdcount 应在合理范围内
	qdcount := uint16(b[4])<<8 | uint16(b[5])
	return qdcount > 0 && qdcount < 100
}

// isMySQL 检测 MySQL 协议（基于握手包特征）。
// MySQL 包结构: payload_length(3 字节, 小端) + sequence_id(1 字节) + payload
// 握手阶段两种典型报文：
//  1. 服务端问候包(Server Greeting): protocol_version=0x0a，后接服务器版本字符串
//  2. 客户端认证响应包(Handshake Response): capability_flags 含 CLIENT_PROTOCOL_41(0x200)，
//     max_packet_size 合理，随后 23 字节保留位为 0
func isMySQL(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	// 解析 payload 长度（3 字节小端）
	payloadLen := uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
	if payloadLen == 0 || 4+int(payloadLen) > len(b) {
		return false
	}
	// 握手阶段 sequence id 通常为 0（server greeting）或 1（client response）
	if b[3] > 2 {
		return false
	}
	payload := b[4:]

	// 情况 1: 服务端问候包 - protocol version = 0x0a (10)
	if len(payload) >= 2 && payload[0] == 0x0a {
		// 紧随其后应为服务器版本字符串（以数字或 'M'(MariaDB) 开头）
		c := payload[1]
		if (c >= '0' && c <= '9') || c == 'M' {
			return true
		}
	}

	// 情况 2: 客户端认证响应包
	if len(payload) >= 32 {
		// capability flags (4 字节小端)
		capFlags := uint32(payload[0]) | uint32(payload[1])<<8 |
			uint32(payload[2])<<16 | uint32(payload[3])<<24
		// 必须设置 CLIENT_PROTOCOL_41 (0x00000200)
		if capFlags&0x00000200 == 0 {
			return false
		}
		// max_packet_size (4 字节小端)，合理范围 (0, 0xffffff]
		maxPacket := uint32(payload[4]) | uint32(payload[5])<<8 |
			uint32(payload[6])<<16 | uint32(payload[7])<<24
		if maxPacket == 0 || maxPacket > 0xffffff {
			return false
		}
		// payload[9:32] 应为 23 字节保留零
		for i := 9; i < 32; i++ {
			if payload[i] != 0 {
				return false
			}
		}
		return true
	}
	return false
}
