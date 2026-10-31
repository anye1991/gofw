// Package packet 提供 L2/L3/L4 协议的零拷贝解析。
package packet

import (
	"encoding/binary"
	"net"
)

// 协议常量
const (
	EtherTypeIPv4 uint16 = 0x0800
	EtherTypeIPv6 uint16 = 0x86DD
	EtherTypeARP  uint16 = 0x0806
	EtherTypeVLAN uint16 = 0x8100
	EtherTypeQinQ uint16 = 0x88A8

	ProtoICMP   uint8 = 1
	ProtoTCP    uint8 = 6
	ProtoUDP    uint8 = 17
	ProtoICMPv6 uint8 = 58
	ProtoGRE    uint8 = 47
	ProtoESP    uint8 = 50
	ProtoAH     uint8 = 51

	// IPv6 扩展头
	ProtoHopByHop uint8 = 0
	ProtoRoute    uint8 = 43
	ProtoFrag     uint8 = 44
	ProtoDestOpts uint8 = 60
	ProtoMH       uint8 = 135
	ProtoHIP      uint8 = 139
	ProtoShim6    uint8 = 140

	TCPSyn = 0x02
	TCPAck = 0x10
	TCPFin = 0x01
	TCPRst = 0x04
	TCPPsh = 0x08
	TCPUrg = 0x20
)

// Packet 表示一个解析后的网络包。
type Packet struct {
	Raw   []byte
	Iface string

	// L2
	DstMAC net.HardwareAddr
	SrcMAC net.HardwareAddr
	Ether  uint16
	VLAN   uint16 // 0 表示无 VLAN

	// L3
	SrcIP    net.IP
	DstIP    net.IP
	Proto    uint8
	TTL      uint8
	ID       uint32 // IP 标识（用于分片重组；IPv6 为 32 位）
	L3Offset int    // 三层头在 Raw 中的偏移（含 VLAN）
	L4Offset int    // 四层头在 Raw 中的偏移（含 VLAN + L3 + 扩展头）

	// L4
	SrcPort  uint16
	DstPort  uint16
	TCPFlags uint8
	IsIPv6   bool

	// 分片
	MoreFrag   bool
	FragOffset uint16
	IsFragment bool

	HasL4 bool
}

// Parse 解析以太网帧。
func (p *Packet) Parse(data []byte, iface string) {
	p.Raw = data
	p.Iface = iface
	p.HasL4 = false
	p.SrcIP = nil
	p.DstIP = nil
	p.Proto = 0
	p.SrcPort = 0
	p.DstPort = 0
	p.TCPFlags = 0
	p.IsIPv6 = false
	p.MoreFrag = false
	p.FragOffset = 0
	p.IsFragment = false
	p.VLAN = 0
	p.ID = 0
	p.L3Offset = 0
	p.L4Offset = 0

	if len(data) < 14 {
		return
	}
	p.DstMAC = net.HardwareAddr(data[0:6])
	p.SrcMAC = net.HardwareAddr(data[6:12])
	etype := binary.BigEndian.Uint16(data[12:14])
	payload := data[14:]

	// 处理 VLAN (802.1Q) 和 QinQ (802.1ad)
	for etype == EtherTypeVLAN || etype == EtherTypeQinQ {
		if len(payload) < 4 {
			return
		}
		p.VLAN = binary.BigEndian.Uint16(payload[0:2]) & 0x0FFF
		etype = binary.BigEndian.Uint16(payload[2:4])
		payload = payload[4:]
	}
	p.Ether = etype

	switch etype {
	case EtherTypeIPv4:
		p.parseIPv4(payload)
	case EtherTypeIPv6:
		p.parseIPv6(payload)
	}
}

func (p *Packet) parseIPv4(b []byte) {
	if len(b) < 20 {
		return
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return
	}
	l3off := len(p.Raw) - len(b)
	p.L3Offset = l3off
	p.SrcIP = net.IP(b[12:16])
	p.DstIP = net.IP(b[16:20])
	p.Proto = b[9]
	p.TTL = b[8]
	p.ID = uint32(binary.BigEndian.Uint16(b[4:6]))

	flagsFrag := binary.BigEndian.Uint16(b[6:8])
	p.MoreFrag = flagsFrag&0x2000 != 0
	p.FragOffset = (flagsFrag & 0x1FFF) * 8
	p.IsFragment = p.MoreFrag || p.FragOffset != 0

	// 分片与非分片的 L4 payload 都从 IP 头之后开始
	p.L4Offset = l3off + ihl
	if p.IsFragment {
		return
	}
	p.parseL4(b[ihl:], p.Proto)
}

func (p *Packet) parseIPv6(b []byte) {
	if len(b) < 40 {
		return
	}
	p.IsIPv6 = true
	l3off := len(p.Raw) - len(b)
	p.L3Offset = l3off
	p.SrcIP = net.IP(b[8:24])
	p.DstIP = net.IP(b[24:40])
	p.Proto = b[6]
	p.TTL = b[7]

	nh := p.Proto
	off := 40
	// 扩展头链表
	for isExtHeader(nh) {
		if len(b[off:]) < 2 {
			return
		}
		next := b[off]
		hdrLen := 8
		if nh != ProtoFrag {
			hdrLen = (int(b[off+1]) + 1) * 8
		}
		if len(b[off:]) < hdrLen {
			return
		}
		// 分片扩展头携带分片信息
		if nh == ProtoFrag && len(b[off:]) >= 8 {
			frag := binary.BigEndian.Uint16(b[off+2 : off+4])
			p.MoreFrag = frag&0x0001 != 0
			p.FragOffset = (frag >> 3) * 8
			p.IsFragment = p.MoreFrag || p.FragOffset != 0
			p.ID = binary.BigEndian.Uint32(b[off+4 : off+8])
			if p.IsFragment {
				// 分片 payload 紧随分片扩展头之后
				p.L4Offset = l3off + off + hdrLen
				return
			}
		}
		off += hdrLen
		nh = next
	}
	p.L4Offset = l3off + off
	p.Proto = nh
	p.parseL4(b[off:], nh)
}

func isExtHeader(nh uint8) bool {
	switch nh {
	case ProtoHopByHop, ProtoRoute, ProtoFrag, ProtoDestOpts, ProtoAH, ProtoESP, ProtoMH, ProtoHIP, ProtoShim6:
		return true
	}
	return false
}

func (p *Packet) parseL4(b []byte, proto uint8) {
	switch proto {
	case ProtoTCP:
		if len(b) < 20 {
			return
		}
		p.SrcPort = binary.BigEndian.Uint16(b[0:2])
		p.DstPort = binary.BigEndian.Uint16(b[2:4])
		dataOff := int(b[12]>>4) * 4
		if dataOff < 20 {
			return
		}
		p.TCPFlags = b[13] & 0x3f
		p.HasL4 = true
	case ProtoUDP:
		if len(b) < 8 {
			return
		}
		p.SrcPort = binary.BigEndian.Uint16(b[0:2])
		p.DstPort = binary.BigEndian.Uint16(b[2:4])
		p.HasL4 = true
	case ProtoICMP, ProtoICMPv6:
		p.HasL4 = true
	}
}

// Summary 返回包的可读摘要。
func (p *Packet) Summary() string {
	s := p.Iface + " " + p.SrcMAC.String() + "->" + p.DstMAC.String() + " "
	if p.VLAN != 0 {
		s += "vlan" + itoa(int(p.VLAN)) + " "
	}
	if p.SrcIP != nil {
		s += p.SrcIP.String() + "->" + p.DstIP.String() + " "
		switch p.Proto {
		case ProtoTCP:
			s += "TCP " + itoa(int(p.SrcPort)) + "->" + itoa(int(p.DstPort)) + " [" + tcpFlagsStr(p.TCPFlags) + "]"
		case ProtoUDP:
			s += "UDP " + itoa(int(p.SrcPort)) + "->" + itoa(int(p.DstPort))
		case ProtoICMP, ProtoICMPv6:
			s += "ICMP"
		default:
			s += "proto=" + itoa(int(p.Proto))
		}
		if p.IsFragment {
			s += " frag"
		}
	} else {
		s += "ethtype=0x" + hex16(p.Ether)
	}
	return s
}

func tcpFlagsStr(f uint8) string {
	if f == 0 {
		return "NONE"
	}
	var out []byte
	if f&TCPSyn != 0 {
		out = append(out, "SYN,"...)
	}
	if f&TCPAck != 0 {
		out = append(out, "ACK,"...)
	}
	if f&TCPFin != 0 {
		out = append(out, "FIN,"...)
	}
	if f&TCPRst != 0 {
		out = append(out, "RST,"...)
	}
	if f&TCPPsh != 0 {
		out = append(out, "PSH,"...)
	}
	if f&TCPUrg != 0 {
		out = append(out, "URG,"...)
	}
	return string(out[:len(out)-1])
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func hex16(v uint16) string {
	const hex = "0123456789abcdef"
	return string([]byte{hex[v>>12], hex[(v>>8)&0xf], hex[(v>>4)&0xf], hex[v&0xf]})
}
