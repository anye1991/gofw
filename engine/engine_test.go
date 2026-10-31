package engine

import (
	"encoding/binary"
	"net"
	"testing"

	"gofw/config"
	"gofw/packet"
)

func makeTCPSyn(dstPort uint16) []byte {
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:14], 0x0800)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 40)
	binary.BigEndian.PutUint16(ip[6:8], 0x4000)
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], net.ParseIP("10.0.0.5").To4())
	copy(ip[16:20], net.ParseIP("10.0.0.1").To4())
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 54321)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], 1000)
	tcp[12] = 5 << 4
	tcp[13] = 0x02 // SYN
	frame := append(eth, ip...)
	frame = append(frame, tcp...)
	return frame
}

func BenchmarkDecide(b *testing.B) {
	rs, err := config.Load("../rules.yaml")
	if err != nil {
		b.Fatal(err)
	}
	eng := NewEngine(rs)
	frames := make([][]byte, 1000)
	for i := range frames {
		frames[i] = makeTCPSyn(uint16(22 + i%80))
	}
	pkts := make([]*packet.Packet, len(frames))
	for i, f := range frames {
		pkts[i] = &packet.Packet{}
		pkts[i].Parse(f, "bench")
	}
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		eng.Decide(pkts[i%len(pkts)])
	}
}
