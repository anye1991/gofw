// Package capture 基于 AF_PACKET raw socket 实现高性能抓包。
package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"gofw/packet"
)

// Capture 抓包器。
type Capture struct {
	iface    string
	fd       int
	stop     chan struct{}
	stopOnce sync.Once
}

// MultiCapture 多网卡抓包器：从多个接口抓包并合并到一个 channel。
type MultiCapture struct {
	caps     []*Capture
	ifaces   []string
	stop     chan struct{}
	stopOnce sync.Once
}

// NewMulti 创建多网卡抓包器。
func NewMulti(ifaces []string) *MultiCapture {
	return &MultiCapture{ifaces: ifaces, stop: make(chan struct{})}
}

// Open 打开所有接口的 raw socket。
func (m *MultiCapture) Open() error {
	for _, iface := range m.ifaces {
		c := New(iface)
		if err := c.Open(); err != nil {
			// 回滚已打开的
			for _, opened := range m.caps {
				opened.Close()
			}
			return fmt.Errorf("open %s: %w", iface, err)
		}
		m.caps = append(m.caps, c)
	}
	return nil
}

// Close 关闭所有抓包器。
func (m *MultiCapture) Close() {
	for _, c := range m.caps {
		c.Close()
	}
}

// Stop 停止所有抓包器。
func (m *MultiCapture) Stop() {
	m.stopOnce.Do(func() {
		close(m.stop)
		for _, c := range m.caps {
			c.Stop()
		}
	})
}

// Packets 合并所有接口的包到一个 channel。
func (m *MultiCapture) Packets(bufSize int) <-chan *packet.Packet {
	ch := make(chan *packet.Packet, 4096)
	var wg sync.WaitGroup
	for _, c := range m.caps {
		wg.Add(1)
		go func(cap *Capture) {
			defer wg.Done()
			for p := range cap.Packets(bufSize) {
				select {
				case ch <- p:
				case <-m.stop:
					ReleasePacket(p)
					return
				}
			}
		}(c)
	}
	go func() {
		wg.Wait()
		close(ch)
	}()
	return ch
}

// bufPool 复用 L4 payload 缓冲区，减少 GC。
var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, 65536)
		return &b
	},
}

// New 创建抓包器。
func New(iface string) *Capture {
	return &Capture{iface: iface, stop: make(chan struct{})}
}

// Open 打开 raw socket 并绑定到网卡。
func (c *Capture) Open() error {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003)))
	if err != nil {
		return err
	}
	c.fd = fd

	iface, err := net.InterfaceByName(c.iface)
	if err != nil {
		syscall.Close(fd)
		return err
	}

	addr := syscall.SockaddrLinklayer{
		Protocol: htons(0x0003),
		Ifindex:  iface.Index,
	}
	if err := syscall.Bind(fd, &addr); err != nil {
		syscall.Close(fd)
		return err
	}

	// 尝试设置混杂模式（失败不致命）
	c.setPromiscuous(iface.Index, true)
	return nil
}

func (c *Capture) setPromiscuous(ifindex int, on bool) {
	var req ifreq
	copy(req.Name[:], c.iface)
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(c.fd), uintptr(syscall.SIOCGIFFLAGS), uintptr(unsafe.Pointer(&req))); errno != 0 {
		return
	}
	flags := *(*uint16)(unsafe.Pointer(&req.Data[0]))
	if on {
		flags |= 0x100 // IFF_PROMISC
	} else {
		flags &^= 0x100
	}
	*(*uint16)(unsafe.Pointer(&req.Data[0])) = flags
	syscall.Syscall(syscall.SYS_IOCTL, uintptr(c.fd), uintptr(syscall.SIOCSIFFLAGS), uintptr(unsafe.Pointer(&req)))
}

// ifreq 对应 Linux struct ifreq。
type ifreq struct {
	Name [16]byte
	Data [24]byte
}

// Close 关闭抓包器。
func (c *Capture) Close() {
	if c.fd >= 0 {
		if iface, err := net.InterfaceByName(c.iface); err == nil {
			c.setPromiscuous(iface.Index, false)
		}
		syscall.Close(c.fd)
		c.fd = -1
	}
}

// Recv 接收一个包。阻塞直到有包或出错。
func (c *Capture) Recv(buf []byte) (int, error) {
	n, _, err := syscall.Recvfrom(c.fd, buf, 0)
	return n, err
}

// isFatalError 判断 Recvfrom 错误是否致命（需退出循环）。
func isFatalError(err error) bool {
	if errors.Is(err, syscall.EBADF) {
		return true
	}
	return false
}

// isTransientError 判断是否为可重试的瞬时错误。
func isTransientError(err error) bool {
	return errors.Is(err, syscall.EINTR) || errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK)
}

// Packets 返回包的迭代 channel。bufSize 为每个包的最大长度。
func (c *Capture) Packets(bufSize int) <-chan *packet.Packet {
	ch := make(chan *packet.Packet, 1024)
	go func() {
		defer close(ch)
		buf := make([]byte, bufSize)
		for {
			select {
			case <-c.stop:
				return
			default:
			}
			n, err := c.Recv(buf)
			if err != nil {
				if isFatalError(err) {
					return
				}
				// 瞬时错误直接重试；其他错误短暂休眠避免 CPU 空转
				if !isTransientError(err) {
					log.Printf("[capture] recv error: %v", err)
					select {
					case <-c.stop:
						return
					case <-time.After(100 * time.Millisecond):
					}
				}
				continue
			}
			if n < 14 {
				continue
			}
			// 从池中取缓冲区，拷贝数据
			bp := bufPool.Get().(*[]byte)
			data := (*bp)[:n]
			copy(data, buf[:n])
			p := &packet.Packet{}
			p.Parse(data, c.iface)
			select {
			case ch <- p:
			case <-c.stop:
				// 停止时把缓冲区还回池中
				bufPool.Put(bp)
				return
			}
		}
	}()
	return ch
}

// ReleasePacket 将包的 Raw 缓冲区归还池中。
// 必须在包不再被任何 goroutine 引用后调用。
func ReleasePacket(p *packet.Packet) {
	if p == nil || p.Raw == nil {
		return
	}
	bp := &p.Raw
	bufPool.Put(bp)
}

// Stop 停止抓包。
func (c *Capture) Stop() {
	c.stopOnce.Do(func() {
		close(c.stop)
	})
}

func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}
