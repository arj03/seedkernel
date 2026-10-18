// The UDP socket primitive exposed to QuickJS as `__udp`, the datagram platform of the UDP
// path (services/udp/net-udp.ts `DatagramPlatform`, shaped by host/native-shim.ts). A
// socket is on a port the OS picks, dual-stack where the machine has IPv6. Its reader
// goroutine holds what it reads until the loop takes it, and the loop hands each batch to
// __udpDeliver in one call, as `[n u8][ip n][port u16][len u16][bytes]` per datagram, n 4
// for IPv4 and 16 for IPv6: the stream (stream.ts) reads and acks once a turn, so a
// crossing per turn is all it needs.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"seedkernel/qjs"
)

// udpHeldMax bounds what a socket holds for the loop. Past it a datagram is dropped, as a
// full socket buffer drops one, and the stream sends it again.
const udpHeldMax = 4 << 20

// udpSocketBuffer is the kernel receive and send buffer a socket asks for, as
// services/udp/stream.ts `SOCKET_BUFFER_BYTES`: room for a sender's whole burst, which a
// default buffer (Windows' especially) drops the tail of.
const udpSocketBuffer = 4 << 20

type udpHost struct {
	el *eventLoop
	qc *qjs.Context

	mu     sync.Mutex
	socks  map[int64]*udpSock
	nextID int64

	fnDeliver *qjs.Value
}

type udpSock struct {
	conn *net.UDPConn

	mu     sync.Mutex
	held   []byte // datagrams read and not yet delivered, packed
	posted bool   // a delivery is queued on the loop
}

// exposeUdp installs `__udp`.
func exposeUdp(qc *qjs.Context, el *eventLoop) *udpHost {
	u := &udpHost{el: el, qc: qc, socks: map[int64]*udpSock{}}
	o := qc.NewObject()
	o.SetPropertyStr("bind", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		// Go binds [::] dual-stack where the machine has IPv6, and 0.0.0.0 where it has not.
		conn, err := net.ListenUDP("udp", &net.UDPAddr{})
		if err != nil {
			return nil, err
		}
		// A kernel that caps the size grants what it allows; that is no reason to fail.
		conn.SetReadBuffer(udpSocketBuffer)
		conn.SetWriteBuffer(udpSocketBuffer)
		s := &udpSock{conn: conn}
		u.mu.Lock()
		u.nextID++
		id := u.nextID
		u.socks[id] = s
		u.mu.Unlock()
		go u.read(id, s)
		r := qc.NewObject()
		r.SetPropertyStr("id", qc.NewInt64(id))
		r.SetPropertyStr("port", qc.NewInt32(int32(conn.LocalAddr().(*net.UDPAddr).Port)))
		return r, nil
	}))
	// A send that fails is a lost datagram, IPv6 from an IPv4 socket among them. An address
	// is sent to at once, from a view of the bytes; a name is resolved to IPv4 off the loop
	// goroutine, from a copy.
	o.SetPropertyStr("send", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		s := u.get(args[0].Int64())
		if s == nil {
			return nil, nil
		}
		host, port := args[1].String(), int(args[2].Int32())
		if ip, err := netip.ParseAddr(host); err == nil {
			if b, err := args[3].View(); err == nil {
				s.conn.WriteToUDPAddrPort(b, netip.AddrPortFrom(ip, uint16(port)))
			}
		} else if b, err := args[3].Bytes(); err == nil {
			go func() {
				if to, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, strconv.Itoa(port))); err == nil {
					s.conn.WriteToUDP(b, to)
				}
			}()
		}
		return nil, nil
	}))
	o.SetPropertyStr("close", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		id := args[0].Int64()
		u.mu.Lock()
		s := u.socks[id]
		delete(u.socks, id)
		u.mu.Unlock()
		if s != nil {
			s.conn.Close()
		}
		return nil, nil
	}))
	o.SetPropertyStr("addresses", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		return qc.NewString(strings.Join(localAddresses(), "\n")), nil
	}))
	qc.Global().SetPropertyStr("__udp", o)
	return u
}

// retain picks up the dispatcher host/native-shim.ts defines when the bundle evaluates.
func (u *udpHost) retain() error {
	u.fnDeliver = u.qc.Global().GetPropertyStr("__udpDeliver")
	if u.fnDeliver.IsUndefined() {
		return fmt.Errorf("udp: __udpDeliver not defined (host/native-shim.ts)")
	}
	return nil
}

func (u *udpHost) get(id int64) *udpSock {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.socks[id]
}

// read is a socket's reader goroutine: one queued delivery takes whatever has arrived by
// the time the loop runs it.
func (u *udpHost) read(id int64, s *udpSock) {
	// Past the largest datagram the path sends (stream.ts `MAX_PACKET`), and small, since a
	// hard NAT's end opens hundreds of sockets at once.
	buf := make([]byte, 2048)
	for {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		// IPv4 as itself, though a dual-stack socket hears it as IPv4-mapped IPv6.
		ip := from.Addr().Unmap().AsSlice()
		s.mu.Lock()
		if len(s.held)+5+len(ip)+n > udpHeldMax {
			s.mu.Unlock()
			continue
		}
		s.held = append(s.held, byte(len(ip)))
		s.held = append(s.held, ip...)
		s.held = binary.BigEndian.AppendUint16(s.held, from.Port())
		s.held = binary.BigEndian.AppendUint16(s.held, uint16(n))
		s.held = append(s.held, buf[:n]...)
		post := !s.posted
		s.posted = true
		s.mu.Unlock()
		if post {
			u.el.post(func() { u.deliver(id, s) })
		}
	}
}

// deliver runs on the loop goroutine and hands JS everything held.
func (u *udpHost) deliver(id int64, s *udpSock) {
	s.mu.Lock()
	batch := s.held
	s.held, s.posted = nil, false
	s.mu.Unlock()
	if u.get(id) == nil {
		return
	}
	dispatch(u.qc, "udpHost: dispatcher error", u.fnDeliver, u.qc.NewInt64(id), u.qc.NewArrayBuffer(batch))
}

// close tears the sockets down with their realm.
func (u *udpHost) close() {
	u.mu.Lock()
	socks := u.socks
	u.socks = map[int64]*udpSock{}
	u.mu.Unlock()
	for _, s := range socks {
		s.conn.Close()
	}
}

// localAddresses is this machine's outward IPv4 addresses, or loopback on one with none,
// then its IPv6 ones but loopback and link-local, as services/udp/node.ts answers.
func localAddresses() []string {
	addrs, _ := net.InterfaceAddrs()
	var outward, all, v6 []string
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		if n.IP.To4() == nil {
			if !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
				v6 = append(v6, n.IP.String())
			}
			continue
		}
		all = append(all, n.IP.String())
		if !n.IP.IsLoopback() {
			outward = append(outward, n.IP.String())
		}
	}
	if len(outward) > 0 {
		all = outward
	}
	return append(all, v6...)
}
