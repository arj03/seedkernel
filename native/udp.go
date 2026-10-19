// The UDP socket primitive exposed to QuickJS as `__udp`, the raw datagrams of the UDP
// path (services/udp/net-udp.ts `RawDatagrams`, which `datagramsOver` shapes). A socket is
// on a port the OS picks, dual-stack where the machine has IPv6. Its reader goroutine holds
// what it reads until the loop takes it, and the loop hands each batch to the callback the
// socket was bound with in one call, as `[n u8][ip n][port u16][len u16][bytes]` per
// datagram, n 4 for IPv4 and 16 for IPv6: the stream (stream.ts) reads and acks once a
// turn, so a crossing per turn is all it needs.
package main

import (
	"encoding/binary"
	"errors"
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
}

type udpSock struct {
	conn    *net.UDPConn
	deliver *qjs.Value // the callback it was bound with, freed on close

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
		s := &udpSock{conn: conn, deliver: args[0].Dup()}
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
			// A delivery still queued finds the socket gone and never reaches it.
			s.deliver.Free()
		}
		return nil, nil
	}))
	// Every address; which are candidates is the shared seam's (datagramsOver).
	o.SetPropertyStr("addresses", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		addrs, _ := net.InterfaceAddrs()
		ips := make([]string, 0, len(addrs))
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				ips = append(ips, n.IP.String())
			}
		}
		return qc.NewString(strings.Join(ips, "\n")), nil
	}))
	qc.Global().SetPropertyStr("__udp", o)
	return u
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
	dispatch(u.qc, "udpHost: dispatcher error", s.deliver, u.qc.NewArrayBuffer(batch))
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
