// The UDP socket primitive exposed to QuickJS as `__udp`: the platform's raw datagrams
// (services/datagrams.ts `RawDatagrams`), which the host lends the transport. A socket is
// on the port asked for, or one the OS picks, dual-stack where the machine has IPv6. Its
// reader goroutine holds what it reads until the loop takes it, and the loop hands each
// batch to the callback the socket was bound with in one call, as `[n u8][ip n][port u16][len u16][bytes]` per
// datagram, n 4 for IPv4 and 16 for IPv6: the transport's connection (quic.js) reads and
// acks once a turn, so a crossing per turn is all it needs.
package main

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"seedkernel/qjs"
)

type udpHost struct {
	el *eventLoop
	qc *qjs.Context

	mu     sync.Mutex
	socks  map[int64]*udpSock
	nextID int64

	// What every socket together holds for the loop, and its ceiling, which the host
	// passes at bind (MAX_UDP_HELD_BYTES): past it a datagram is dropped, as a full socket
	// buffer drops one, and the stream sends it again.
	held    atomic.Int64
	heldMax atomic.Int64

	// Delivered batch buffers, shared by every socket so a burst's buffer is filled again
	// rather than regrown. The GC lets idle ones go, so no socket keeps its largest.
	batches sync.Pool
}

type udpSock struct {
	conn    *net.UDPConn
	deliver qjs.Value // the callback it was bound with, freed on close

	mu     sync.Mutex
	held   *[]byte // datagrams read and not yet delivered, packed, in a pooled buffer
	posted bool    // a delivery is queued on the loop
	task   func() // the delivery the reader posts, made once so posting allocates nothing
}

// exposeUdp installs `__udp`.
func exposeUdp(qc *qjs.Context, el *eventLoop) *udpHost {
	u := &udpHost{el: el, qc: qc, socks: map[int64]*udpSock{}}
	u.batches.New = func() any { return new([]byte) }
	o := qc.NewObject()
	o.SetPropertyStr("bind", qc.Function(func(qc *qjs.Context, args []qjs.Value) (qjs.Value, error) {
		// Go binds [::] dual-stack where the machine has IPv6, and 0.0.0.0 where it has not, on
		// the port asked for, or one the OS picks for 0.
		port := 0
		if len(args) > 3 {
			port = int(args[3].Int32())
		}
		conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: port})
		if err != nil {
			return qjs.Value{}, err
		}
		// The buffers the host asks for; a kernel that caps the size grants what it allows,
		// which is no reason to fail.
		conn.SetReadBuffer(int(args[1].Int64()))
		conn.SetWriteBuffer(int(args[1].Int64()))
		u.heldMax.Store(args[2].Int64())
		s := &udpSock{conn: conn, deliver: args[0].Dup()}
		u.mu.Lock()
		u.nextID++
		id := u.nextID
		u.socks[id] = s
		u.mu.Unlock()
		s.task = func() { u.deliver(id, s) }
		go u.read(id, s)
		r := qc.NewObject()
		r.SetPropertyStr("id", qc.NewInt64(id))
		r.SetPropertyStr("port", qc.NewInt32(int32(conn.LocalAddr().(*net.UDPAddr).Port)))
		return r, nil
	}))
	// A turn's datagrams, `([socket u32][host][port u16][len u16][bytes])*`, which the host
	// has checked: the host `[4][ip 4]` or `[16][ip 16]`, or a name as `[0][len u8][name]`
	// (services/datagrams.ts `datagramEnd`). A send that fails is a lost datagram, IPv6 from
	// an IPv4 socket among them. An address is sent to at once, from a view of the batch; a
	// name is resolved to IPv4 off the loop goroutine, from a copy. A batch is mostly one
	// path's, so a socket is looked up once a run.
	o.SetPropertyStr("send", qc.Function(func(qc *qjs.Context, args []qjs.Value) (qjs.Value, error) {
		b, err := args[0].View()
		if err != nil {
			return qjs.Value{}, err
		}
		var s *udpSock
		sid := int64(-1)
		for at := 0; at < len(b); {
			n := int(b[at+4])
			p := at + 5 + n
			if n == 0 {
				p = at + 6 + int(b[at+5])
			}
			port, end := binary.BigEndian.Uint16(b[p:]), p+4+int(binary.BigEndian.Uint16(b[p+2:]))
			if id := int64(binary.BigEndian.Uint32(b[at:])); id != sid {
				s, sid = u.get(id), id
			}
			bytes, host := b[p+4:end], b[at+5:p]
			at = end
			if s == nil {
				continue
			}
			if ip, ok := netip.AddrFromSlice(host); ok && n != 0 {
				s.conn.WriteToUDPAddrPort(bytes, netip.AddrPortFrom(ip, port))
				continue
			}
			conn, name, copied := s.conn, string(host[1:]), append([]byte(nil), bytes...)
			go func() {
				if to, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(name, strconv.Itoa(int(port)))); err == nil {
					conn.WriteToUDP(copied, to)
				}
			}()
		}
		return qjs.Value{}, nil
	}))
	o.SetPropertyStr("close", qc.Function(func(qc *qjs.Context, args []qjs.Value) (qjs.Value, error) {
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
		return qjs.Value{}, nil
	}))
	// Every address; which are candidates is the transport's (udp.js).
	o.SetPropertyStr("addresses", qc.Function(func(qc *qjs.Context, args []qjs.Value) (qjs.Value, error) {
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
	// Past the largest datagram the path sends (transport/quic/quic.c's 1452), and small, since a
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
		// IPv4 as itself, though a dual-stack socket hears it as IPv4-mapped IPv6. Read
		// through an array, since AsSlice allocates per datagram.
		addr := from.Addr().Unmap()
		a16 := addr.As16()
		ip := a16[:]
		if addr.Is4() {
			ip = a16[12:]
		}
		size := int64(5 + len(ip) + n)
		if u.held.Add(size) > u.heldMax.Load() {
			u.held.Add(-size)
			continue
		}
		s.mu.Lock()
		if s.held == nil {
			s.held = u.batches.Get().(*[]byte)
		}
		h := append(*s.held, byte(len(ip)))
		h = append(h, ip...)
		h = binary.BigEndian.AppendUint16(h, from.Port())
		h = binary.BigEndian.AppendUint16(h, uint16(n))
		*s.held = append(h, buf[:n]...)
		post := !s.posted
		s.posted = true
		s.mu.Unlock()
		if post {
			u.el.post(s.task)
		}
	}
}

// deliver runs on the loop goroutine and hands JS everything held.
func (u *udpHost) deliver(id int64, s *udpSock) {
	s.mu.Lock()
	held := s.held
	s.held, s.posted = nil, false
	s.mu.Unlock()
	batch := *held
	// Released here, whether or not the socket is still there to take it.
	u.held.Add(-int64(len(batch)))
	ab := qjs.Value{}
	if u.get(id) != nil {
		ab = u.qc.NewArrayBuffer(batch)
	}
	// The realm has its own copy, so the buffer goes back for any socket to fill again,
	// without regrowing it.
	*held = batch[:0]
	u.batches.Put(held)
	if !ab.IsZero() {
		dispatch(u.qc, "udpHost: dispatcher error", s.deliver, ab)
	}
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
