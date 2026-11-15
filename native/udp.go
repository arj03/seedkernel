// The UDP socket primitive exposed to QuickJS as `__udp`: the platform's raw datagrams
// (services/datagrams.ts `RawDatagrams`), which the host lends the transport. A socket is
// on the port asked for, or one the OS picks, dual-stack where the machine has IPv6. Its
// reader goroutine holds what it reads until the loop takes it, and the loop hands each
// batch to the callback the socket was bound with in one call, as `[n u8][ip n][port u16][len u16][bytes]` per
// datagram, n 4 for IPv4 and 16 for IPv6: the transport's connection (quic.js) reads and
// acks once a turn, so a crossing per turn is all it needs.
package main

import (
	"bytes"
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

	// Where the kernel takes a run of datagrams as one send (udp_linux.go, udp_windows.go):
	// the run's buffer and control message, kept, since only the loop goroutine sends.
	gso bool
	run []byte
	oob [32]byte
}

// A run sent as one fits one UDP payload, and the kernel cuts at most 64 (UDP_MAX_SEGMENTS).
const (
	gsoMaxSegs  = 64
	gsoMaxBytes = 65000
	// What a socket reads before it asks for coalesced reads, and the buffer that takes
	// them: a socket that carries a path gets there, and a hard NAT's hundreds of probing
	// sockets keep their small buffers.
	groAfter = 32
	groBuf   = 1 << 16
)

// datagramAt reads the datagram of a send batch at `at` (`[socket u32][host][port u16][len
// u16][bytes]`), answering where the next begins. The host is as the batch spells it.
func datagramAt(b []byte, at int) (id int64, host []byte, port uint16, data []byte, end int) {
	n := int(b[at+4])
	p := at + 5 + n
	if n == 0 {
		p = at + 6 + int(b[at+5])
	}
	port, end = binary.BigEndian.Uint16(b[p:]), p+4+int(binary.BigEndian.Uint16(b[p+2:]))
	return int64(binary.BigEndian.Uint32(b[at:])), b[at+4 : p], port, b[p+4 : end], end
}

// sendRun sends `first`, to `to`, with what follows it from `at` that can go in one buffer:
// the same socket, host and port, none longer than first, a shorter one last. It answers
// where the run ended.
func (s *udpSock) sendRun(b []byte, at int, id int64, host []byte, port uint16, first []byte, to netip.AddrPort) int {
	run := append(s.run[:0], first...)
	for segs := 1; segs < gsoMaxSegs && at < len(b) && len(run)+len(first) <= gsoMaxBytes; segs++ {
		nid, nhost, nport, next, end := datagramAt(b, at)
		if nid != id || nport != port || len(next) == 0 || len(next) > len(first) || !bytes.Equal(nhost, host) {
			break
		}
		run = append(run, next...)
		at = end
		if len(next) < len(first) {
			break
		}
	}
	s.run = run
	if len(run) == len(first) {
		s.conn.WriteToUDPAddrPort(first, to)
		return at
	}
	if _, _, err := s.conn.WriteMsgUDPAddrPort(run, gsoOOB(s.oob[:], len(first)), to); gsoRefused(err) {
		s.gso = false
		for o := 0; o < len(run); o += len(first) {
			s.conn.WriteToUDPAddrPort(run[o:min(o+len(first), len(run))], to)
		}
	}
	return at
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
		s := &udpSock{conn: conn, deliver: args[0].Dup(), gso: gsoCapable(conn)}
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
	// an IPv4 socket among them. An address is sent to at once, from a view of the batch,
	// and a run of datagrams to it in one syscall where the kernel cuts them (sendRun); a
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
			id, host, port, data, end := datagramAt(b, at)
			if id != sid {
				s, sid = u.get(id), id
			}
			at = end
			if s == nil {
				continue
			}
			if ip, ok := netip.AddrFromSlice(host[1:]); ok && host[0] != 0 {
				to := netip.AddrPortFrom(ip, port)
				if s.gso && len(data) > 0 {
					at = s.sendRun(b, at, id, host, port, data, to)
				} else {
					s.conn.WriteToUDPAddrPort(data, to)
				}
				continue
			}
			conn, name, copied := s.conn, string(host[2:]), append([]byte(nil), data...)
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
	var oob [64]byte
	for k := 0; ; k++ {
		if k == groAfter && enableGRO(s.conn) {
			buf = make([]byte, groBuf)
		}
		n, oobn, _, from, err := s.conn.ReadMsgUDPAddrPort(buf, oob[:])
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		// A coalesced read is a run of one sender's datagrams of seg bytes, the last shorter.
		seg := n
		if g := groSize(oob[:oobn]); g > 0 && g < n {
			seg = g
		}
		// IPv4 as itself, though a dual-stack socket hears it as IPv4-mapped IPv6. Read
		// through an array, since AsSlice allocates per datagram.
		addr := from.Addr().Unmap()
		a16 := addr.As16()
		ip := a16[:]
		if addr.Is4() {
			ip = a16[12:]
		}
		count := 1
		if seg > 0 {
			count = (n + seg - 1) / seg
		}
		size := int64(count*(5+len(ip)) + n)
		if u.held.Add(size) > u.heldMax.Load() {
			u.held.Add(-size)
			continue
		}
		s.mu.Lock()
		if s.held == nil {
			s.held = u.batches.Get().(*[]byte)
		}
		h := *s.held
		for at, i := 0, 0; i < count; i++ {
			d := buf[at:min(at+seg, n)]
			at += len(d)
			h = append(h, byte(len(ip)))
			h = append(h, ip...)
			h = binary.BigEndian.AppendUint16(h, from.Port())
			h = binary.BigEndian.AppendUint16(h, uint16(len(d)))
			h = append(h, d...)
		}
		*s.held = h
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
