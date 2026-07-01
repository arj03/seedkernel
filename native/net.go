// net.go — the Go target's TCP socket primitive: a length-framed, whole-message
// duplex channel (rawChannel) over a raw socket.
//
//	[len u32 BE][bytes]   one PeerLink message per record.
//
// This is the only networking that stays in Go. The
// protocol that used to live here — the PeerLink handshake, the NodeNetwork routing
// table, and the request/response + bulk Transport — now runs as the shared host JS
// (net-link.ts, net-route.ts, net.ts) inside QuickJS, driven over this primitive via
// __net (sock.go). ws.go is the WebSocket twin of this channel. Wire framing is
// byte-identical to the TypeScript so a Go node and a Bun node interop.
package main

import (
	"context"
	"net"
	"sync"
	"time"
)

const maxTCPMessage = 16 << 20 // frame cap (matches the TS MAX_TCP_MESSAGE / WS cap)

// tcpSocketBuffer is the send/receive socket buffer set on every TCP connection
// (dialed and accepted). The request/response traffic pattern leaves idle gaps
// between bursts, which stops the kernel's receive-buffer autotuning from ramping,
// so over a high-RTT link a connection otherwise stalls near the OS default window
// (~64 KiB → only a few MB/s at 27 ms RTT — the bandwidth-delay product is the cap,
// not the link). A fixed generous buffer lifts that ceiling: 4 MiB covers a fast,
// high-RTT link's BDP with headroom.
const tcpSocketBuffer = 4 << 20

// dialTCP dials with SO_RCVBUF/SO_SNDBUF set on the socket BEFORE connect (the
// Dialer's Control hook runs on the raw fd pre-handshake), so the TCP window scale
// advertised in the SYN is sized for the large buffer. Setting the buffer after the
// connection is up is too late to widen the window scale, which otherwise caps a
// high-RTT transfer near the OS-default window.
func dialTCP(addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second, Control: controlSocketBuffers}
	return d.DialContext(context.Background(), "tcp", addr)
}

// ───────────────────────── small byte helpers ─────────────────────────

func putU32BE(b []byte, off int, v uint32) {
	b[off] = byte(v >> 24)
	b[off+1] = byte(v >> 16)
	b[off+2] = byte(v >> 8)
	b[off+3] = byte(v)
}

func getU32BE(b []byte, off int) uint32 {
	return uint32(b[off])<<24 | uint32(b[off+1])<<16 | uint32(b[off+2])<<8 | uint32(b[off+3])
}

// ───────────────────────── RawChannel: a whole-message duplex ─────────────────

// rawChannel delivers whole messages atomically (net-link.ts RawChannel). TCP gets
// message boundaries from a length prefix; WS already has them. A channel owns one
// socket and one read goroutine; send is safe from any goroutine.
//
// onMsg ownership: the read loop hands its onMsg callback a freshly-allocated slice
// that the callee owns — it is never reused by the reader, so the callee may retain it
// without copying. Both implementations honor this (tcpChannel allocates per reassembled
// frame, rawSockChannel per read), so the delivery boundary needs no defensive copy.
type rawChannel interface {
	send(bytes []byte)
	close()
}

// ── tcpChannel: length-prefixed frames over a TCP socket ──────────────────────
//
// The connection may be supplied already-open (an accepted inbound socket) or dialed
// lazily in the background (an outbound dial): until the dial completes, sends buffer
// in `pending`, mirroring how a node:net socket queues writes issued before connect.
type tcpChannel struct {
	onMsg   func([]byte)
	onClose func()

	mu      sync.Mutex
	conn    net.Conn
	pending [][]byte // sends issued before the background dial connected
	open    bool
	dead    bool
}

// newTCPChannelDial returns a channel that connects in the background (the dial
// path): the caller can send immediately and the bytes flush once connected.
func newTCPChannelDial(addr string, onMsg func([]byte), onClose func()) *tcpChannel {
	c := &tcpChannel{onMsg: onMsg, onClose: onClose}
	go func() {
		conn, err := dialTCP(addr)
		if err != nil {
			c.fail()
			return
		}
		c.mu.Lock()
		if c.dead { // closed before the dial landed
			c.mu.Unlock()
			conn.Close()
			return
		}
		c.conn = conn
		c.mu.Unlock()
		c.flushPending() // drain pre-connect sends in order, then open direct writes
		c.readLoop()
	}()
	return c
}

// flushPending drains the pre-connect buffer in send order, then opens the
// direct-write path. open stays false until pending is empty under the lock, so a
// concurrent send() keeps buffering (it never writes) while this goroutine flushes —
// making the dial goroutine the sole writer right up to the handoff. That ordering
// guarantee is the point: a later frame must not overtake an earlier buffered one
// (PeerLink needs its HELLO to land first). Writes stay off the lock so a stuck
// conn.Write still can't block close().
func (c *tcpChannel) flushPending() {
	for {
		c.mu.Lock()
		if c.dead {
			c.mu.Unlock()
			return
		}
		pending := c.pending
		c.pending = nil
		if len(pending) == 0 {
			c.open = true // pending drained under the lock: future sends write directly
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
		for _, b := range pending {
			c.writeFrame(b)
		}
	}
}

func (c *tcpChannel) send(bytes []byte) {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	if !c.open {
		c.pending = append(c.pending, append([]byte(nil), bytes...))
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	c.writeFrame(bytes)
}

func (c *tcpChannel) writeFrame(bytes []byte) {
	// Reject an over-cap frame here rather than letting uint32(len(bytes)) silently wrap
	// (a >4 GiB message would write a truncated length and desync the peer) or shipping a
	// 16 MiB–4 GiB frame the receiver is hardcoded to reject. The read side treats an
	// over-cap length as fatal (readLoop), so mirror it: fail the channel locally instead
	// of provoking the peer to drop the link.
	if len(bytes) > maxTCPMessage {
		c.fail()
		return
	}
	var hdr [4]byte
	putU32BE(hdr[:], 0, uint32(len(bytes)))
	c.mu.Lock()
	conn := c.conn
	dead := c.dead
	c.mu.Unlock()
	if dead || conn == nil {
		return
	}
	// net.Buffers ships the length prefix and the payload with one writev (a single
	// syscall on a TCPConn), so we neither allocate a 4+len(bytes) frame nor copy the
	// whole payload to prepend the header — the biggest saving on the 1 MiB upload path.
	// A TCPConn's fd write lock makes each WriteTo atomic against concurrent sends, so
	// frames on the same socket still can't interleave. WriteTo consumes the slice header
	// it's given (advancing/niling entries), so hand it a fresh local; bytes is untouched.
	iov := net.Buffers{hdr[:], bytes}
	if _, err := iov.WriteTo(conn); err != nil {
		c.fail()
	}
}

// close is the deliberate teardown: it does NOT fire onClose (the owner asked for
// it). A fail() racing behind it stays silent because dead is already set — a
// live-channel error, by contrast, must still reach onClose or the owning PeerLink
// is never forgotten and the peer is blackholed.
func (c *tcpChannel) close() {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	c.dead = true
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

func (c *tcpChannel) fail() {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	c.dead = true
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
	c.onClose()
}

func (c *tcpChannel) readLoop() {
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 64<<10)
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	for {
		n, err := conn.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			// Consume whole frames by advancing an offset, then shift the unread tail
			// back to the front of the SAME backing array. Reslicing buf forward
			// (buf = buf[4+ln:]) instead walks the slice toward the end of its array, so
			// each Read's append keeps reallocating a fresh 64 KiB-class buffer and
			// copying the sliver across — needless churn on a high-throughput link.
			off := 0
			for {
				if len(buf)-off < 4 {
					break
				}
				ln := getU32BE(buf, off)
				if ln > maxTCPMessage {
					c.fail()
					return
				}
				if uint32(len(buf)-off) < 4+ln {
					break
				}
				msg := append([]byte(nil), buf[off+4:off+4+int(ln)]...)
				off += int(4 + ln)
				c.onMsg(msg)
			}
			if off > 0 {
				buf = append(buf[:0], buf[off:]...) // overlap-safe compaction (memmove)
			}
		}
		if err != nil {
			c.fail()
			return
		}
	}
}

// ── rawSockChannel: a raw byte duplex over a TCP socket (no framing) ───────────
//
// The transport under the JS WebSocket codec (net-frame.ts), which does its own
// RFC 6455 framing. Unlike tcpChannel it neither length-prefixes sends nor
// reassembles reads: send writes bytes verbatim, and each socket read is delivered
// as-is (a chunk, not a whole message). Dial/teardown semantics mirror tcpChannel,
// including buffering pre-connect sends so the WS client can write its upgrade
// request the moment the channel is created.
type rawSockChannel struct {
	onMsg   func([]byte)
	onClose func()

	mu      sync.Mutex
	conn    net.Conn
	pending [][]byte // sends issued before the background dial connected
	open    bool
	dead    bool
}

// newRawChannelDial returns a raw byte channel that connects in the background;
// the caller can write immediately and the bytes flush once connected.
func newRawChannelDial(addr string, onMsg func([]byte), onClose func()) *rawSockChannel {
	c := &rawSockChannel{onMsg: onMsg, onClose: onClose}
	go func() {
		conn, err := dialTCP(addr)
		if err != nil {
			c.fail()
			return
		}
		c.mu.Lock()
		if c.dead { // closed before the dial landed
			c.mu.Unlock()
			conn.Close()
			return
		}
		c.conn = conn
		c.mu.Unlock()
		c.flushPending() // drain pre-connect writes in order, then open direct writes
		c.readLoop()
	}()
	return c
}

// flushPending drains the pre-connect buffer in order, then opens the direct-write
// path — same gate-before-open ordering as tcpChannel.flushPending, so the buffered
// WS upgrade request can't be overtaken by a later frame.
func (c *rawSockChannel) flushPending() {
	for {
		c.mu.Lock()
		if c.dead {
			c.mu.Unlock()
			return
		}
		pending := c.pending
		c.pending = nil
		if len(pending) == 0 {
			c.open = true // pending drained under the lock: future sends write directly
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
		for _, b := range pending {
			c.writeRaw(b)
		}
	}
}

func (c *rawSockChannel) send(bytes []byte) {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	if !c.open {
		c.pending = append(c.pending, append([]byte(nil), bytes...))
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	c.writeRaw(bytes)
}

func (c *rawSockChannel) writeRaw(bytes []byte) {
	c.mu.Lock()
	conn, dead := c.conn, c.dead
	c.mu.Unlock()
	if dead || conn == nil {
		return
	}
	if _, err := conn.Write(bytes); err != nil {
		c.fail()
	}
}

// close is the deliberate teardown (no onClose); see tcpChannel.close.
func (c *rawSockChannel) close() {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	c.dead = true
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

func (c *rawSockChannel) fail() {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	c.dead = true
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
	c.onClose()
}

func (c *rawSockChannel) readLoop() {
	chunk := make([]byte, 64<<10)
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	for {
		n, err := conn.Read(chunk)
		if n > 0 {
			c.onMsg(append([]byte(nil), chunk[:n]...))
		}
		if err != nil {
			c.fail()
			return
		}
	}
}
