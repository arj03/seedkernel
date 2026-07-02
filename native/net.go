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
	"encoding/binary"
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

// ───────────────────────── RawChannel: a whole-message duplex ─────────────────

// rawChannel delivers whole messages atomically (net-link.ts RawChannel). TCP gets
// message boundaries from a length prefix; WS already has them. A channel owns one
// socket and one read goroutine; send is safe from any goroutine.
//
// onMsg ownership: the read loop hands its onMsg callback a freshly-allocated slice
// that the callee owns — it is never reused by the reader, so the callee may retain it
// without copying. Both strategies honor this (framedProto allocates per reassembled
// frame, rawProto per read), so the delivery boundary needs no defensive copy.
type rawChannel interface {
	send(bytes []byte)
	close()
}

// ── sockChannel: the shared connection core (framed or raw) ────────────────────
//
// Both wire shapes are the same connection with a swappable strategy: length-framed
// whole messages (net-link.ts RawChannel over TCP) and a raw byte duplex (the
// transport under the JS WebSocket codec, which does its own RFC 6455 framing). The
// subtle parts live here exactly once — the open/dead lifecycle, the pre-connect
// `pending` buffer with its flush-before-open gate, and the close vs fail split.
// Only how a single send reaches the wire (proto.writeMsg) and how received bytes
// become onMsg deliveries (proto.readLoop) differ between the two.
//
// The connection may be supplied already-open (an accepted inbound socket) or dialed
// lazily in the background (an outbound dial): until the dial completes, sends buffer
// in `pending`, mirroring how a node:net socket queues writes issued before connect.
type sockChannel struct {
	proto   proto
	onMsg   func([]byte)
	onClose func()

	mu      sync.Mutex
	conn    net.Conn
	pending [][]byte // sends issued before the background dial connected
	open    bool
	dead    bool
}

// proto is the framed-vs-raw wire strategy. framedProto length-prefixes each message
// and reassembles whole frames on read; rawProto writes bytes verbatim and delivers
// each socket read as-is (a chunk, not a whole message). Both are zero-size, so the
// interface values framingFor hands out box without allocating.
type proto interface {
	writeMsg(c *sockChannel, bytes []byte) // frame-and-write one send
	readLoop(c *sockChannel)               // the read loop: socket bytes → onMsg
}

// framingFor maps sock.go's raw flag to the wire strategy: raw ⇒ bytes verbatim,
// otherwise length-framed. The returned zero-size value costs no allocation.
func framingFor(raw bool) proto {
	if raw {
		return rawProto{}
	}
	return framedProto{}
}

// newDialChannel returns a channel that connects in the background (the dial path):
// the caller can send immediately and the bytes flush once connected.
func newDialChannel(addr string, p proto, onMsg func([]byte), onClose func()) *sockChannel {
	c := &sockChannel{proto: p, onMsg: onMsg, onClose: onClose}
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
		c.proto.readLoop(c)
	}()
	return c
}

// newInboundChannel wraps an already-open accepted socket: open from the start with
// no pending buffer to drain. The caller starts proto.readLoop once the JS channel
// is registered — see netHost.wrapInbound.
func newInboundChannel(p proto, conn net.Conn, onMsg func([]byte), onClose func()) *sockChannel {
	return &sockChannel{proto: p, onMsg: onMsg, onClose: onClose, conn: conn, open: true}
}

// flushPending drains the pre-connect buffer in send order, then opens the
// direct-write path. open stays false until pending is empty under the lock, so a
// concurrent send() keeps buffering (it never writes) while this goroutine flushes —
// making the dial goroutine the sole writer right up to the handoff. That ordering
// guarantee is the point: a later message must not overtake an earlier buffered one
// (PeerLink needs its HELLO to land first; a WS client its upgrade request). Writes
// stay off the lock so a stuck conn.Write still can't block close().
func (c *sockChannel) flushPending() {
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
			c.proto.writeMsg(c, b)
		}
	}
}

func (c *sockChannel) send(bytes []byte) {
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
	c.proto.writeMsg(c, bytes)
}

// socket snapshots the connection and dead flag under the lock — the guard every
// write path takes before touching the fd (conn may still be nil mid-dial, or already
// closed by close/fail). The read loop uses it too: it runs only after conn is set,
// so it can ignore the dead flag.
func (c *sockChannel) socket() (net.Conn, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.conn, c.dead
}

// close is the deliberate teardown: it does NOT fire onClose (the owner asked for
// it). A fail() racing behind it stays silent because dead is already set — a
// live-channel error, by contrast, must still reach onClose or the owning PeerLink
// is never forgotten and the peer is blackholed.
func (c *sockChannel) close() {
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

// fail is the error teardown: it closes the socket and fires onClose so the owner
// drops the channel. Idempotent against close() and a second fail() via the dead flag.
func (c *sockChannel) fail() {
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

// ── framedProto: length-prefixed frames — [len u32 BE][bytes] per message ──────
type framedProto struct{}

func (framedProto) writeMsg(c *sockChannel, bytes []byte) {
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
	binary.BigEndian.PutUint32(hdr[:], uint32(len(bytes)))
	conn, dead := c.socket()
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

func (framedProto) readLoop(c *sockChannel) {
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 64<<10)
	idle := 0 // consecutive compactions that left most of cap(buf) unused
	conn, _ := c.socket()
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
				ln := binary.BigEndian.Uint32(buf[off:])
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
				// The compaction keeps the backing array, so one 16 MiB frame would pin
				// 16 MiB per connection for its life — a real high-water cost on a node
				// holding many peers after a bulk sync. Snap the capacity back to the
				// tail once 16 consecutive compactions used under a quarter of it.
				// Rate-limiting the shrink matters: doing it per-frame made a sustained
				// stream of large frames realloc-thrash (BenchmarkNetUpload1M: 2.1 →
				// 5.3 MB/op); every 16th frame amortizes that to noise, while a link
				// whose burst has passed still frees its buffer within 16 messages.
				if cap(buf) > 64<<10 && len(buf) < cap(buf)/4 {
					if idle++; idle >= 16 {
						idle = 0
						buf = append(make([]byte, 0, max(len(buf), 4096)), buf...)
					}
				} else {
					idle = 0
				}
			}
		}
		if err != nil {
			c.fail()
			return
		}
	}
}

// ── rawProto: a raw byte duplex — bytes pass through verbatim, no framing ───────
type rawProto struct{}

func (rawProto) writeMsg(c *sockChannel, bytes []byte) {
	conn, dead := c.socket()
	if dead || conn == nil {
		return
	}
	if _, err := conn.Write(bytes); err != nil {
		c.fail()
	}
}

func (rawProto) readLoop(c *sockChannel) {
	chunk := make([]byte, 64<<10)
	conn, _ := c.socket()
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
