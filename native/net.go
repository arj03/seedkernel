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
	"runtime"
	"sync"
	"time"
)

const maxTCPMessage = 16 << 20 // frame cap (matches the TS MAX_TCP_MESSAGE / WS cap)

// sendQueueLimit caps the bytes a channel buffers for its writer goroutine. The JS
// protocol is request/response — even the 1 MiB bulk upload path awaits an ack per
// chunk — so a healthy link's queue stays a few messages deep; hitting the cap means
// the peer has stopped draining (or JS is pushing unpaced), and the channel fails
// rather than buffering without bound. Must exceed maxTCPMessage or a single
// max-size frame could never be queued.
const sendQueueLimit = 32 << 20

// closeGrace bounds how long a deliberate close() lets the writer flush queued
// sends (a PeerLink rejection, a WS close frame) before the socket is torn down
// regardless — so closing a channel to a wedged peer can't pin its writer forever.
const closeGrace = 5 * time.Second

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
// socket, one read goroutine, and one writer goroutine; send only queues (it is safe
// from any goroutine and never blocks on the socket) and takes ownership of its
// slice — the caller must not reuse it.
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
// subtle parts live here exactly once — the writer goroutine with its bounded queue,
// the dead lifecycle, and the close vs fail split. Only how a single send reaches
// the wire (proto.writeMsg) and how received bytes become onMsg deliveries
// (proto.readLoop) differ between the two.
//
// Writes never run on the caller's goroutine: send() only queues, and the channel's
// writer goroutine (writeLoop) owns every socket write. The caller is the event-loop
// goroutine (sock.go N.send), which owns ALL QuickJS execution — so a peer that
// stops draining (its receive window closed, our 4 MiB send buffer full) must not
// block a send there: a synchronous conn.Write would freeze every timer (including
// the JS Transport request timeouts that are supposed to bound exactly this) and
// every other channel until that one peer drained. node:net, which the shared JS was
// written against, has the same shape — socket.write buffers in userspace and
// returns. The queue is bounded (sendQueueLimit; a full queue fails the channel) and
// doubles as the pre-connect buffer: the writer only starts once the background dial
// lands, so earlier sends wait in order — a later message can never overtake an
// earlier one (PeerLink needs its HELLO to land first; a WS client its upgrade
// request), because one writer drains one FIFO.
type sockChannel struct {
	proto   proto
	onMsg   func([]byte)
	onClose func()

	mu     sync.Mutex
	conn   net.Conn // set at most once, under mu, strictly before the writer/reader goroutines start (they read it lock-free); close/fail Close() it but never reassign
	queue  [][]byte // sends awaiting the writer, in order (also buffers pre-connect sends)
	queued int      // bytes held in queue — the sendQueueLimit accounting
	dead   bool

	wake chan struct{} // cap 1: nudges the writer after queue/dead change; coalesces bursts
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
	c := &sockChannel{proto: p, onMsg: onMsg, onClose: onClose, wake: make(chan struct{}, 1)}
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
		go c.writeLoop() // started only after conn is set; drains pre-connect sends in order
		c.proto.readLoop(c)
	}()
	return c
}

// newInboundChannel wraps an already-open accepted socket: its writer starts
// immediately. The caller starts proto.readLoop once the JS channel is registered —
// see netHost.wrapInbound.
func newInboundChannel(p proto, conn net.Conn, onMsg func([]byte), onClose func()) *sockChannel {
	c := &sockChannel{proto: p, onMsg: onMsg, onClose: onClose, conn: conn, wake: make(chan struct{}, 1)}
	go c.writeLoop()
	return c
}

// send queues bytes for the writer goroutine and returns immediately; it never
// touches the socket. It takes ownership of bytes (the one caller, sock.go's N.send,
// hands over a fresh JsTypedArrayToGo copy), so nothing is copied here. A send on a
// dead channel is dropped silently, like a node:net write after destroy.
func (c *sockChannel) send(bytes []byte) {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	if c.queued+len(bytes) > sendQueueLimit {
		c.mu.Unlock()
		// The peer has stopped draining (the JS protocol acks even bulk chunks, so a
		// healthy queue stays shallow): fail the channel instead of buffering forever.
		// On its own goroutine because send runs on the loop goroutine and fail's
		// onClose posts to el.tasks — which can be full, and only the loop drains it.
		go c.fail()
		return
	}
	c.queue = append(c.queue, bytes)
	c.queued += len(bytes)
	c.mu.Unlock()
	c.signal()
	// Hand the processor to the freshly-woken writer (it sits in this P's runnext
	// slot) so the frame hits the wire now, overlapping with the rest of the sender's
	// JS turn, instead of waiting for the loop goroutine to park at end of turn —
	// worth ~10% round-trip latency and upload throughput on the Net benches. A
	// scheduling hint only: correctness never depends on when the writer runs.
	runtime.Gosched()
}

// signal nudges the writer without blocking: the cap-1 buffer coalesces bursts, and
// the writer re-checks queue+dead under mu after every wake, so a coalesced or
// spurious signal is harmless.
func (c *sockChannel) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// writeLoop is the channel's sole writer: it pops sends in FIFO order and runs
// proto.writeMsg on this goroutine, so a stalled conn.Write blocks only this channel
// — never the event loop. It exits (closing the socket) once the channel is dead AND
// the queue is empty: fail() empties the queue itself (an error teardown has nothing
// to flush to), while a deliberate close() leaves it for the writer to flush —
// bounded by the closeGrace write deadline close() arms — before the final Close.
func (c *sockChannel) writeLoop() {
	for {
		c.mu.Lock()
		if len(c.queue) == 0 {
			if c.dead {
				c.mu.Unlock()
				c.conn.Close() // idempotent: fail() already closed it on the error path
				return
			}
			c.mu.Unlock()
			<-c.wake
			continue
		}
		b := c.queue[0]
		c.queue[0] = nil // release the payload once written, not when the queue array turns over
		c.queue = c.queue[1:]
		if len(c.queue) == 0 {
			c.queue = nil // drained: free the backing array instead of pinning its high-water cap
		}
		c.queued -= len(b)
		c.mu.Unlock()
		// After a close()-initiated flush hits a write error, writeMsg's fail() is a
		// no-op (dead is already set) and the remaining writes error instantly on the
		// closed/deadlined conn — the loop still terminates, it just drains fast.
		c.proto.writeMsg(c, b)
	}
}

// close is the deliberate teardown: it does NOT fire onClose (the owner asked for
// it). A fail() racing behind it stays silent because dead is already set — a
// live-channel error, by contrast, must still reach onClose or the owning PeerLink
// is never forgotten and the peer is blackholed.
//
// Queued sends still flush: the JS side sends-then-closes (a PeerLink handshake
// rejection, a WS close frame), and the old synchronous send had handed those bytes
// to the kernel before close could run — so the writer drains the queue (and any
// write already in flight) before the socket closes. The closeGrace write deadline
// bounds that flush; the writer owns the actual conn.Close.
func (c *sockChannel) close() {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	c.dead = true
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return // dial still in flight: its goroutine sees dead and closes the fresh conn (queued sends are dropped, as before)
	}
	conn.SetWriteDeadline(time.Now().Add(closeGrace))
	c.signal() // the writer flushes the queue, then Close()s and exits
}

// fail is the error teardown: it closes the socket and fires onClose so the owner
// drops the channel. Unsent queued messages are dropped — the link is broken, there
// is nothing to flush them to. Idempotent against close() and a second fail() via
// the dead flag.
func (c *sockChannel) fail() {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	c.dead = true
	c.queue, c.queued = nil, 0
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		conn.Close() // also unblocks a writer mid-Write; it errors out, sees dead, and exits
	}
	c.signal() // wake a parked writer so it observes dead and exits
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
	// net.Buffers ships the length prefix and the payload with one writev (a single
	// syscall on a TCPConn), so we neither allocate a 4+len(bytes) frame nor copy the
	// whole payload to prepend the header — the biggest saving on the 1 MiB upload path.
	// Only the writer goroutine calls this (conn is always set by then), so frames on
	// the same socket can't interleave. WriteTo consumes the slice header it's given
	// (advancing/niling entries), so hand it a fresh local; bytes is untouched.
	iov := net.Buffers{hdr[:], bytes}
	if _, err := iov.WriteTo(c.conn); err != nil {
		c.fail()
	}
}

func (framedProto) readLoop(c *sockChannel) {
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 64<<10)
	idle := 0 // consecutive compactions that left most of cap(buf) unused
	conn := c.conn // set strictly before the read loop starts
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
	if _, err := c.conn.Write(bytes); err != nil {
		c.fail()
	}
}

func (rawProto) readLoop(c *sockChannel) {
	chunk := make([]byte, 64<<10)
	conn := c.conn // set strictly before the read loop starts
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
