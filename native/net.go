// net.go — the Go target's TCP socket primitive: a raw byte duplex (rawChannel) over a
// socket, with no message boundaries of its own.
//
// This is the only networking in Go. Everything structural — the wire codec that
// imposes those boundaries, the PeerLink handshake, the routing table, the
// request/response layer — is the transport bundle's guest program
// (transport/guest.js, driven by host/transport-host.ts) running in QuickJS over this
// via __net (sock.go).
package main

import (
	"context"
	"net"
	"runtime"
	"sync"
	"time"
)

// MAX_FRAME_BYTES (§12.6, §16.1): one wire-visible frame cap. This target holds its own
// descriptors, so it declares and enforces its own copy — the same rule that puts the
// declaration in core/net-limits.ts rather than in the transport it bounds. Keep the two
// in step; a socket seam must never read this number out of the module it is bounding.
const maxFrameBytes = 2 << 20

// sendQueueLimit caps the bytes a channel buffers for its writer goroutine. The JS
// protocol is a single request/response plane — even a block upload awaits an ack per
// chunk — so a healthy link's queue stays a few messages deep; hitting the cap means
// the peer has stopped draining (or JS is pushing unpaced), and the channel fails
// rather than buffering without bound. Must exceed maxFrameBytes or a single
// max-size frame could never be queued; it stays at 2x the frame cap, so "how deep may a
// stalled peer's queue get" does not drift when the cap moves.
const sendQueueLimit = 4 << 20

// closeGrace bounds how long a deliberate close() lets the writer flush queued
// sends (a PeerLink rejection, a WS close frame) before the socket is torn down
// regardless — so closing a channel to a wedged peer can't pin its writer forever.
const closeGrace = 5 * time.Second

// Socket buffers are deliberately left at kernel defaults — do NOT set SO_RCVBUF/
// SO_SNDBUF here. An explicit value is silently clamped to net.core.{r,w}mem_max
// (208 KiB on stock Linux) and, worse, LOCKS the buffer, disabling the kernel's
// autotuning that would otherwise grow it to tcp_{r,w}mem[2] (~6 MB) as a bulk
// transfer ramps. A fixed 4 MiB set pre-handshake here once pinned every holder
// connection on an untuned box to a ~64 KiB receive window — 2.5 MB/s per
// connection at 26 ms RTT — the very stall it was meant to fix, while iperf on
// the same box (default sockets, autotuned) filled the link.

// dialTCP dials with default socket options; the kernel autotunes the buffers
// and negotiates a window scale sized for tcp_rmem[2], so a high-RTT bulk
// transfer is not window-limited.
func dialTCP(addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second}
	return d.DialContext(context.Background(), "tcp", addr)
}

// ───────────────────────── RawLink: a byte duplex ──────────────────────────────

// rawChannel delivers bytes as they arrive (core/socket-seam.ts RawLink at
// FRAMING.LENGTH or FRAMING.WS_*): one delivery is an arbitrary slice of the stream and
// implies no boundary, which the transport bundle's framer imposes at the far side of
// __net. A channel owns one socket, one read goroutine, and one writer goroutine; send
// only queues (it is safe from any goroutine and never blocks on the socket) and takes
// ownership of its slice — the caller must not reuse it.
//
// onMsg ownership: the read loop hands its onMsg callback a freshly-allocated slice per
// read that the callee owns — the reader never reuses it, so the callee may retain it
// and the delivery boundary needs no defensive copy.
type rawChannel interface {
	send(bytes []byte)
	close()
}

// ── sockChannel: the connection core ───────────────────────────────────────────
//
// One socket, with the subtle parts in one place: the writer goroutine and its bounded
// queue, the dead lifecycle, and the close vs fail split.
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
	onMsg   func([]byte)
	onClose func()

	mu     sync.Mutex
	conn   net.Conn // set at most once, under mu, strictly before the writer/reader goroutines start (they read it lock-free); close/fail Close() it but never reassign
	queue  [][]byte // sends awaiting the writer, in order (also buffers pre-connect sends)
	queued int      // bytes held in queue — the sendQueueLimit accounting
	dead   bool

	wake chan struct{} // cap 1: nudges the writer after queue/dead change; coalesces bursts
}

// newDialChannel returns a channel that connects in the background (the dial path):
// the caller can send immediately and the bytes flush once connected.
func newDialChannel(addr string, onMsg func([]byte), onClose func()) *sockChannel {
	c := &sockChannel{onMsg: onMsg, onClose: onClose, wake: make(chan struct{}, 1)}
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
		c.readLoop()
	}()
	return c
}

// newInboundChannel wraps an already-open accepted socket: its writer starts
// immediately. The caller starts proto.readLoop once the JS channel is registered —
// see netHost.wrapInbound.
func newInboundChannel(conn net.Conn, onMsg func([]byte), onClose func()) *sockChannel {
	c := &sockChannel{onMsg: onMsg, onClose: onClose, conn: conn, wake: make(chan struct{}, 1)}
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
		c.writeMsg(b)
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

// ── the wire: a raw byte duplex — bytes pass through verbatim, no framing ──────
//
// Go imposes no message boundaries at all. Whether a link is length-prefixed or
// RFC 6455 framed is the transport bundle's decision and its code (transport/guest.js),
// so this file moves bytes and nothing else.
func (c *sockChannel) writeMsg(bytes []byte) {
	if _, err := c.conn.Write(bytes); err != nil {
		c.fail()
	}
}

func (c *sockChannel) readLoop() {
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
