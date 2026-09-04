// net.go — the Go target's TCP socket primitive: a raw byte duplex (rawChannel), with no
// message boundaries of its own. This is the only networking in Go; the wire codec, the
// PeerLink handshake and routing are the transport bundle's guest program (transport/src)
// running in QuickJS over this via __net (sock.go).
package main

import (
	"context"
	"net"
	"runtime"
	"sync"
	"time"
)

// tcpKeepAlive is how long a connection may be idle before the kernel probes it, set on
// both the dial and the listen path: it is the only thing that reclaims a socket whose
// peer VANISHED (no FIN on a NAT rebind or a killed VM), while a present-but-silent peer
// is silentReadTimeout's business.
const tcpKeepAlive = 30 * time.Second

// silentReadTimeout bounds a connection that has never delivered a BYTE — the cheapest
// attack is to connect and say nothing, since no handshake starts so none of the
// transport's deadlines arm. Armed before the first read and CLEARED by it, deliberately
// not an idle deadline: once bytes flow, whether a quiet link may be held belongs to the
// authenticated transport guest (linkIdleTimeoutMs). A var, not a const, so a test can
// shrink it.
var silentReadTimeout = 30 * time.Second

// Socket buffers stay at kernel defaults — an explicit SO_RCVBUF/SO_SNDBUF is clamped to
// net.core.{r,w}mem_max and LOCKS the buffer, disabling the autotuning that grows it to
// ~6 MB as a bulk transfer ramps (a fixed 4 MiB once pinned holder connections to a
// ~64 KiB receive window, the very stall it was meant to fix).

// dialTCP dials with default socket options (see the note above).
func dialTCP(addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 5 * time.Second, KeepAlive: tcpKeepAlive}
	return d.DialContext(context.Background(), "tcp", addr)
}

// ───────────────────────── RawLink: a byte duplex ──────────────────────────────

// rawChannel delivers bytes as they arrive (core/socket-seam.ts RawLink): one delivery is
// an arbitrary slice of the stream and implies no boundary, which the transport bundle's
// framer imposes on the far side of __net. A channel owns one socket, one read goroutine
// and one writer goroutine. send only queues — safe from any goroutine — and takes
// ownership of its slice. onMsg borrows the read buffer only for the call; the native
// host reserves its shared staging allowance before making any retained copy.
type rawChannel interface {
	send(bytes []byte)
	buffered() int
	resume()
	close(graceful bool)
}

// ── sockChannel: the connection core ───────────────────────────────────────────
//
// Writes never run on the caller's goroutine: the caller is the event-loop goroutine
// (sock.go N.send), which owns ALL QuickJS execution, so a peer that stops draining must
// not block it — a synchronous conn.Write would freeze every timer, including the JS
// transport timeouts meant to bound exactly this (node:net has the same shape). The queue
// doubles as the pre-connect buffer, and one writer draining one FIFO keeps later
// messages from overtaking earlier ones (PeerLink's HELLO, a WS upgrade request).
type sockChannel struct {
	onMsg   func([]byte) bool // false means the native driver-wide read allowance refused it
	onClose func()

	mu         sync.Mutex
	conn       net.Conn // set at most once, under mu, before the reader/writer start (they read it lock-free); close/fail Close() it but never reassign
	queue      [][]byte // sends awaiting the writer, in order (also buffers pre-connect sends)
	queued     int      // bytes held in queue, reported to the host's outbound owner
	dead       bool
	closeGrace time.Duration // installed from the shared TypeScript network policy

	wake     chan struct{} // cap 1: nudges the writer after queue/dead change; coalesces bursts
	readGate chan struct{} // one token permits one socket read / serialized realm turn
}

func newReadGate() chan struct{} {
	gate := make(chan struct{}, 1)
	gate <- struct{}{} // the first read may start immediately
	return gate
}

// newDialChannel returns a channel that connects in the background (the dial path):
// the caller can send immediately and the bytes flush once connected.
func newDialChannel(addr string, onMsg func([]byte) bool, onClose func(), closeGrace time.Duration) *sockChannel {
	c := &sockChannel{onMsg: onMsg, onClose: onClose, closeGrace: closeGrace,
		wake: make(chan struct{}, 1), readGate: newReadGate()}
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

// newInboundChannel wraps an already-open accepted socket: its writer starts immediately,
// while the caller starts readLoop once the JS channel is registered (netHost.wrapInbound).
func newInboundChannel(conn net.Conn, onMsg func([]byte) bool, onClose func(), closeGrace time.Duration) *sockChannel {
	c := &sockChannel{onMsg: onMsg, onClose: onClose, conn: conn, closeGrace: closeGrace,
		wake: make(chan struct{}, 1), readGate: newReadGate()}
	go c.writeLoop()
	return c
}

// send queues bytes for the writer goroutine and returns immediately, never touching the
// socket. It takes ownership of bytes (sock.go hands over a fresh JsTypedArrayToGo copy),
// so nothing is copied here. A send on a dead channel is dropped silently, like a
// node:net write after destroy. It answers nothing: what one link may hold is the driver's
// per-link owner (host/transport-host.ts `LinkOutboundOwner`), which charges every write
// against this socket's `buffered()` BEFORE it reaches here. A refusal from this primitive
// would be a second gate on the same bytes, with no owner behind it.
func (c *sockChannel) send(bytes []byte) {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	c.queue = append(c.queue, bytes)
	c.queued += len(bytes)
	c.mu.Unlock()
	c.signal()
	// Hand the processor to the freshly-woken writer (sitting in this P's runnext slot) so
	// the frame hits the wire now, overlapping the sender's JS turn — ~10% round-trip
	// latency on the Net benches. A hint only: correctness never depends on it.
	runtime.Gosched()
}

// buffered is the host custody owner's view of this socket: bytes accepted from the guest
// whose conn.Write has not completed. This primitive reports the fact; transport content
// neither reads it nor derives time policy from it.
func (c *sockChannel) buffered() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.queued
}

// Each delivery consumes the sole read token. The JS driver returns it only after that
// read's serialized realm turn settles, so excess bytes stay in the socket receive window.
func (c *sockChannel) resume() {
	c.wakeReader()
}

// waitReadable parks until this link's read token comes back, and answers whether the loop
// may read. Both teardowns wakeReader(), so a parked reader always observes a dead channel.
func (c *sockChannel) waitReadable() bool {
	<-c.readGate
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.dead
}

func (c *sockChannel) wakeReader() {
	select {
	case c.readGate <- struct{}{}:
	default:
	}
}

// signal nudges the writer without blocking: the cap-1 buffer coalesces bursts, and the
// writer re-checks queue+dead under mu after every wake, so a spurious one is harmless.
func (c *sockChannel) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// writeLoop is the channel's sole writer: it pops sends in FIFO order and writes on this
// goroutine, so a stalled conn.Write blocks only this channel. It exits once the channel
// is dead AND the queue is empty: fail() and a non-graceful close empty the queue, while a
// graceful close leaves it for the writer to flush under the closeGrace deadline.
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
		// Take the WHOLE backlog, not its head: the record layer writes one frame per
		// record, so popping one at a time cost a syscall and two lock round-trips each
		// where one writev carries the batch (writeMsgs).
		batch := c.queue
		c.queue = nil // drained: free the backing array instead of pinning its high-water cap
		c.mu.Unlock()
		// If a close()-initiated flush hits a write error, fail() is a no-op (dead is set)
		// and the remaining writes error instantly on the closed conn — the loop still
		// terminates, it just drains fast.
		n := c.writeMsgs(batch)
		c.mu.Lock()
		// Keep the batch visible to buffered() while conn.Write owns it — over-reporting for
		// the span of one writev, which is the conservative side of a custody bound. A
		// concurrent hard close/fail may already have released the whole allowance.
		if c.queued >= n {
			c.queued -= n
		}
		c.mu.Unlock()
	}
}

// terminate is the channel's sole dead transition, made idempotent by the dead flag:
// whichever of close/fail arrives first wins and the other returns silently, so a fail()
// racing behind a deliberate close never fires onClose for it. flush keeps the queue for
// the writer to drain under closeGrace; notify fires onClose, which only the error path
// wants — a deliberate close was the owner's own request.
func (c *sockChannel) terminate(flush, notify bool) {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	c.dead = true
	if !flush {
		c.queue, c.queued = nil, 0
	}
	conn := c.conn
	c.mu.Unlock()
	// A nil conn is a dial still in flight: its goroutine sees dead and closes the fresh
	// conn itself. Neither loop has started yet, so the wakes below are inert.
	if conn != nil {
		if flush {
			conn.SetWriteDeadline(time.Now().Add(c.closeGrace))
		} else {
			conn.Close() // also unblocks a writer mid-Write; it errors out, sees dead, and exits
		}
	}
	c.signal() // wake a parked writer so it flushes, or observes dead and exits
	c.wakeReader()
	if notify {
		c.onClose()
	}
}

func (c *sockChannel) close(graceful bool) { c.terminate(graceful, false) }
func (c *sockChannel) fail()               { c.terminate(false, true) }

// The wire: bytes pass through verbatim. Whether a link is length-prefixed or RFC 6455
// framed is the transport bundle's decision and its code (transport/src). Returns the
// batch's byte total, which is what the caller releases from `queued`.
func (c *sockChannel) writeMsgs(batch [][]byte) int {
	total := 0
	for _, b := range batch {
		total += len(b)
	}
	// One frame is the latency path the send-side Gosched hands the processor over for
	// (see send), so it stays a plain Write rather than entering the vector machinery.
	if len(batch) == 1 {
		if _, err := c.conn.Write(batch[0]); err != nil {
			c.fail()
		}
		return total
	}
	// net.Buffers CONSUMES its header slice as it writes, which is safe because the batch
	// left the queue before this goroutine took it. On a conn with no writev fast path it
	// falls back to one Write per buffer — exactly the old loop.
	bufs := net.Buffers(batch)
	if _, err := bufs.WriteTo(c.conn); err != nil {
		c.fail()
	}
	return total
}

func (c *sockChannel) readLoop() {
	chunk := make([]byte, 64<<10)
	conn := c.conn // set strictly before the read loop starts
	// Armed for the first read and dropped by it, so it bounds a peer that never speaks
	// without ever bounding one that has.
	conn.SetReadDeadline(time.Now().Add(silentReadTimeout))
	spoke := false
	for {
		if !c.waitReadable() {
			return
		}
		n, err := conn.Read(chunk)
		if n > 0 {
			if !spoke {
				spoke = true
				conn.SetReadDeadline(time.Time{}) // said something: the guest's link deadlines own it now
			}
			// onMsg charges the §12.6 staging allowance before copying this borrowed
			// scratch slice, stalling here when the window is full. It answers false only
			// for a read that can never fit; leaving that socket open would just let the
			// peer retry outside the meter.
			if !c.onMsg(chunk[:n]) {
				c.fail()
				return
			}
		} else if err == nil {
			// A zero-byte, nil-error read made no realm turn to return the token.
			c.resume()
		}
		if err != nil {
			c.fail() // including the deadline: a socket that opened and never spoke
			return
		}
	}
}
