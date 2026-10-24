// The TCP socket primitive: a raw byte duplex (sockChannel) with no message boundaries.
// Framing, handshake and routing are the transport bundle's, reached via __net (net.go).
package main

import (
	"context"
	"net"
	"runtime"
	"sync"
	"time"
)

// ───────────────────────── RawLink: a byte duplex ──────────────────────────────

// sockChannel is a RawLink (services/socket-seam.ts): each delivery is an arbitrary slice
// of the stream, borrowed only for the onMsg call. It owns one socket, a reader and a
// writer goroutine. send only queues, so a peer that stops draining never blocks the loop
// goroutine; the FIFO also buffers pre-connect sends.
type sockChannel struct {
	onMsg   func([]byte)
	onClose func()

	mu         sync.Mutex
	conn       net.Conn // set once, under mu, before the reader/writer start
	queue      [][]byte // sends awaiting the writer, in order
	queued     int      // bytes held in queue, reported by buffered()
	dead       bool
	closeGrace time.Duration
	cancelDial context.CancelFunc // aborts a connect in flight; nil on an accepted socket

	wake     chan struct{} // cap 1: nudges the writer; coalesces bursts
	readGate chan struct{} // one token permits one socket read
}

func newSockChannel(onMsg func([]byte), onClose func(), closeGrace time.Duration) *sockChannel {
	c := &sockChannel{onMsg: onMsg, onClose: onClose, closeGrace: closeGrace,
		wake: make(chan struct{}, 1), readGate: make(chan struct{}, 1)}
	c.readGate <- struct{}{} // the first read may start immediately
	return c
}

// newDialChannel returns a channel that connects in the background; sends queue until then.
func newDialChannel(addr string, keepAlive time.Duration, onMsg func([]byte), onClose func(), closeGrace time.Duration) *sockChannel {
	c := newSockChannel(onMsg, onClose, closeGrace)
	ctx, cancel := context.WithCancel(context.Background())
	c.cancelDial = cancel
	go func() {
		// Kernel-default socket buffers: setting SO_RCVBUF/SO_SNDBUF disables autotuning. No
		// timeout of its own: a dial that never connects never reads, and the host's
		// silent-socket deadline (host/platform.ts `tcpChannels`) closes the channel, which
		// cancels ctx.
		conn, err := (&net.Dialer{KeepAlive: keepAlive}).DialContext(ctx, "tcp", addr)
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
		go c.writeLoop()
		c.readLoop()
	}()
	return c
}

// newInboundChannel wraps an accepted socket; the caller starts readLoop once the JS
// channel is registered.
func newInboundChannel(conn net.Conn, onMsg func([]byte), onClose func(), closeGrace time.Duration) *sockChannel {
	c := newSockChannel(onMsg, onClose, closeGrace)
	c.conn = conn
	go c.writeLoop()
	return c
}

// send queues bytes for the writer and takes ownership of them. A send on a dead channel
// is dropped. There is no refusal here: `LinkOutboundOwner` (host/transport-host.ts)
// bounds a link against buffered() before it sends.
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
	// Let the woken writer put the frame on the wire now (~10% round-trip latency).
	runtime.Gosched()
}

// buffered is the bytes accepted by send whose conn.Write has not completed.
func (c *sockChannel) buffered() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.queued
}

// waitReadable parks for the read token and reports whether the channel is still alive.
func (c *sockChannel) waitReadable() bool {
	<-c.readGate
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.dead
}

// resume returns the read token, once a delivery's realm turn has settled; until then
// excess bytes stay in the socket's receive window.
func (c *sockChannel) resume() {
	select {
	case c.readGate <- struct{}{}:
	default:
	}
}

// signal nudges the writer without blocking; a spurious wake is harmless.
func (c *sockChannel) signal() {
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

// writeLoop is the channel's sole writer, draining the queue in order. It exits once the
// channel is dead and the queue empty; a graceful close leaves the queue to flush under
// closeGrace.
func (c *sockChannel) writeLoop() {
	for {
		c.mu.Lock()
		if len(c.queue) == 0 {
			if c.dead {
				c.mu.Unlock()
				c.conn.Close()
				return
			}
			c.mu.Unlock()
			<-c.wake
			continue
		}
		// Take the whole backlog, for one writev.
		batch := c.queue
		c.queue = nil
		c.mu.Unlock()
		n := c.writeMsgs(batch)
		c.mu.Lock()
		// The batch counts in buffered() until written. A hard close may already have
		// zeroed it.
		if c.queued >= n {
			c.queued -= n
		}
		c.mu.Unlock()
	}
}

// terminate is the channel's one dead transition; the first of close/fail wins. flush
// leaves the queue to drain under closeGrace; notify fires onClose, for the error path.
func (c *sockChannel) terminate(flush, notify bool) {
	c.mu.Lock()
	if c.dead {
		c.mu.Unlock()
		return
	}
	c.dead = true
	// Before connect no writer will start, so nothing flushes.
	if !flush || c.conn == nil {
		c.queue, c.queued = nil, 0
	}
	conn := c.conn
	c.mu.Unlock()
	// A nil conn is a dial in flight: cancelling ends it, and one that lands anyway closes
	// its conn on seeing dead.
	if c.cancelDial != nil {
		c.cancelDial()
	}
	if conn != nil {
		if flush {
			conn.SetWriteDeadline(time.Now().Add(c.closeGrace))
		} else {
			conn.Close() // also unblocks a writer mid-Write
		}
	}
	c.signal()
	c.resume()
	if notify {
		c.onClose()
	}
}

func (c *sockChannel) close(graceful bool) { c.terminate(graceful, false) }
func (c *sockChannel) fail()               { c.terminate(false, true) }

// writeMsgs writes a batch verbatim and returns its byte total.
func (c *sockChannel) writeMsgs(batch [][]byte) int {
	total := 0
	for _, b := range batch {
		total += len(b)
	}
	if len(batch) == 1 {
		if _, err := c.conn.Write(batch[0]); err != nil {
			c.fail()
		}
		return total
	}
	// net.Buffers consumes the slice header; the batch already left the queue.
	bufs := net.Buffers(batch)
	if _, err := bufs.WriteTo(c.conn); err != nil {
		c.fail()
	}
	return total
}

func (c *sockChannel) readLoop() {
	chunk := make([]byte, 64<<10)
	conn := c.conn
	for {
		if !c.waitReadable() {
			return
		}
		n, err := conn.Read(chunk)
		if n > 0 {
			c.onMsg(chunk[:n])
		} else if err == nil {
			// No delivery, so no realm turn returns the token.
			c.resume()
		}
		if err != nil {
			c.fail()
			return
		}
	}
}
