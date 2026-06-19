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
	crand "crypto/rand"
	"net"
	"sync"
	"time"
)

const maxTCPMessage = 16 << 20 // frame cap (matches the TS MAX_TCP_MESSAGE / WS cap)

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

func randBytes(n int) []byte {
	b := make([]byte, n)
	crand.Read(b)
	return b
}

// ───────────────────────── RawChannel: a whole-message duplex ─────────────────

// rawChannel delivers whole messages atomically (net-link.ts RawChannel). TCP gets
// message boundaries from a length prefix; WS already has them. A channel owns one
// socket and one read goroutine; send is safe from any goroutine.
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
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
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
		c.open = true
		pending := c.pending
		c.pending = nil
		c.mu.Unlock()
		for _, b := range pending {
			c.writeFrame(b)
		}
		c.readLoop()
	}()
	return c
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
	out := make([]byte, 4+len(bytes))
	putU32BE(out, 0, uint32(len(bytes)))
	copy(out[4:], bytes)
	c.mu.Lock()
	conn := c.conn
	dead := c.dead
	c.mu.Unlock()
	if dead || conn == nil {
		return
	}
	if _, err := conn.Write(out); err != nil {
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
			for {
				if len(buf) < 4 {
					break
				}
				ln := getU32BE(buf, 0)
				if ln > maxTCPMessage {
					c.fail()
					return
				}
				if uint32(len(buf)) < 4+ln {
					break
				}
				msg := append([]byte(nil), buf[4:4+ln]...)
				buf = buf[4+ln:]
				c.onMsg(msg)
			}
		}
		if err != nil {
			c.fail()
			return
		}
	}
}
