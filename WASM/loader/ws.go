// ws.go — WebSocket (RFC 6455) as a rawChannel over a raw TCP socket, the Go twin
// of host/ws/ws-codec.ts + the WsChannel classes in host/net-node.ts. WebSocket
// exists only because browsers cannot speak raw TCP, so it is treated as a wire
// codec over a plain TCP listener: we do the opening handshake and the framing
// ourselves, identically on every target. Client→server frames are masked (RFC
// 6455 §5.3), server→client unmasked; fragmented data messages are reassembled and
// control frames (ping/pong/close) are handled inline.
//
// We hand-roll the framing rather than reuse a library (e.g. coder/websocket)
// deliberately: that library does its handshake through net/http, which links
// crypto/tls and the crypto/internal/fips140 module and adds ~6 MiB to the binary
// (11.5 MiB vs ~5 MiB). RFC 6455 over a raw socket keeps the single binary lean and
// cgo-free, and a Go node only ever talks to RFC 6455-compliant peers anyway.
//
// SHA-1 here is the fixed §4.2.2 accept-key checksum, not security crypto and not an
// interop-sensitive value (it never leaves the handshake), so crypto/sha1 +
// encoding/base64 from the standard library is the right tool — this does not
// reintroduce a Go-native crypto dependency in the libsodium sense.
package main

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"net"
	"strings"
	"sync"
	"time"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
const maxWSHandshake = 16 << 10 // an HTTP upgrade request is tiny

const (
	opCont   = 0x0
	opBinary = 0x2
	opClose  = 0x8
	opPing   = 0x9
	opPong   = 0xa
)

// wsAcceptKey is the server's Sec-WebSocket-Accept for a client key (RFC 6455 §4.2.2).
func wsAcceptKey(secWebSocketKey string) string {
	h := sha1.Sum([]byte(secWebSocketKey + wsGUID))
	return base64.StdEncoding.EncodeToString(h[:])
}

// wsClientKey mints a fresh client Sec-WebSocket-Key and the accept value the server
// must echo back (host/ws/ws-codec.ts wsClientKey).
func wsClientKey() (key, expectAccept string) {
	key = base64.StdEncoding.EncodeToString(randBytes(16))
	return key, wsAcceptKey(key)
}

// encodeWSFrame encodes one FIN frame. mask non-nil (4 bytes) for client→server,
// nil for server→client (host/ws/ws-codec.ts encodeFrame).
func encodeWSFrame(opcode byte, payload, mask []byte) []byte {
	maskBit := byte(0)
	maskLen := 0
	if mask != nil {
		maskBit = 0x80
		maskLen = 4
	}
	n := len(payload)
	var header []byte
	switch {
	case n < 126:
		header = []byte{0x80 | (opcode & 0x0f), maskBit | byte(n)}
	case n < 1<<16:
		header = []byte{0x80 | (opcode & 0x0f), maskBit | 126, byte(n >> 8), byte(n)}
	default:
		header = []byte{0x80 | (opcode & 0x0f), maskBit | 127, 0, 0, 0, 0, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
	}
	out := make([]byte, 0, len(header)+maskLen+n)
	out = append(out, header...)
	if mask != nil {
		out = append(out, mask...)
		for i := 0; i < n; i++ {
			out = append(out, payload[i]^mask[i&3])
		}
	} else {
		out = append(out, payload...)
	}
	return out
}

type wsFrame struct {
	opcode  byte
	payload []byte
}

// wsParser is an incremental frame reader. expectMasked enforces the RFC's
// directionality (a server feeds client bytes, which must be masked; a client feeds
// server bytes, which must not be). Fragmented data messages are reassembled,
// bounded by the single-frame cap; control frames may interleave (§5.4). It mirrors
// host/ws/ws-codec.ts WsParser, decoding in Go rather than ws.wasm.
type wsParser struct {
	expectMasked bool
	buf          []byte
	fragOpcode   int // -1 = no fragmented message in flight
	frags        []byte
}

func newWSParser(expectMasked bool) *wsParser {
	return &wsParser{expectMasked: expectMasked, fragOpcode: -1}
}

// frameLength returns the total byte length of the next frame from its (unvalidated)
// header, or -1 if too few bytes are buffered to know yet.
func (p *wsParser) frameLength() (int, error) {
	if len(p.buf) < 2 {
		return -1, nil
	}
	masked := p.buf[1]&0x80 != 0
	len7 := int(p.buf[1] & 0x7f)
	base, ext, payloadLen := 2, 0, len7
	switch len7 {
	case 126:
		if len(p.buf) < 4 {
			return -1, nil
		}
		ext = 2
		payloadLen = int(p.buf[2])<<8 | int(p.buf[3])
	case 127:
		if len(p.buf) < 10 {
			return -1, nil
		}
		if getU32BE(p.buf, 2) != 0 { // > 4 GiB
			return 0, errors.New("ws: oversize frame")
		}
		ext = 8
		payloadLen = int(getU32BE(p.buf, 6))
	}
	maskLen := 0
	if masked {
		maskLen = 4
	}
	return base + ext + maskLen + payloadLen, nil
}

// push feeds bytes and returns whatever whole messages completed; an error means a
// protocol violation (the channel must tear down).
func (p *wsParser) push(chunk []byte) ([]wsFrame, error) {
	p.buf = append(p.buf, chunk...)
	var out []wsFrame
	for {
		total, err := p.frameLength()
		if err != nil {
			return nil, err
		}
		if total < 0 {
			break
		}
		if total > maxTCPMessage {
			return nil, errors.New("ws: oversize frame")
		}
		if len(p.buf) < total {
			break
		}
		fin, opcode, payload, err := p.decodeOne(p.buf[:total])
		if err != nil {
			return nil, err
		}
		p.buf = p.buf[total:]

		switch {
		case opcode == opCont:
			if p.fragOpcode < 0 {
				return nil, errors.New("ws: protocol error")
			}
			if len(p.frags)+len(payload) > maxTCPMessage {
				return nil, errors.New("ws: oversize frame")
			}
			p.frags = append(p.frags, payload...)
			if fin {
				out = append(out, wsFrame{opcode: byte(p.fragOpcode), payload: p.frags})
				p.fragOpcode, p.frags = -1, nil
			}
		case !fin:
			// first fragment of a data message (the decoder rejects fragmented
			// control frames before this)
			if p.fragOpcode >= 0 {
				return nil, errors.New("ws: protocol error")
			}
			p.fragOpcode = int(opcode)
			p.frags = append([]byte(nil), payload...)
		default:
			// unfragmented frame; a data frame may not preempt an in-flight
			// fragmented message, control frames interleave freely (§5.4)
			if opcode < 0x8 && p.fragOpcode >= 0 {
				return nil, errors.New("ws: protocol error")
			}
			out = append(out, wsFrame{opcode: opcode, payload: payload})
		}
	}
	return out, nil
}

// decodeOne decodes one complete frame, enforcing mask direction and the control-
// frame constraints (unfragmented, ≤125 bytes).
func (p *wsParser) decodeOne(frame []byte) (fin bool, opcode byte, payload []byte, err error) {
	fin = frame[0]&0x80 != 0
	opcode = frame[0] & 0x0f
	masked := frame[1]&0x80 != 0
	if masked != p.expectMasked {
		return false, 0, nil, errors.New("ws: bad mask direction")
	}
	len7 := int(frame[1] & 0x7f)
	base, ext := 2, 0
	switch len7 {
	case 126:
		ext = 2
	case 127:
		ext = 8
	}
	maskOff := base + ext
	dataOff := maskOff
	if masked {
		dataOff += 4
	}
	payload = append([]byte(nil), frame[dataOff:]...)
	if masked {
		key := frame[maskOff : maskOff+4]
		for i := range payload {
			payload[i] ^= key[i&3]
		}
	}
	if opcode >= 0x8 { // control frame
		if !fin {
			return false, 0, nil, errors.New("ws: fragmented control frame")
		}
		if len(payload) > 125 {
			return false, 0, nil, errors.New("ws: oversize control frame")
		}
	}
	return fin, opcode, payload, nil
}

// ── wsChannel: RFC 6455 over a TCP socket, a rawChannel ───────────────────────
// One type drives both ends; they differ only in who speaks first in the opening
// handshake and in masking. PeerLink emits its HELLO before the handshake finishes,
// so sends queue until the channel opens (net-node.ts WsChannelBase.pending).
type wsChannel struct {
	onMsg   func([]byte)
	onClose func()
	client  bool // we masked our frames and expect unmasked frames back

	mu      sync.Mutex
	conn    net.Conn
	parser  *wsParser
	pending [][]byte
	open    bool
	dead    bool

	host         string // client: for the Host: / GET request line
	port         string
	expectAccept string // client: the accept value the server must echo
}

// newWSChannelDial dials a node's WS endpoint (the node-side client; the browser uses
// its platform WebSocket). It connects in the background, sends the upgrade request,
// verifies the 101, then expects unmasked frames.
func newWSChannelDial(addr string, onMsg func([]byte), onClose func()) *wsChannel {
	host, port, _ := net.SplitHostPort(addr)
	c := &wsChannel{onMsg: onMsg, onClose: onClose, client: true, parser: newWSParser(false), host: host, port: port}
	go func() {
		conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
		if err != nil {
			c.fail()
			return
		}
		c.mu.Lock()
		if c.dead {
			c.mu.Unlock()
			conn.Close()
			return
		}
		c.conn = conn
		c.mu.Unlock()
		c.runClient()
	}()
	return c
}

func (c *wsChannel) mask() []byte {
	if c.client {
		return randBytes(4)
	}
	return nil
}

func (c *wsChannel) send(bytes []byte) {
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
	c.writeRaw(encodeWSFrame(opBinary, bytes, c.mask()))
}

func (c *wsChannel) writeRaw(b []byte) {
	c.mu.Lock()
	conn, dead := c.conn, c.dead
	c.mu.Unlock()
	if dead || conn == nil {
		return
	}
	if _, err := conn.Write(b); err != nil {
		c.fail()
	}
}

func (c *wsChannel) close() {
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

// fail mirrors the TCP channel: deliberate close() sets dead first and stays silent;
// a live-channel error must reach onClose so the link is forgotten.
func (c *wsChannel) fail() {
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

func (c *wsChannel) runServer() {
	header, leftover, err := c.readHandshake()
	if err != nil {
		c.fail()
		return
	}
	key := headerValue(header, "sec-websocket-key")
	if key == "" {
		c.fail()
		return
	}
	c.writeRaw([]byte("HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + wsAcceptKey(key) + "\r\n\r\n"))
	c.becomeOpen()
	c.frameLoop(leftover)
}

func (c *wsChannel) runClient() {
	key, expectAccept := wsClientKey()
	c.expectAccept = expectAccept
	c.writeRaw([]byte("GET / HTTP/1.1\r\nHost: " + net.JoinHostPort(c.host, c.port) + "\r\n" +
		"Upgrade: websocket\r\nConnection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n"))
	header, leftover, err := c.readHandshake()
	if err != nil {
		c.fail()
		return
	}
	// Sec-WebSocket-Accept is case-significant base64; compare the exact value.
	if !strings.Contains(header, "HTTP/1.1 101") || headerValue(header, "sec-websocket-accept") != c.expectAccept {
		c.fail()
		return
	}
	c.becomeOpen()
	c.frameLoop(leftover)
}

// readHandshake reads until the CRLFCRLF head terminator, returning the header text
// and any bytes that followed it. Bounded so a peer that never finishes the head
// cannot make us hoard memory.
func (c *wsChannel) readHandshake() (header string, leftover []byte, err error) {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	buf := make([]byte, 0, 1024)
	chunk := make([]byte, 4096)
	for {
		n, rerr := conn.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			if i := indexCRLFCRLF(buf); i >= 0 {
				return string(buf[:i]), append([]byte(nil), buf[i+4:]...), nil
			}
			if len(buf) > maxWSHandshake {
				return "", nil, errors.New("ws: handshake too large")
			}
		}
		if rerr != nil {
			return "", nil, rerr
		}
	}
}

func (c *wsChannel) becomeOpen() {
	c.mu.Lock()
	c.open = true
	pending := c.pending
	c.pending = nil
	c.mu.Unlock()
	for _, b := range pending {
		c.writeRaw(encodeWSFrame(opBinary, b, c.mask()))
	}
}

func (c *wsChannel) frameLoop(initial []byte) {
	if len(initial) > 0 {
		if !c.feed(initial) {
			return
		}
	}
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	chunk := make([]byte, 64<<10)
	for {
		n, err := conn.Read(chunk)
		if n > 0 && !c.feed(chunk[:n]) {
			return
		}
		if err != nil {
			c.fail()
			return
		}
	}
}

// feed pushes bytes through the parser and dispatches whole frames; it returns false
// once the channel has been torn down (protocol error or a CLOSE frame).
func (c *wsChannel) feed(chunk []byte) bool {
	frames, err := c.parser.push(chunk)
	if err != nil {
		c.fail()
		return false
	}
	for _, f := range frames {
		switch f.opcode {
		case opBinary:
			c.onMsg(f.payload)
		case opPing:
			c.writeRaw(encodeWSFrame(opPong, f.payload, c.mask()))
		case opClose:
			c.fail()
			return false
		}
	}
	return true
}

func indexCRLFCRLF(b []byte) int {
	for i := 0; i+3 < len(b); i++ {
		if b[i] == 13 && b[i+1] == 10 && b[i+2] == 13 && b[i+3] == 10 {
			return i
		}
	}
	return -1
}

// headerValue case-insensitively pulls a header value out of an HTTP request head.
func headerValue(head, name string) string {
	name = strings.ToLower(name)
	for _, line := range strings.Split(head, "\r\n") {
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		if strings.ToLower(strings.TrimSpace(line[:colon])) == name {
			return strings.TrimSpace(line[colon+1:])
		}
	}
	return ""
}
