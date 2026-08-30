// sock.go — the TCP socket primitive exposed to QuickJS as `__net`: open a socket, hand
// its bytes to JS, send, close. No message boundaries here — the transport bundle's guest
// program (transport/src) runs over the unframed RawLink shape this module hands it. Bytes
// cross the Go↔JS boundary only on the event-loop goroutine: reader goroutines hand each
// message to el.post, and the loop delivers it through the retained __netDeliver/
// __netClosed/__netAccept dispatchers defined in host/native-shim.ts.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	"seedloader/qjs"
)

// acceptErrBackoff paces the accept loop after a non-fatal error: EMFILE makes Accept fail
// immediately and repeatedly, and retrying flat out would spin a core.
const acceptErrBackoff = 20 * time.Millisecond

type netHost struct {
	el  *eventLoop
	qc  *qjs.Context
	und *qjs.Value // a reusable `undefined` for the `this` of dispatcher calls

	mu        sync.Mutex
	chans     map[int64]rawChannel
	nextID    int64
	listeners []net.Listener // bound listeners, closed on network teardown

	// Policy values installed by host/native-shim.ts before any socket is opened.
	maxLiveChannels int
	closeGrace      time.Duration

	// Retained JS dispatchers (the host realm's router into per-channel callbacks).
	fnDeliver *qjs.Value
	fnClosed  *qjs.Value
	fnAccept  *qjs.Value
}

// exposeNet installs `__net` into the realm. The shaping that turns it into RawLink
// objects, and the dispatchers Go's reader goroutines route through, are typed TS in
// host/native-shim.ts.
func exposeNet(qc *qjs.Context, el *eventLoop) *netHost {
	n := &netHost{el: el, qc: qc, und: qc.NewUndefined(), chans: map[int64]rawChannel{}}
	o := qc.NewObject()

	o.SetPropertyStr("install", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		if len(t.Args()) < 2 {
			return nil, errors.New("net: no socket limits supplied")
		}
		maxLive := int(t.Args()[0].Int64())
		grace := time.Duration(t.Args()[1].Int64()) * time.Millisecond
		if maxLive <= 0 || grace <= 0 {
			return nil, errors.New("net: invalid socket limits")
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		if n.maxLiveChannels != 0 || n.closeGrace != 0 {
			return nil, errors.New("net: socket limits already installed")
		}
		n.maxLiveChannels = maxLive
		n.closeGrace = grace
		return t.Context().NewUndefined(), nil
	}))

	// One socket kind: a raw byte duplex. Which codec runs over it is the transport
	// bundle's business, never Go's.
	o.SetPropertyStr("connect", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		if len(t.Args()) < 2 {
			return t.Context().NewInt64(0), nil // 0 is never a live id (get → nil)
		}
		addr := net.JoinHostPort(t.Args()[0].String(), strconv.Itoa(int(t.Args()[1].Int32())))
		return t.Context().NewInt64(n.dial(addr)), nil
	}))
	o.SetPropertyStr("listen", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		if len(t.Args()) < 2 {
			return t.Context().NewInt32(-1), nil // -1: the shim throws on a failed bind
		}
		bound, err := n.listen(t.Args()[0].String(), int(t.Args()[1].Int32()))
		if err != nil {
			return t.Context().NewInt32(-1), nil
		}
		return t.Context().NewInt32(int32(bound)), nil
	}))
	o.SetPropertyStr("send", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		if len(t.Args()) < 2 {
			return nil, nil
		}
		id := t.Args()[0].Int64()
		if ch := n.get(id); ch != nil {
			// b is a fresh copy (JsTypedArrayToGo), so send takes ownership without another. It
			// only queues — the write happens on the channel's writer goroutine (net.go writeLoop).
			if b, err := qjs.JsTypedArrayToGo(t.Args()[1]); err == nil {
				ch.send(b)
			}
		}
		return nil, nil
	}))
	o.SetPropertyStr("buffered", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		if len(t.Args()) < 1 {
			return t.Context().NewInt64(0), nil
		}
		if ch := n.get(t.Args()[0].Int64()); ch != nil {
			return t.Context().NewInt64(int64(ch.buffered())), nil
		}
		return t.Context().NewInt64(0), nil
	}))
	o.SetPropertyStr("resume", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		if len(t.Args()) >= 1 {
			if ch := n.get(t.Args()[0].Int64()); ch != nil {
				ch.resume()
			}
		}
		return nil, nil
	}))
	o.SetPropertyStr("closeListeners", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		n.closeListeners()
		return nil, nil
	}))
	o.SetPropertyStr("close", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		if len(t.Args()) < 1 {
			return nil, nil
		}
		// A deliberate close() sets dead WITHOUT firing onClose, so the readLoop error
		// chasing it never runs the onClose registry-drop. Dropping the entry here keeps
		// every local close (each rejected handshake, each duplicate dial) from leaking its
		// n.chans slot — attacker-triggerable memory exhaustion; the JS shim deletes from
		// its own Map for the same reason.
		id := t.Args()[0].Int64()
		if ch := n.get(id); ch != nil {
			graceful := len(t.Args()) >= 2 && t.Args()[1].Int32() != 0
			ch.close(graceful)
			n.mu.Lock()
			delete(n.chans, id)
			n.mu.Unlock()
		}
		return nil, nil
	}))
	qc.Global().SetPropertyStr("__net", o)
	return n
}

// retain picks up the three dispatchers the shared shim defines at module scope
// (host/native-shim.ts) when host-shell.gen.js is evaluated — after exposeNet installed
// `__net`, before any socket delivers.
func (n *netHost) retain() error {
	g := n.qc.Global()
	n.fnDeliver = g.GetPropertyStr("__netDeliver")
	n.fnClosed = g.GetPropertyStr("__netClosed")
	n.fnAccept = g.GetPropertyStr("__netAccept")
	// IsUndefined, not nil: GetPropertyStr never returns Go nil (qjs/value.go), so a nil
	// check would compile, never fire, and turn this boot error into "not a function".
	if n.fnDeliver.IsUndefined() || n.fnClosed.IsUndefined() || n.fnAccept.IsUndefined() {
		return fmt.Errorf("net: __netDeliver/__netClosed/__netAccept not defined (host/native-shim.ts)")
	}
	return nil
}

func (n *netHost) get(id int64) rawChannel {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.chans[id]
}

func (n *netHost) alloc() int64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.nextID++
	return n.nextID
}

// allocInbound is alloc for a socket nobody asked for: it refuses once the host holds
// maxLiveChannels. The count is read under the same lock that hands out the id, so the
// only slack is at most one connection per accept goroutine.
func (n *netHost) allocInbound() (int64, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.chans) >= n.maxLiveChannels {
		return 0, false
	}
	n.nextID++
	return n.nextID, true
}

// dial opens an outbound byte duplex: it connects in the background and buffers
// pre-connect sends, so JS can wrap the id and send its HELLO (or WS upgrade) immediately.
func (n *netHost) dial(addr string) int64 {
	id := n.alloc()
	ch := newDialChannel(addr, n.onMsg(id), n.onClose(id), n.closeGrace)
	n.mu.Lock()
	n.chans[id] = ch
	n.mu.Unlock()
	return id
}

// listen accepts inbound byte duplexes. The read goroutine starts only inside the posted
// task, after __netAccept created the JS channel — otherwise it could deliver a frame
// before JS has one to route it to.
func (n *netHost) listen(host string, port int) (int, error) {
	// No buffer options: an explicit SO_RCVBUF pre-bind locks out receive autotuning (see
	// net.go). KeepAlive is explicit so an accepted socket whose peer vanishes without a
	// FIN is reclaimed (tcpKeepAlive).
	lc := net.ListenConfig{KeepAlive: tcpKeepAlive}
	ln, err := lc.Listen(context.Background(), "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return 0, err
	}
	bound := ln.Addr().(*net.TCPAddr).Port
	n.mu.Lock()
	n.listeners = append(n.listeners, ln) // retained so teardown can close it (and end the accept loop)
	n.mu.Unlock()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return // listener closed (closeListeners) — release the goroutine
				}
				// Anything else is this process's condition (descriptor exhaustion, a reset
				// between SYN and accept): pause and keep serving, not retire the port.
				time.Sleep(acceptErrBackoff)
				continue
			}
			// The ceiling, applied before a goroutine or buffer is spent on the socket.
			id, ok := n.allocInbound()
			if !ok {
				conn.Close()
				continue
			}
			ch, start := n.wrapInbound(id, conn)
			// The transport's per-source half-open budget groups by IP, not ephemeral
			// source port. This listener is TCP, so RemoteAddr is a *net.TCPAddr.
			remoteAddr := conn.RemoteAddr().(*net.TCPAddr).IP.String()
			n.mu.Lock()
			n.chans[id] = ch
			n.mu.Unlock()
			n.el.post(func() {
				n.invoke(n.fnAccept, n.qc.NewInt32(int32(bound)), n.qc.NewInt64(id), n.qc.NewString(remoteAddr))
				start() // safe now: the JS channel exists
			})
		}
	}()
	return bound, nil
}

// closeListeners closes every bound listener, so each accept goroutine's Accept() errors
// and exits, releasing the fd. Wired to the driver's channels.close (native-shim.ts).
func (n *netHost) closeListeners() {
	n.mu.Lock()
	lns := n.listeners
	n.listeners = nil
	n.mu.Unlock()
	for _, ln := range lns {
		ln.Close()
	}
}

// wrapInbound builds a channel for an accepted socket but defers its read goroutine
// to the returned start(), so the loop registers the JS channel first.
func (n *netHost) wrapInbound(id int64, conn net.Conn) (rawChannel, func()) {
	c := newInboundChannel(conn, n.onMsg(id), n.onClose(id), n.closeGrace)
	return c, func() { go c.readLoop() }
}

// onMsg/onClose run on a socket reader goroutine; they hand the work to the loop
// goroutine, which owns all QuickJS access.
func (n *netHost) onMsg(id int64) func([]byte) {
	return func(b []byte) {
		// b is freshly allocated and ours (the rawChannel onMsg contract), so capture it
		// directly — one fewer full pass over every inbound byte.
		n.el.post(func() { n.invoke(n.fnDeliver, n.qc.NewInt64(id), n.qc.NewArrayBuffer(b)) })
	}
}

func (n *netHost) onClose(id int64) func() {
	return func() {
		n.el.post(func() {
			// Drop the channel before notifying JS: onClose only fires from fail() (socket
			// already closed, no fd to release), and deleting up front makes an N.close(id)
			// from the JS onClose handler a clean no-op rather than a re-close.
			n.mu.Lock()
			delete(n.chans, id)
			n.mu.Unlock()
			n.invoke(n.fnClosed, n.qc.NewInt64(id))
		})
	}
}

// invoke calls a retained JS dispatcher and frees the argument values (JS copies
// the bytes out, so the ArrayBuffer need not survive the call).
func (n *netHost) invoke(fn *qjs.Value, args ...*qjs.Value) {
	if _, err := n.qc.Invoke(fn, n.und, args...); err != nil {
		fmt.Fprintln(os.Stderr, "netHost: dispatcher error:", err)
	}
	for _, a := range args {
		a.Free()
	}
}

// The ChannelFactory over these primitives lives in host/native-shim.ts; Go's networking
// stops at the socket.
