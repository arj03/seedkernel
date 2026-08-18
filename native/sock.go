// sock.go — the TCP socket primitive exposed to QuickJS as `__net`: open a socket, hand
// its bytes to JS, send, close. No message boundaries here — the wire codec, the PeerLink
// handshake, routing and request/response run as the transport bundle's guest program
// (transport/src) over the unframed RawLink shape this module hands it.
//
// Bytes cross the Go↔JS boundary only on the event-loop goroutine: reader goroutines hand
// each message to el.post, and the loop delivers it into JS through the retained
// __netDeliver/__netClosed/__netAccept dispatchers, then pumps. The shared shim
// (host/native-shim.ts) defines those dispatchers; `netHost.retain` picks them up once the
// bundle is up.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"seedloader/qjs"
)

// maxLiveChannels caps how many sockets this host holds at once. Accepting is the one
// thing here that happens without anyone asking, and each accepted socket costs two
// goroutines, a 64 KiB read buffer and a map entry BEFORE the transport guest has looked
// at it. The guest's own link budgets (transport-host.ts) are the policy; this sits an
// order of magnitude above their sum so it never fires in normal operation, and bounds the
// window they cannot — a flood arriving faster than the loop drains its posted accepts, or
// a guest that has stopped refusing at all.
//
// A var, not a const, only so a test can shrink it.
var maxLiveChannels = 4096

// acceptErrBackoff paces the accept loop after a non-fatal error. EMFILE makes Accept fail
// immediately and repeatedly; returning would kill serving for good over a transient
// condition, and retrying flat out would spin a core.
const acceptErrBackoff = 20 * time.Millisecond

type netHost struct {
	el  *eventLoop
	qc  *qjs.Context
	und *qjs.Value // a reusable `undefined` for the `this` of dispatcher calls

	mu        sync.Mutex
	chans     map[int64]rawChannel
	nextID    int64
	listeners []net.Listener // bound listeners, closed on network teardown

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

	// One socket kind: a raw byte duplex. Which codec runs over it is the transport
	// bundle's business, never Go's.
	o.SetPropertyStr("connect", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		if len(t.Args()) < 2 {
			return t.Context().NewInt64(0), nil // 0 is never a live id (get → nil)
		}
		addr := net.JoinHostPort(t.Args()[0].String(), strconv.Itoa(int(t.Args()[1].Int32())))
		return t.Context().NewInt64(n.dial(addr)), nil
	}))
	o.SetPropertyStr("listen", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		if len(t.Args()) < 2 {
			return t.Context().NewInt32(-1), nil // -1: the shim throws on a failed bind
		}
		bound, err := n.listen(t.Args()[0].String(), int(t.Args()[1].Int32()))
		if err != nil {
			return t.Context().NewInt32(-1), nil
		}
		return t.Context().NewInt32(int32(bound)), nil
	}))
	o.SetPropertyStr("send", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		if len(t.Args()) < 2 {
			return nil, nil
		}
		id := t.Args()[0].Int64()
		if ch := n.get(id); ch != nil {
			// b is a fresh copy (JsTypedArrayToGo), so send takes ownership without
			// another. It only queues — the write happens on the channel's writer
			// goroutine, never here on the loop goroutine (net.go writeLoop).
			if b, err := qjs.JsTypedArrayToGo(t.Args()[1]); err == nil {
				ch.send(b)
			}
		}
		return nil, nil
	}))
	o.SetPropertyStr("closeListeners", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		n.closeListeners()
		return nil, nil
	}))
	o.SetPropertyStr("close", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		if len(t.Args()) < 1 {
			return nil, nil
		}
		// A deliberate close() sets dead WITHOUT firing onClose (net.go), and the readLoop
		// error chasing it short-circuits in fail() — so the onClose registry-drop below
		// never runs for a local close. Dropping the entry here instead is what keeps every
		// local close (the guest closes on each rejected handshake, and on a duplicate-dial
		// resolution) from leaking its n.chans slot: attacker-triggerable memory
		// exhaustion. The JS shim deletes from its own chans Map for the same reason.
		id := t.Args()[0].Int64()
		if ch := n.get(id); ch != nil {
			ch.close()
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
// (host/native-shim.ts), which runs when host-shell.gen.js is evaluated — after exposeNet
// installed `__net`, and before any socket delivers.
func (n *netHost) retain() error {
	g := n.qc.Global()
	n.fnDeliver = g.GetPropertyStr("__netDeliver")
	n.fnClosed = g.GetPropertyStr("__netClosed")
	n.fnAccept = g.GetPropertyStr("__netAccept")
	// IsUndefined, not nil: a missing property is a *Value wrapping JS_UNDEFINED and
	// GetPropertyStr never returns Go nil (qjs/value.go), so a nil check would compile,
	// never fire, and turn this named boot error into "not a function" at the first frame.
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
// only slack is between here and the caller's insert — at most one connection per accept
// goroutine, which is why the cap sits far above the guest's link budgets.
func (n *netHost) allocInbound() (int64, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.chans) >= maxLiveChannels {
		return 0, false
	}
	n.nextID++
	return n.nextID, true
}

// dial opens an outbound byte duplex. It connects in the background and buffers
// pre-connect sends, so JS can wrap the id and send its HELLO (or WS upgrade) immediately;
// the JS channel is registered in the same JS turn, before the loop can process a frame.
func (n *netHost) dial(addr string) int64 {
	id := n.alloc()
	ch := newDialChannel(addr, n.onMsg(id), n.onClose(id))
	n.mu.Lock()
	n.chans[id] = ch
	n.mu.Unlock()
	return id
}

// listen accepts inbound byte duplexes. The read goroutine starts only inside the posted
// task, AFTER __netAccept created the JS channel — otherwise it could deliver a frame
// before JS has a channel to route it to.
func (n *netHost) listen(host string, port int) (int, error) {
	// No buffer options: an explicit SO_RCVBUF pre-bind locks out receive autotuning (see
	// the note above dialTCP in net.go). KeepAlive is explicit so an accepted socket whose
	// peer vanishes without a FIN is reclaimed (tcpKeepAlive).
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
				// Anything else is this process's condition, not the listener's end (a
				// descriptor exhaustion, a socket reset between SYN and accept): pause and
				// keep serving rather than retiring the port.
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
			n.mu.Lock()
			n.chans[id] = ch
			n.mu.Unlock()
			n.el.post(func() {
				n.invoke(n.fnAccept, n.qc.NewInt32(int32(bound)), n.qc.NewInt64(id))
				start() // safe now: the JS channel exists
			})
		}
	}()
	return bound, nil
}

// closeListeners closes every bound listener, so each accept goroutine's ln.Accept()
// errors and exits, releasing the fd and the goroutine. Wired to the driver's
// channels.close (native-shim.ts) so a network teardown leaks neither.
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
	c := newInboundChannel(conn, n.onMsg(id), n.onClose(id))
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
			// Drop the channel before notifying JS. onClose only fires from fail(), which
			// has already closed the socket, so there is no fd to release here — and
			// deleting up front makes an N.close(id) from the JS onClose handler a clean
			// no-op rather than a re-close. The JS shim does the same.
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
		fmt.Println("netHost: dispatcher error:", err)
	}
	for _, a := range args {
		a.Free()
	}
}

// The ChannelFactory over these primitives, and the transport driver built on it, live in
// host/native-shim.ts. Go's networking stops at the socket.
