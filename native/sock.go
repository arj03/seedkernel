// sock.go — the TCP socket primitive exposed to QuickJS as `__net`. This is the only
// networking that stays in Go: open a socket, hand its bytes to JS, send, close. There
// are no message boundaries here — the wire codec, the PeerLink handshake, routing and
// request/response all run as the transport bundle's guest program (transport/src)
// over the unframed RawLink shape this module hands it.
//
// Bytes cross the Go↔JS boundary only on the event-loop goroutine: socket reader
// goroutines hand each message to el.post, which the loop delivers into JS via the
// retained __netDeliver/__netClosed/__netAccept dispatchers and then pumps. Those
// dispatchers are defined by the shared shim (host/native-shim.ts — the ex-netShimJS
// shaping, moved out of Go) at host-shell.gen.js evaluation time, and retained by
// `netHost.retain` once the bundle is up.
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

// maxLiveChannels caps how many sockets this host holds at once, inbound and outbound
// together. Accepting is the one thing here that happens without anyone asking: the
// loop takes whatever the kernel hands it, and each accepted socket costs two
// goroutines, a 64 KiB read buffer and a map entry BEFORE the transport guest has
// looked at it. The guest's own link budgets (transport-host.ts: 1024 unverified + 256
// verified + 256 authed) are the policy and stay the policy — this sits an order of
// magnitude above their sum so that in normal operation it never fires. What it bounds
// is the window those budgets cannot: a flood arriving faster than the loop goroutine
// drains its posted accepts, and the case of a guest that has stopped refusing at all.
// Over the cap the socket is closed immediately, before any of it is spent.
// A var, not a const, only so a test can shrink it: nothing in the process writes it.
var maxLiveChannels = 4096

// acceptErrBackoff paces the accept loop after a non-fatal error. EMFILE (the process
// out of descriptors) makes Accept fail immediately and repeatedly; returning on it
// would kill serving for good over a transient condition, and retrying flat out would
// spin a core. The loop pauses instead and carries on once descriptors free up.
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

// exposeNet installs `__net` into the realm: the byte-level socket primitive. The
// shaping that turns it into RawLink objects — and the __netDeliver/__netClosed/
// __netAccept dispatchers Go's reader goroutines route through — is typed TS in
// host/native-shim.ts, evaluated with the shared bundle; `netHost.retain` picks the
// dispatchers up once that bundle is up (main.go boot).
func exposeNet(qc *qjs.Context, el *eventLoop) *netHost {
	n := &netHost{el: el, qc: qc, und: qc.NewUndefined(), chans: map[int64]rawChannel{}}
	o := qc.NewObject()

	// One socket kind: a raw byte duplex. Which codec runs over it — length-prefixed
	// or RFC 6455 — is the transport bundle's, never Go's.
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
			// another copy. It only queues: the socket write happens on the channel's
			// writer goroutine, never here on the loop goroutine (net.go writeLoop).
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
		// A deliberate close() sets dead WITHOUT firing onClose (net.go: the owner asked
		// for it), and the readLoop error chasing it short-circuits in fail() on dead — so
		// the onClose registry-drop (below) never runs for a locally-initiated close. Drop
		// the entry here instead, or every local close (the guest closes on each rejected
		// handshake, and again on a duplicate-dial resolution) leaks its n.chans slot
		// without bound — an attacker-triggerable memory exhaustion. The JS shim mirrors
		// this by deleting from its own chans Map in close(). This deletes without firing
		// onClose, preserving the deliberate-close semantic (fail() is already short-circuited).
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
// (host/native-shim.ts), which runs when host-shell.gen.js is evaluated — AFTER
// exposeNet installed `__net`, and before any socket delivers. The shaping that used
// to live here as a Go string (netShimJS) is typed TS now; Go only retains callbacks.
func (n *netHost) retain() error {
	g := n.qc.Global()
	n.fnDeliver = g.GetPropertyStr("__netDeliver")
	n.fnClosed = g.GetPropertyStr("__netClosed")
	n.fnAccept = g.GetPropertyStr("__netAccept")
	// IsUndefined, not nil: a missing property is a *Value wrapping JS_UNDEFINED, and
	// GetPropertyStr never returns Go nil (qjs/value.go). A nil check here would compile,
	// never fire, and turn this named boot-time error into QuickJS's "not a function" at
	// the first frame.
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

// allocInbound is alloc for a socket nobody asked for: it refuses once the host already
// holds maxLiveChannels. The count is read under the same lock that hands out the id,
// so the only slack is between here and the caller's insert — at most one connection
// per accept goroutine (one per bound listener), which is why the cap sits far above
// the guest's link budgets rather than exactly on them.
func (n *netHost) allocInbound() (int64, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.chans) >= maxLiveChannels {
		return 0, false
	}
	n.nextID++
	return n.nextID, true
}

// dial opens an outbound byte duplex. It connects in the background and
// buffers pre-connect sends, so JS can wrap the id and PeerLink can sendHello() (or
// the WS client can write its upgrade request) immediately; the JS channel is
// registered (synchronously, in the same JS turn) before the loop ever processes a
// delivered frame.
func (n *netHost) dial(addr string) int64 {
	id := n.alloc()
	ch := newDialChannel(addr, n.onMsg(id), n.onClose(id))
	n.mu.Lock()
	n.chans[id] = ch
	n.mu.Unlock()
	return id
}

// listen accepts inbound byte duplexes. The read goroutine is started only from inside the posted task, AFTER
// __netAccept has created the JS channel — otherwise the read goroutine could
// deliver a frame before JS has a channel to route it to.
func (n *netHost) listen(host string, port int) (int, error) {
	// Accepted sockets keep default buffer options on purpose: a fixed SO_RCVBUF set
	// pre-bind is clamped to net.core.rmem_max (208 KiB stock) and locks out receive
	// autotuning, pinning a high-RTT PUT into a holder near a 64 KiB window (~2.5 MB/s
	// at 26 ms RTT). Defaults autotune to tcp_rmem[2] (~6 MB) and fill the link (see
	// the note above dialTCP in net.go).
	// KeepAlive is set explicitly (not left to Go's default) so an accepted socket whose
	// peer vanishes without a FIN is reclaimed rather than held until the process exits
	// — see the note on tcpKeepAlive in net.go.
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
				// Anything else is this process's condition, not the listener's end: a
				// descriptor exhaustion, a socket the kernel reset between SYN and accept.
				// Pause and keep serving (acceptErrBackoff) rather than retiring the port.
				time.Sleep(acceptErrBackoff)
				continue
			}
			// The ceiling (maxLiveChannels), applied before a single goroutine or buffer
			// is spent on the socket: over it, the connection is dropped on the floor.
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

// closeListeners closes every bound listener, which makes each accept goroutine's
// ln.Accept() return an error and exit — releasing the listener fd and the goroutine.
// Wired to the driver's channels.close (native-shim.ts) so a realm/network teardown
// (tests, any future re-serve) doesn't leak a listener + accept goroutine until os.Exit.
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
	// The accepted socket keeps the kernel's default buffers, inherited from a listener
	// that sets none — deliberately, so receive autotuning stays on (see listen above).
	c := newInboundChannel(conn, n.onMsg(id), n.onClose(id))
	return c, func() { go c.readLoop() }
}

// onMsg/onClose run on a socket reader goroutine; they hand the work to the loop
// goroutine, which owns all QuickJS access.
func (n *netHost) onMsg(id int64) func([]byte) {
	return func(b []byte) {
		// b is freshly allocated and owned by us (rawChannel onMsg contract), so capture
		// it directly instead of copying. Dropping that copy removes a full extra pass over
		// every inbound byte — on a 1 MiB receive, one fewer 1 MiB copy before it reaches JS.
		n.el.post(func() { n.invoke(n.fnDeliver, n.qc.NewInt64(id), n.qc.NewArrayBuffer(b)) })
	}
}

func (n *netHost) onClose(id int64) func() {
	return func() {
		n.el.post(func() {
			// Drop the channel before notifying JS. onClose only ever fires from the
			// channel's fail() path, which has already closed the socket — so there is
			// no fd to release here. Deleting up front means an N.close(id) issued from
			// the JS onClose handler resolves to a clean no-op (get → nil) rather than
			// re-closing a dead channel; it mirrors the JS shim, which deletes from its
			// own map before invoking onClose.
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

// The ChannelFactory over these primitives — and the transport driver built on it —
// live in host/native-shim.ts, where they are typed against the shared interfaces.
// Go's networking stops at the socket.
