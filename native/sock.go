// sock.go — the TCP socket primitive exposed to QuickJS as `__net`. This is the
// only networking that stays in Go: open a
// socket, frame whole messages over it, deliver them to JS, send, close. The
// protocol on top — the PeerLink handshake, routing, request/response — runs as
// the shared host JS (net-link.ts, net.ts, net-node.ts) over the RawChannel shape
// this module hands it. It reuses sockChannel (net.go) for the [len][bytes] framing.
//
// Bytes cross the Go↔JS boundary only on the event-loop goroutine: socket reader
// goroutines hand each message to el.post, which the loop delivers into JS via the
// retained __netDeliver/__netClosed/__netAccept dispatchers and then pumps.
package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"sync"

	"seedloader/qjs"
)

type netHost struct {
	el  *eventLoop
	qc  *qjs.Context
	und *qjs.Value // a reusable `undefined` for the `this` of dispatcher calls

	mu        sync.Mutex
	chans     map[int64]rawChannel
	nextID    int64
	listeners []net.Listener // bound listeners, closed on network teardown

	// Retained JS dispatchers (host.js-side router into per-channel callbacks).
	fnDeliver *qjs.Value
	fnClosed  *qjs.Value
	fnAccept  *qjs.Value
}

// exposeNet installs `__net` into the realm and the `netShimJS` glue that turns a
// channel id into a RawChannel. Returns the netHost (kept alive for the process).
func exposeNet(qc *qjs.Context, el *eventLoop) *netHost {
	n := &netHost{el: el, qc: qc, und: qc.NewUndefined(), chans: map[int64]rawChannel{}}
	o := qc.NewObject()
	fn := func(g func(*qjs.This) (*qjs.Value, error)) *qjs.Value { return qc.Function(g) }

	connect := func(raw bool) *qjs.Value {
		return fn(func(t *qjs.This) (*qjs.Value, error) {
			if len(t.Args()) < 2 {
				return t.Context().NewInt64(0), nil // 0 is never a live id (get → nil)
			}
			addr := net.JoinHostPort(t.Args()[0].String(), strconv.Itoa(int(t.Args()[1].Int32())))
			return t.Context().NewInt64(n.dial(addr, raw)), nil
		})
	}
	listen := func(raw bool) *qjs.Value {
		return fn(func(t *qjs.This) (*qjs.Value, error) {
			if len(t.Args()) < 2 {
				return t.Context().NewInt32(-1), nil // -1: the shim throws on a failed bind
			}
			bound, err := n.listen(t.Args()[0].String(), int(t.Args()[1].Int32()), raw)
			if err != nil {
				return t.Context().NewInt32(-1), nil
			}
			return t.Context().NewInt32(int32(bound)), nil
		})
	}
	o.SetPropertyStr("connect", connect(false))   // node↔node, length-framed TCP
	o.SetPropertyStr("connectRaw", connect(true)) // raw byte stream (under the JS WS codec)
	o.SetPropertyStr("listen", listen(false))     // accept node↔node TCP
	o.SetPropertyStr("listenRaw", listen(true))   // accept raw byte streams (browser↔node WS)
	o.SetPropertyStr("send", fn(func(t *qjs.This) (*qjs.Value, error) {
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
	o.SetPropertyStr("closeListeners", fn(func(t *qjs.This) (*qjs.Value, error) {
		n.closeListeners()
		return nil, nil
	}))
	o.SetPropertyStr("close", fn(func(t *qjs.This) (*qjs.Value, error) {
		if len(t.Args()) < 1 {
			return nil, nil
		}
		// A deliberate close() sets dead WITHOUT firing onClose (net.go: the owner asked
		// for it), and the readLoop error chasing it short-circuits in fail() on dead — so
		// the onClose registry-drop (below) never runs for a locally-initiated close. Drop
		// the entry here instead, or every local close (net-link.ts closes on each rejected
		// handshake, net-route.ts on a duplicate-dial resolution) leaks its n.chans slot
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

	if _, err := qc.Eval("net-shim.js", qjs.Code(netShimJS)); err != nil {
		panic(fmt.Sprintf("net shim: %v", err))
	}
	g := qc.Global()
	n.fnDeliver = g.GetPropertyStr("__netDeliver") // owned refs, kept for process lifetime
	n.fnClosed = g.GetPropertyStr("__netClosed")
	n.fnAccept = g.GetPropertyStr("__netAccept")
	return n
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

// dial opens an outbound channel: length-framed TCP, or a raw byte stream when raw
// (the transport under the JS WebSocket codec). Both connect in the background and
// buffer pre-connect sends, so JS can wrap the id and PeerLink can sendHello() (or
// the WS client can write its upgrade request) immediately; the JS channel is
// registered (synchronously, in the same JS turn) before the loop ever processes a
// delivered frame.
func (n *netHost) dial(addr string, raw bool) int64 {
	id := n.alloc()
	ch := newDialChannel(addr, framingFor(raw), n.onMsg(id), n.onClose(id))
	n.mu.Lock()
	n.chans[id] = ch
	n.mu.Unlock()
	return id
}

// listen accepts inbound channels (length-framed TCP, or raw byte streams when
// raw). The read goroutine is started only from inside the posted task, AFTER
// __netAccept has created the JS channel — otherwise the read goroutine could
// deliver a frame before JS has a channel to route it to.
func (n *netHost) listen(host string, port int, raw bool) (int, error) {
	// Control sets SO_RCVBUF/SO_SNDBUF on the listening socket BEFORE bind, so every
	// accepted connection inherits the large buffer at the handshake and negotiates a
	// big TCP window scale. Raising the buffer on an already-accepted socket (tuneTCP)
	// is too late to fix the window scale — which is why a high-RTT receive (PUT into a
	// holder) otherwise stays window-limited even with a large post-accept SO_RCVBUF.
	lc := net.ListenConfig{Control: controlSocketBuffers}
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
				return // listener closed (closeListeners) or fatal accept error — exit the goroutine
			}
			id := n.alloc()
			ch, start := n.wrapInbound(id, conn, raw)
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
// Wired to makeNetwork's channels.close so a realm/network teardown (tests, any future
// re-serve) doesn't leak a listener + accept goroutine until os.Exit.
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
func (n *netHost) wrapInbound(id int64, conn net.Conn, raw bool) (rawChannel, func()) {
	// Socket buffers are already set on the listener (pre-bind, via ListenConfig.Control)
	// and inherited here, so the accepted connection's window scale is sized correctly.
	c := newInboundChannel(framingFor(raw), conn, n.onMsg(id), n.onClose(id))
	return c, func() { go c.proto.readLoop(c) }
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

// netShimJS turns the byte-level __net into the RawChannel shape net-link.ts wants,
// and routes Go's deliver/close/accept callbacks to the right channel. Loader glue
// (platform binding), not shared TS — like sodiumShimJS.
const netShimJS = `
"use strict";
(function () {
  const N = __net;
  const chans = new Map();     // id -> { deliver, closed }
  const listeners = new Map(); // bound port -> accept(id)

  // A whole-message RawChannel (TCP, length-framed in Go): the routing core's
  // PeerLink drives this directly.
  function makeRawChannel(id) {
    let onMsg = () => {}, onClose = () => {};
    chans.set(id, {
      deliver: (bytes) => onMsg(bytes),
      closed: () => { chans.delete(id); onClose(); },
    });
    return {
      send: (bytes) => N.send(id, bytes),
      onMessage: (cb) => { onMsg = cb; },
      onClose: (cb) => { onClose = cb; },
      // A deliberate close never fires __netClosed (Go closes silently), so drop our own
      // map entry here too — otherwise every local close leaks a chans entry unbounded.
      close: () => { N.close(id); chans.delete(id); },
    };
  }

  // A raw byte duplex (no framing): the transport under the JS WebSocket codec
  // (net-frame.ts WsClientChannel/WsServerChannel), which frames on top.
  function makeRawStream(id) {
    let onData = () => {}, onClose = () => {};
    chans.set(id, {
      deliver: (bytes) => onData(bytes),
      closed: () => { chans.delete(id); onClose(); },
    });
    return {
      write: (bytes) => N.send(id, bytes),
      onData: (cb) => { onData = cb; },
      onClose: (cb) => { onClose = cb; },
      close: () => { N.close(id); chans.delete(id); }, // see makeRawChannel: drop on deliberate close
    };
  }

  globalThis.netConnect = (host, port) => makeRawChannel(N.connect(host, port));
  globalThis.netConnectRaw = (host, port) => makeRawStream(N.connectRaw(host, port));
  globalThis.netListen = (host, port, onAccept) => {
    const bound = N.listen(host, port);
    if (bound < 0) throw new Error("netListen: bind failed");
    listeners.set(bound, (id) => onAccept(makeRawChannel(id)));
    return bound;
  };
  globalThis.netListenRaw = (host, port, onAccept) => {
    const bound = N.listenRaw(host, port);
    if (bound < 0) throw new Error("netListenRaw: bind failed");
    listeners.set(bound, (id) => onAccept(makeRawStream(id)));
    return bound;
  };
  // Teardown closes every bound listener in Go, so every accept closure here is
  // stale — clear them too, or they pin their onAccept graphs for the process
  // lifetime in a long-lived holder that re-serves.
  globalThis.netCloseListeners = () => { N.closeListeners(); listeners.clear(); };
  globalThis.__netDeliver = (id, bytes) => { const c = chans.get(id); if (c) c.deliver(new Uint8Array(bytes)); };
  globalThis.__netClosed = (id) => { const c = chans.get(id); if (c) c.closed(); };
  globalThis.__netAccept = (port, id) => { const a = listeners.get(port); if (a) a(id); };
})();
`

// installNetwork wires the shared NodeNetworkCore (host-netroute.gen.js) to the Go
// socket primitive via a ChannelFactory over __net, exposing makeNetwork(identity,
// listen, wsListen). Eval AFTER the route bundle, sodium, and the net shim.
func installNetwork(qc *qjs.Context) {
	if _, err := qc.Eval("engine-net.js", qjs.Code(engineNetworkJS)); err != nil {
		panic(fmt.Sprintf("install network: %v", err))
	}
}

const engineNetworkJS = `
"use strict";
(function () {
  // The engine ChannelFactory: the routing core's one platform seam, backed by the
  // Go __net primitive. connect/listen return/produce RawChannels identically to
  // the node:net factory, so NodeNetworkCore runs unchanged.
  globalThis.makeNetwork = function (identity, listen, wsListen) {
    const channels = {
      connect: (addr) => addr.transport === "ws"
        ? netConnectWS(addr.host, addr.port)
        : netConnect(addr.host, addr.port),
      listen: (tcp, ws, onAccept) => {
        let port = 0, wsPort = 0;
        if (tcp) port = netListen(tcp.host, tcp.port, onAccept);
        if (ws) wsPort = netListenWS(ws.host, ws.port, onAccept);
        return Promise.resolve({ port, wsPort });
      },
      close: () => { netCloseListeners(); }, // close bound listeners + their accept goroutines on teardown
    };
    return new NodeNetworkCore({ identity, sodium, channels, listen, wsListen });
  };
})();
`
