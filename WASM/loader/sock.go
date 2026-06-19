// sock.go — the TCP socket primitive exposed to QuickJS as `__net`. This is the
// only networking that stays in Go: open a
// socket, frame whole messages over it, deliver them to JS, send, close. The
// protocol on top — the PeerLink handshake, routing, request/response — runs as
// the shared host JS (net-link.ts, net.ts, net-node.ts) over the RawChannel shape
// this module hands it. It reuses tcpChannel (net.go) for the [len][bytes] framing.
//
// Bytes cross the Go↔JS boundary only on the event-loop goroutine: socket reader
// goroutines hand each message to el.post, which the loop delivers into JS via the
// retained __netDeliver/__netClosed/__netAccept dispatchers and then pumps.
package main

import (
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

	mu     sync.Mutex
	chans  map[int64]rawChannel
	nextID int64

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

	connect := func(ws bool) *qjs.Value {
		return fn(func(t *qjs.This) (*qjs.Value, error) {
			addr := net.JoinHostPort(t.Args()[0].String(), strconv.Itoa(int(t.Args()[1].Int32())))
			return t.Context().NewInt64(n.dial(addr, ws)), nil
		})
	}
	listen := func(ws bool) *qjs.Value {
		return fn(func(t *qjs.This) (*qjs.Value, error) {
			bound, err := n.listen(t.Args()[0].String(), int(t.Args()[1].Int32()), ws)
			if err != nil {
				return t.Context().NewInt32(-1), nil
			}
			return t.Context().NewInt32(int32(bound)), nil
		})
	}
	o.SetPropertyStr("connect", connect(false))   // node↔node, length-framed TCP
	o.SetPropertyStr("connectWS", connect(true))  // node dialing a WS endpoint
	o.SetPropertyStr("listen", listen(false))     // accept node↔node TCP
	o.SetPropertyStr("listenWS", listen(true))    // accept browser↔node WebSocket
	o.SetPropertyStr("send", fn(func(t *qjs.This) (*qjs.Value, error) {
		id := t.Args()[0].Int64()
		if ch := n.get(id); ch != nil {
			if b, err := qjs.JsTypedArrayToGo(t.Args()[1]); err == nil {
				ch.send(b)
			}
		}
		return nil, nil
	}))
	o.SetPropertyStr("close", fn(func(t *qjs.This) (*qjs.Value, error) {
		if ch := n.get(t.Args()[0].Int64()); ch != nil {
			ch.close()
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

// dial opens an outbound channel (TCP, or WS when ws). Both connect in the
// background and buffer pre-connect sends, so JS can makeRawChannel(id) and
// PeerLink can sendHello() immediately; the JS channel is registered (synchronously,
// in the same JS turn) before the loop ever processes a delivered frame.
func (n *netHost) dial(addr string, ws bool) int64 {
	id := n.alloc()
	var ch rawChannel
	if ws {
		ch = newWSChannelDial(addr, n.onMsg(id), n.onClose(id))
	} else {
		ch = newTCPChannelDial(addr, n.onMsg(id), n.onClose(id))
	}
	n.mu.Lock()
	n.chans[id] = ch
	n.mu.Unlock()
	return id
}

// listen accepts inbound channels (TCP, or WS when ws). The read/handshake
// goroutine is started only from inside the posted task, AFTER __netAccept has
// created the JS channel — otherwise the read goroutine could deliver a frame
// before JS has a channel to route it to.
func (n *netHost) listen(host string, port int, ws bool) (int, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return 0, err
	}
	bound := ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			id := n.alloc()
			ch, start := n.wrapInbound(id, conn, ws)
			n.mu.Lock()
			n.chans[id] = ch
			n.mu.Unlock()
			cid := id
			n.el.post(func() {
				n.invoke(n.fnAccept, n.qc.NewInt32(int32(bound)), n.qc.NewInt64(cid))
				start() // safe now: the JS channel exists
			})
		}
	}()
	return bound, nil
}

// wrapInbound builds a channel for an accepted socket but defers its read/handshake
// goroutine to the returned start(), so the loop registers the JS channel first.
func (n *netHost) wrapInbound(id int64, conn net.Conn, ws bool) (rawChannel, func()) {
	if ws {
		w := &wsChannel{onMsg: n.onMsg(id), onClose: n.onClose(id), client: false, conn: conn, parser: newWSParser(true)}
		return w, func() { go w.runServer() }
	}
	tc := &tcpChannel{onMsg: n.onMsg(id), onClose: n.onClose(id), conn: conn, open: true}
	return tc, func() { go tc.readLoop() }
}

// onMsg/onClose run on a socket reader goroutine; they hand the work to the loop
// goroutine, which owns all QuickJS access.
func (n *netHost) onMsg(id int64) func([]byte) {
	return func(b []byte) {
		msg := append([]byte(nil), b...)
		n.el.post(func() { n.invoke(n.fnDeliver, n.qc.NewInt64(id), n.qc.NewArrayBuffer(msg)) })
	}
}

func (n *netHost) onClose(id int64) func() {
	return func() {
		n.el.post(func() {
			n.invoke(n.fnClosed, n.qc.NewInt64(id))
			n.mu.Lock()
			delete(n.chans, id)
			n.mu.Unlock()
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
  const listeners = new Map(); // bound port -> onAccept(channel)

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
      close: () => N.close(id),
    };
  }

  globalThis.netConnect = (host, port) => makeRawChannel(N.connect(host, port));
  globalThis.netConnectWS = (host, port) => makeRawChannel(N.connectWS(host, port));
  globalThis.netListen = (host, port, onAccept) => {
    const bound = N.listen(host, port);
    if (bound < 0) throw new Error("netListen: bind failed");
    listeners.set(bound, onAccept);
    return bound;
  };
  globalThis.netListenWS = (host, port, onAccept) => {
    const bound = N.listenWS(host, port);
    if (bound < 0) throw new Error("netListenWS: bind failed");
    listeners.set(bound, onAccept);
    return bound;
  };
  globalThis.__netDeliver = (id, bytes) => { const c = chans.get(id); if (c) c.deliver(new Uint8Array(bytes)); };
  globalThis.__netClosed = (id) => { const c = chans.get(id); if (c) c.closed(); };
  globalThis.__netAccept = (port, id) => { const f = listeners.get(port); if (f) f(makeRawChannel(id)); };
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
      close: () => {},
    };
    return new NodeNetworkCore({ identity, sodium, channels, listen, wsListen });
  };
})();
`
