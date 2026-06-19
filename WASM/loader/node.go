// node.go — assembles the engine node's HOST realm: the QuickJS realm that holds
// the platform primitives (sodium, fs, net) and the shared orchestration JS
// (Transport + NodeNetworkCore routing, the cap-bridge). The confined guest runs
// in its own realm (guest.go) and reaches this one only through host.call.
//
// This is the engine twin of host/main.ts boot(): same shape, but the platform
// backends are Go (wazero/libsodium, Go os, Go sockets) instead of node:net +
// libsodium-wrappers. The CLI + serve loop build on top of this.
package main

import (
	"fmt"

	"seedloader/qjs"
)

// installEngineHost wires the full host realm into qc: the Web polyfills, the
// sodium + fs + net (__net) primitives, the shared net route bundle (Transport /
// NodeNetworkCore / makeNetwork), and the cap-bridge (createCapBridge +
// __buildCapBridge). After this, host JS can build a network, a transport, and a
// cap-bridge, and the realm can host a guest (guest.go). el drives the realm's loop.
func installEngineHost(qc *qjs.Context, el *eventLoop, sd *libsodium, dir string) error {
	installPolyfills(qc)
	exposeSodium(qc, sd)
	if err := exposeFs(qc, dir); err != nil {
		return fmt.Errorf("fs: %w", err)
	}
	return installEngineNet(qc, el)
}

// installEngineNet adds just the networking + cap-bridge layer to a realm that
// already holds polyfills + sodium + fs: the __net socket primitive, the shared net
// route bundle (Transport / NodeNetworkCore / makeNetwork), the cap-bridge, the node
// setup glue, and the guest realm's async-net completion callbacks. Split out from
// installEngineHost as the networking layer proper — installEngineHost layers it over
// the polyfills + sodium + fs it installs first.
func installEngineNet(qc *qjs.Context, el *eventLoop) error {
	installPolyfills(qc) // idempotent; the net-route bundle needs TextEncoder/TextDecoder
	exposeNet(qc, el)
	if _, err := qc.Eval("host-netroute.gen.js", qjs.Code(hostNetRouteJS)); err != nil {
		return fmt.Errorf("net route bundle: %w", err)
	}
	if err := installWsCodec(qc); err != nil { // WS codec over __net raw + __ws (ws.wasm)
		return err
	}
	installNetwork(qc)
	exposeCapBridge(qc)
	if _, err := qc.Eval("engine-node.js", qjs.Code(engineNodeJS)); err != nil {
		return fmt.Errorf("node setup glue: %w", err)
	}

	// Completion callbacks for a guest's blocked net host.call: when the host realm's
	// Transport promise settles, __hostBridgeCall calls these, and loop.resolveCall
	// deposits the result in the call's netBlocking slot so awaitNetCall returns it.
	qc.Global().SetPropertyStr("__netDone", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		resp, err := qjs.JsTypedArrayToGo(t.Args()[1])
		if err != nil {
			el.resolveCall(t.Args()[0].Int64(), 1, nil, "net result not bytes")
			return nil, nil
		}
		el.resolveCall(t.Args()[0].Int64(), 0, resp, "")
		return nil, nil
	}))
	qc.Global().SetPropertyStr("__netFail", qc.Function(func(t *qjs.This) (*qjs.Value, error) {
		el.resolveCall(t.Args()[0].Int64(), 1, nil, t.Args()[1].String())
		return nil, nil
	}))
	return nil
}

// engineNodeJS is the node-assembly glue (the engine twin of main.ts boot()'s net +
// cap-bridge wiring): build identity / network / transport / cap-bridge from the
// primitives already in the realm, all driven by Go from main.go. Pure glue — the
// network, transport, and cap-bridge are the shared TS; this only stitches them with
// the Go-supplied identity, listen addresses, peers, and module-call hook.
const engineNodeJS = `
"use strict";
(function () {
  // The node keypair Go loaded/minted (libsodium ed25519 sk = seed‖pk), as the
  // {publicKey, privateKey} shape the cap-bridge + transport want.
  globalThis.__setIdentity = function (skHex) {
    const sk = fromHex(skHex);
    globalThis.__identity = { privateKey: sk, publicKey: sk.slice(32) };
    return toHex(sk.slice(32));
  };
  // Stand up the network + transport over the Go __net factory. Returns start()'s
  // Promise so Go can await the listener bind before reading the bound ports.
  globalThis.__startNode = function (listen, wsListen, timeoutMs) {
    globalThis.__network = makeNetwork(__identity, listen, wsListen);
    globalThis.__transport = new Transport(toHex(__identity.publicKey), __network, timeoutMs);
    return __network.start();
  };
  // The bound TCP/WS ports (0 when not listening), as [tcp u16 BE][ws u16 BE].
  globalThis.__nodePorts = function () {
    const p = __network.port | 0, w = __network.wsPort | 0;
    return new Uint8Array([(p >>> 8) & 255, p & 255, (w >>> 8) & 255, w & 255]);
  };
  // Teach the network a cohort peer's address (--peers entry: pk@host:port) and add
  // it to the reachable set (CAP_NET_PEERS). Mirrors the --peers wiring in main.ts.
  globalThis.__addPeer = function (spec) {
    const { peerId, addr } = parsePeerSpec(spec, "tcp");
    __network.addPeerAddr(peerId, addr);
    (globalThis.__peers = globalThis.__peers || []).push(peerId);
  };
  // Pre-dial the cohort so net.peers is connected before serving (best-effort).
  globalThis.__nodeReady = function () { return __network.ready().catch(() => {}); };
  // Build the single cap funnel for the loaded bundle's declared domains, over this
  // node's identity + transport + cohort, with module-call routed to Go (installed
  // wasm handlers). caps is the manifest's cap array.
  globalThis.__buildNodeBridge = function (caps) {
    __buildCapBridge(caps, __identity, __transport, globalThis.__peers || [], globalThis.__moduleCall);
  };
})();
`

// wireHolder routes incoming transport requests to a confined guest's `handle`
// entrypoint — "the shell runs the app" as a holder (README §13.7). The host realm
// must hold the bundle's Transport at globalThis.__transport. The guest answers
// synchronously from local fs + crypto, so onRequest gets bytes back immediately.
func wireHolder(hostQc *qjs.Context, g *guestRealm) {
	hostQc.Global().SetPropertyStr("__serveHandle", hostQc.Function(func(t *qjs.This) (*qjs.Value, error) {
		typ := byte(t.Args()[0].Int32())
		payload, err := qjs.JsTypedArrayToGo(t.Args()[1])
		if err != nil {
			return t.Context().NewArrayBuffer(nil), nil
		}
		resp, err := g.serveHandle(typ, payload)
		if err != nil {
			return t.Context().NewArrayBuffer(nil), nil
		}
		return t.Context().NewArrayBuffer(resp), nil
	}))
	// net.ts dispatchRequest does frame.set(resp, …), so the handler must return a
	// Uint8Array — wrap the ArrayBuffer __serveHandle hands back.
	if _, err := hostQc.Eval("wire-holder.js", qjs.Code(
		`__transport.onRequest((from, type, payload) => new Uint8Array(__serveHandle(type, payload)));`,
	)); err != nil {
		panic(fmt.Sprintf("wireHolder: %v", err))
	}
}
