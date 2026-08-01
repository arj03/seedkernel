package main

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"seedloader/qjs"
)

// The full routing + transport runs as the
// shared net-route.ts NodeNetworkCore + net.ts Transport inside QuickJS, over the
// Go socket primitive. Two independent nodes (each its own NodeNetworkCore +
// Transport) complete the PeerLink handshake, route, and exchange a typed
// request/response over a real loopback socket — the dial/accept/promote/deliver
// path and the correlation/timeout layer, none of it logic in Go.
//
// Only the WebSocket transport is exercised here — it drives the full WS path: the
// raw Go byte stream (sock.go connectRaw/listenRaw), the shared net-frame WsChannel,
// and the RFC 6455 framing in ws.wasm (via __ws). The TCP twin of this exact flow is
// covered by asyncnet_test (makeNetwork + Transport + a confined guest over a real
// TCP socket) and end-to-end against real node/bun nodes by scripts/loader-interop.sh.

// The realm a networking test runs in is the production one: boot() installs the __net
// socket primitive and ws.wasm, then evaluates the shared bundle carrying the routing
// core — so `makeNetwork` here is the very factory the binary boots with, not a harness
// that assembles the stack a second way.

func TestTwoNodeRequestResponseWS(t *testing.T) {
	runTwoNode(t, "ws", "wsPort", `undefined, { host: "127.0.0.1", port: 0 }`)
}

// listenArgs is the `listen, wsListen` pair — makeNetwork's third and fourth arguments,
// the second being the contact secret (§12.6). Both nodes here are open (no secret), so
// the pair is what selects which transport A binds.
func runTwoNode(t *testing.T, transport, portField, listenArgs string) {
	bootRealm(t)

	// A listens; B dials A and asks; A's request handler echoes the payload back.
	harness := fmt.Sprintf(`
		globalThis.startTest = async function () {
		  const idA = sodium.crypto_sign_keypair();
		  const idB = sodium.crypto_sign_keypair();
		  const aId = toHex(idA.publicKey), bId = toHex(idB.publicKey);
		  const netA = makeNetwork(idA, undefined, %s);
		  const netB = makeNetwork(idB, undefined, undefined, undefined);
		  await netA.start();
		  const tA = new Transport(aId, netA, 1000);
		  const tB = new Transport(bId, netB, 1000);
		  tA.onRequest((from, proto, payload) => payload);
		  netB.addPeerAddr(aId, { host: "127.0.0.1", port: netA.%s, transport: "%s" });
		  return await tB.request(aId, new TextEncoder().encode("_test"), new Uint8Array([10, 20, 30]));
		};
	`, listenArgs, portField, transport)
	if _, err := qc.Eval("transport-harness.js", qjs.Code(harness)); err != nil {
		t.Fatal("harness:", err)
	}

	kind, value, msg, err := el.await("startTest()", 8*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if kind != 0 {
		t.Fatalf("request did not resolve: kind=%d msg=%q", kind, msg)
	}
	if want := []byte{10, 20, 30}; !bytes.Equal(value, want) {
		t.Fatalf("response = %v, want %v", value, want)
	}
}
