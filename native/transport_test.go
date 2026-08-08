package main

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"seedloader/qjs"
)

// The full routing + transport runs as the
// transport bundle's guest program inside QuickJS, over the
// Go socket primitive. Two independent nodes (each running its own transport
// guest) complete the PeerLink handshake, route, and exchange a typed
// request/response over a real loopback socket — the dial/accept/promote/deliver
// path and the correlation/timeout layer, none of it logic in Go.
//
// Only the WebSocket transport is exercised here — it drives the full WS path: the
// raw Go byte stream (sock.go connectRaw/listenRaw), the shared net-frame WsChannel,
// and the RFC 6455 framing in ws.wasm (via __ws). The TCP twin of this exact flow is
// covered by asyncnet_test (a confined guest over a real TCP socket) and end-to-end
// against real node/bun nodes by scripts/loader-interop.sh.

// The realm a networking test runs in is the production one: boot() installs the __net
// socket primitive and ws.wasm, then evaluates the shared bundle carrying the routing
// core — so `makeTransportNode` here is the very factory the binary boots with, not a
// harness that assembles the stack a second way.

func TestTwoNodeRequestResponseWS(t *testing.T) {
	runTwoNode(t, "ws", "wsPort", `wsListen: { host: "127.0.0.1", port: 0 },`)
}

// listenArgs is the `listen, wsListen` pair — makeTransportNode's transport config,
// the second being the contact secret (§12.6). Both nodes here are open (no secret), so
// the pair is what selects which transport A binds.
func runTwoNode(t *testing.T, transport, portField, listenArgs string) {
	bootRealm(t)

	// A listens; B dials A and asks; A's request handler echoes the payload back.
	harness := fmt.Sprintf(`
		// A node's network IS the transport bundle, so both ends are stood up by
		// makeTransportNode — the factory bootNode uses — and the policy has to admit
		// the artifact's own transport author before either has a network at all.
		setPolicy(JSON.stringify({ authors: [embeddedTransportAuthor],
		                           grants: { mount: [embeddedTransportAuthor] } }));
		globalThis.startTest = async function () {
		  const idA = sodium.crypto_sign_keypair();
		  const idB = sodium.crypto_sign_keypair();
		  const aId = toHex(idA.publicKey), bId = toHex(idB.publicKey);
		  const a = await makeTransportNode({ identity: idA, %s timeoutMs: 1000 });
		  const b = await makeTransportNode({ identity: idB, timeoutMs: 1000 });
		  await a.transport.start();
		  a.transport.onRequest((from, proto, payload) => payload);
		  b.transport.addPeerAddr(aId, { host: "127.0.0.1", port: a.transport.%s, transport: "%s" });
		  return await b.transport.request(aId, new TextEncoder().encode("_test"), new Uint8Array([10, 20, 30]));
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
