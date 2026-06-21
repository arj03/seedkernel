package main

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"

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

// netRouteNode stands up one isolated host realm with the full net stack (sodium,
// the __net socket primitive, the shared route bundle, the WS codec, makeNetwork) on
// its own loop — everything a Transport needs over a real socket. Takes testing.TB so
// both the request/response tests and net_bench_test's round-trip benches share it.
func netRouteNode(tb testing.TB) (*eventLoop, *qjs.Context, func()) {
	tb.Helper()
	wrt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	sd := bootSodium(wrt)

	rt, err := qjs.New()
	if err != nil {
		wrt.Close(ctx)
		tb.Fatal(err)
	}
	qc := rt.Context()
	el := newEventLoop(qc)
	installPolyfills(qc)
	exposeSodium(qc, sd)
	exposeNet(qc, el)
	if _, err := qc.Eval("host-netroute.gen.js", qjs.Code(hostNetRouteJS)); err != nil {
		rt.Close()
		wrt.Close(ctx)
		tb.Fatal("eval route bundle:", err)
	}
	if err := installWsCodec(qc); err != nil { // WS codec (ws.wasm via __ws) for the ws transport
		rt.Close()
		wrt.Close(ctx)
		tb.Fatal("ws codec:", err)
	}
	installNetwork(qc)
	return el, qc, func() { rt.Close(); wrt.Close(ctx) }
}

func TestTwoNodeRequestResponseWS(t *testing.T) {
	runTwoNode(t, "ws", "wsPort", `undefined, { host: "127.0.0.1", port: 0 }`)
}

func runTwoNode(t *testing.T, transport, portField, listenArgs string) {
	el, qc, done := netRouteNode(t)
	defer done()

	// A listens; B dials A and asks; A's request handler echoes [type, ...payload].
	harness := fmt.Sprintf(`
		globalThis.startTest = async function () {
		  const idA = sodium.crypto_sign_keypair();
		  const idB = sodium.crypto_sign_keypair();
		  const aId = toHex(idA.publicKey), bId = toHex(idB.publicKey);
		  const netA = makeNetwork(idA, %s);
		  const netB = makeNetwork(idB, undefined, undefined);
		  await netA.start();
		  const tA = new Transport(aId, netA, 1000);
		  const tB = new Transport(bId, netB, 1000);
		  tA.onRequest((from, type, payload) => {
		    const out = new Uint8Array(payload.length + 1);
		    out[0] = type;
		    out.set(payload, 1);
		    return out;
		  });
		  netB.addPeerAddr(aId, { host: "127.0.0.1", port: netA.%s, transport: "%s" });
		  return await tB.request(aId, 5, new Uint8Array([10, 20, 30]));
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
	if want := []byte{5, 10, 20, 30}; !bytes.Equal(value, want) {
		t.Fatalf("response = %v, want %v", value, want)
	}
}
