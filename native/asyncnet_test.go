package main

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"

	"seedloader/qjs"
)

// asyncnet: a confined guest *initiates* a real network round-trip. The
// guest's only net surface is `await host.call(CAP_NET_SEND, …)`; the engine has no
// Asyncify, so that op returns a callId-backed Promise instead of blocking. This
// proves the cross-realm async seam end to end: the guest's await suspends, the host
// realm's Transport dials a responder over a loopback socket, and when its promise
// settles the shared loop (loop.go) resolves the guest's promise and resumes the
// awaiting entrypoint — all driven by one loop pumping both realms.
//
// Topology: one host realm, two networks. A (responder) listens and echoes
// [type, ...payload]; B (the guest's node) holds the cap-bridge over its transport.
// The guest, running as initiator, asks A and returns the echoed bytes.
func TestAsyncNetInitiator(t *testing.T) {
	dir := t.TempDir()
	wrt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	sd := bootSodium(wrt)
	rt, err := qjs.New()
	if err != nil {
		wrt.Close(ctx)
		t.Fatal(err)
	}
	hostQc := rt.Context()
	el := newEventLoop(hostQc)
	if err := installEngineHost(hostQc, el, sd, dir); err != nil {
		rt.Close()
		wrt.Close(ctx)
		t.Fatal("host:", err)
	}
	defer func() { rt.Close(); wrt.Close(ctx) }()

	// A (responder, listens) and B (the guest's node). The guest's cap-bridge is built
	// over B's identity + transport, granting crypto + net only. A's onRequest echoes
	// the payload so the round-trip result is checkable.
	if _, err := hostQc.Eval("setup.js", qjs.Code(`
		globalThis.idA = sodium.crypto_sign_keypair();
		globalThis.idB = sodium.crypto_sign_keypair();
		globalThis.aId = toHex(idA.publicKey);
		globalThis.bId = toHex(idB.publicKey);
		globalThis.netA = makeNetwork(idA, { host: "127.0.0.1", port: 0 }, undefined);
		globalThis.netB = makeNetwork(idB, undefined, undefined);
		globalThis.tA = new Transport(aId, netA, 2000);
		globalThis.tB = new Transport(bId, netB, 2000);
		tA.onRequest((from, proto, payload) => payload);
		__buildCapBridge(["crypto", "net"], idB, tB, [aId]);
	`)); err != nil {
		t.Fatal("setup:", err)
	}

	// Bind A's listener (sets netA.port), then point B at A.
	if _, _, _, err := el.await(`(async () => { await netA.start(); return new Uint8Array(0); })()`, 5*time.Second); err != nil {
		t.Fatal("start:", err)
	}
	if _, err := hostQc.Eval("peer.js", qjs.Code(
		`netB.addPeerAddr(aId, { host: "127.0.0.1", port: netA.port, transport: "tcp" });`,
	)); err != nil {
		t.Fatal("addPeerAddr:", err)
	}

	// The initiator guest: build a CAP_NET_SEND frame to A (from APP config) and await
	// the response. The await is the whole point — it suspends until the host realm's
	// socket round-trip settles and the loop resolves the guest's promise.
	const askGuestSource = `
		function fromHex(h) {
		  const out = new Uint8Array(h.length / 2);
		  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
		  return out;
		}
		register("ask", async (msg) => {
		  const peer = fromHex(APP.peer);            // A's 32-byte public key
		  const proto = [0x74, 0x65, 0x73, 0x74];    // "test"
		  const req = new Uint8Array(32 + 1 + proto.length + msg.length); // [peer 32][pidLen u8][proto][payload]
		  req.set(peer, 0);
		  req[32] = proto.length;
		  req.set(proto, 33);
		  req.set(msg, 33 + proto.length);
		  const r = await host.call(CAP_NET_SEND, req); // [ok u8][resp]
		  if (r[0] !== 1) throw new Error("net send failed");
		  return r.slice(1);
		});
	`
	aIdHex := mustEvalString(t, hostQc, `aId`)
	g, err := newGuestRealm(el, "", fmt.Sprintf(`{"peer":%q}`, aIdHex), askGuestSource)
	if err != nil {
		t.Fatal("guest:", err)
	}
	defer g.close()

	msg := []byte("ping over the wire")
	got, err := g.runGuest("ask", msg)
	if err != nil {
		t.Fatal("ask:", err)
	}
	want := msg // A echoes the payload directly
	if !bytes.Equal(got, want) {
		t.Fatalf("ask = %v, want %v", got, want)
	}
}

// mustEvalString evaluates a JS expression yielding a string and returns it.
func mustEvalString(t *testing.T, qc *qjs.Context, expr string) string {
	t.Helper()
	v, err := qc.Eval("<evalString>", qjs.Code(expr))
	if err != nil {
		t.Fatalf("eval %q: %v", expr, err)
	}
	return v.String()
}
