package main

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"seedloader/qjs"
)

// asyncnet: a confined guest *initiates* a real network round-trip. The
// guest's only net surface is `await host.call("net/send", …)`; the engine has no
// Asyncify, so that call returns a callId-backed Promise instead of blocking. This
// proves the cross-realm async seam end to end: the guest's await suspends, the host
// realm's transport bundle dials a responder over a loopback socket, and when its promise
// settles the shared loop (loop.go) resolves the guest's promise and resumes the
// awaiting entrypoint — all driven by one loop pumping both realms.
//
// Topology: one host realm, two networks. A (responder) listens and echoes
// [type, ...payload]; B (the guest's node) holds the cap-bridge over its transport.
// The guest, running as initiator, asks A and returns the echoed bytes.
func TestAsyncNetInitiator(t *testing.T) {
	capBridgeRealm(t)

	// A (responder, listens) and B (the guest's node). The guest's cap-bridge is built
	// over B's identity + transport, granting net/send only. A's onRequest echoes
	// the payload so the round-trip result is checkable.
	if _, err := qc.Eval("setup.js", qjs.Code(`
		globalThis.idA = sodium.crypto_sign_keypair();
		globalThis.idB = sodium.crypto_sign_keypair();
		globalThis.aId = toHex(idA.publicKey);
		globalThis.bId = toHex(idB.publicKey);
		// A node without an admitted transport bundle has no network at all, so the
		// policy has to name the artifact's own transport author before either node
		// stands up. The id is read from the realm, never restated.
		setPolicy(JSON.stringify({ authors: [embeddedTransportAuthor],
		                           transportAuthors: [embeddedTransportAuthor] }));
		globalThis.__setup = (async () => {
		  const a = await makeTransportNode({ identity: idA, listen: { host: "127.0.0.1", port: 0 }, timeoutMs: 2000 });
		  const b = await makeTransportNode({ identity: idB, timeoutMs: 2000 });
		  globalThis.netA = a.net;
		  globalThis.netB = b.net;
		  netA.onRequest((from, proto, payload) => payload);
		  __buildCapBridge(["net/send"], idB, netB, [aId]);
		})();
	`)); err != nil {
		t.Fatal("setup:", err)
	}

	// Bind A's listener (sets netA.port), then point B at A.
	if _, _, _, err := el.await("(async () => { await __setup; await netA.start(); return new Uint8Array(0); })()", 5*time.Second); err != nil {
		t.Fatal("start:", err)
	}
	if _, err := qc.Eval("peer.js", qjs.Code(
		`netB.addPeerAddr(aId, { host: "127.0.0.1", port: netA.port, transport: "tcp" });`,
	)); err != nil {
		t.Fatal("addPeerAddr:", err)
	}

	// The initiator guest: build a net/send frame to A (from APP config) and await
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
		  const r = await host.call("net/send", req); // [ok u8][resp]
		  if (r[0] !== 1) throw new Error("net send failed");
		  return r.slice(1);
		});
	`
	aIdHex := mustEvalString(t, qc, `aId`)
	newTestRealm(t, fmt.Sprintf(`{"peer":%q}`, aIdHex), askGuestSource)

	msg := []byte("ping over the wire")
	got, err := realmCall("ask", msg)
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
