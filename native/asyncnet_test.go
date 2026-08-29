package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"seedloader/qjs"
)

// asyncnet: a confined guest *initiates* a real network round-trip, which proves the
// cross-realm async seam end to end. The guest's await suspends (the engine has no
// Asyncify, so the call returns a callId-backed Promise rather than blocking), the host
// realm's transport dials a responder over a loopback socket, and when its promise settles
// the shared loop resolves the guest's and resumes the entrypoint — one loop, both realms.
//
// Topology: one host realm, two networks. A (responder) listens and echoes
// [type, ...payload]; B holds the guest seam over its transport, and its guest asks A.
func TestAsyncNetInitiator(t *testing.T) {
	guestSeamRealm(t)

	// A (responder, listens) and B (the guest's node). The guest's seam is built over B's
	// identity, granting only the transport's reserved id and resolving it through B's own
	// routing — the same shell method an app's seam gets in production. A runs the probe
	// app, which echoes, so the round-trip result is checkable.
	sender := testAuthor(t)
	probeBlob, err := os.ReadFile(writeProbeBundle(t, sender, "probe"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := qc.Eval("setup.js", qjs.Code(fmt.Sprintf(`
		globalThis.__probe = null;
		globalThis.loadProbe = (bytes) => { globalThis.__probe = new Uint8Array(bytes); };
		globalThis.idA = sodium.crypto_sign_keypair();
		globalThis.idB = sodium.crypto_sign_keypair();
		globalThis.aId = toHex(idA.publicKey);
		globalThis.bId = toHex(idB.publicKey);
		// A node without an admitted transport bundle has no network at all, so the
		// policy has to name the artifact's own transport author before either node
		// stands up. The id is read from the realm, never restated.
		setPolicy(JSON.stringify({ authors: [embeddedTransportAuthor, %q],
		                           grants: { link: [embeddedTransportAuthor] } }));
		globalThis.__setup = (async () => {
		  const a = await makeTransportNode({ identity: idA, listen: { host: "127.0.0.1", port: 0 }, timeoutMs: 2000 });
		  const b = await makeTransportNode({ identity: idB, timeoutMs: 2000 });
		  globalThis.netA = a.transport;
		  globalThis.netB = b.transport;
		  globalThis.__nodeA = a;
		  globalThis.__nodeB = b;
		  // The seam a confined guest on B runs against: _net resolves through B's own
		  // routing, which is what an app's seam is wired with (shell-core crossRealmCall).
		  // Driven through B's retained app handle rather than dispatch, because _net is a LOCAL service
		  // name: a co-resident realm reaches it and a peer does not (§12.10), and
		  // dispatch is the peer's door. This seam is hand-built rather than a loaded
		  // slot, so the host loopback stands in for the cross-realm call — the same
		  // slot, the same entrypoint, the app's own op framing recomposed here (the
		  // shell passes bytes and never reads them).
		  __buildGuestSeam([], idB, { call: (id, payload) => {
		    const n = payload[0];
		    let op = "";
		    for (let i = 0; i < n; i++) op += String.fromCharCode(payload[1 + i]);
		    const args = payload.slice(1 + n);
		    const framed = new Uint8Array(1 + op.length + args.length);
		    framed[0] = op.length;
		    for (let i = 0; i < op.length; i++) framed[1 + i] = op.charCodeAt(i);
		    framed.set(args, 1 + op.length);
		    return globalThis.__nodeBApp.invoke(framed);
		  } }, undefined, ["_net"]);
		})();
	`, hex.EncodeToString(sender.id())))); err != nil {
		t.Fatal("setup:", err)
	}
	if _, err := callRealm("loadProbe", 5*time.Second, qc.NewArrayBuffer(probeBlob)); err != nil {
		t.Fatal("loadProbe:", err)
	}

	// Bind A's listener (sets netA.port), then point B at A.
	if _, _, _, err := el.await("(async () => { await __setup; globalThis.__nodeBApp = await __nodeB.shell.loadBundleBlob(__probe); await netA.start(); await __nodeA.shell.loadBundleBlob(__probe); return new Uint8Array(0); })()", 5*time.Second); err != nil {
		t.Fatal("start:", err)
	}
	// Eval would block on the promise without advancing the event loop.
	if _, _, _, err := el.await(`teachAddr(__nodeB.shell, aId, "tcp://127.0.0.1:" + netA.port)`, 5*time.Second); err != nil {
		t.Fatal("addr:", err)
	}

	// The initiator guest: build a `send` op for the transport (peer from APP config) and
	// await the response. The await is the whole point — it suspends until the host
	// realm's socket round-trip settles and the loop resolves the guest's promise.
	const askGuestSource = `
		function fromHex(h) {
		  const out = new Uint8Array(h.length / 2);
		  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
		  return out;
		}
		// handle reads [caller 32][this app's op framing]: the local "ask" op (the mock
		// realm composes it around the test payload) builds the transport's send op and
		// awaits the response. The await is the whole point — it suspends until the host
		// realm's socket round-trip settles and the loop resolves the guest's promise.
		function handle(arg) {
		  const n = arg[32];
		  const msg = arg.subarray(33 + n);
		  const peer = fromHex(APP.peer);                       // A's 32-byte public key
		  const proto = new TextEncoder().encode("probe");      // the app A claims
		  // [opLen u8]["send"] then the op's args:
		  // [noReply u8][deadline u32][to blob][proto blob][payload blob].
		  const opName = "send";
		  const req = new Uint8Array(1 + opName.length + 1 + 4 + 4 + 32 + 4 + proto.length + 4 + msg.length);
		  req[0] = opName.length;
		  for (let i = 0; i < opName.length; i++) req[1 + i] = opName.charCodeAt(i);
		  let off = 1 + opName.length;
		  const dv = new DataView(req.buffer);
		  req[off++] = 0;                       // noReply
		  dv.setUint32(off, 0); off += 4;       // deadline: the node's default
		  dv.setUint32(off, 32); off += 4;
		  req.set(peer, off); off += 32;
		  dv.setUint32(off, proto.length); off += 4;
		  req.set(proto, off); off += proto.length;
		  dv.setUint32(off, msg.length); off += 4;
		  req.set(msg, off);
		  return host.call("_net", req).then((r) => {   // [ok u8][resp]
		    if (r[0] !== 1) throw new Error("net send failed");
		    return r.slice(1);
		  });
		}
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
