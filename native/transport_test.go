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

// Routing and transport run as the transport bundle's guest program inside QuickJS, over
// the Go socket primitive. Two independent nodes complete the PeerLink handshake, route,
// and exchange a typed request/response over a real loopback socket — the
// dial/accept/promote/deliver path and the correlation/timeout layer, none of it Go logic.
//
// Only the WebSocket transport is exercised here, which drives the full WS path: the raw
// Go byte stream (sock.go), the shared net-frame WsChannel and the RFC 6455 codec. The TCP
// twin is asyncnet_test, and scripts/loader-interop.sh covers both against real node/bun
// nodes.
//
// The realm is the production one — boot() installs the primitives and evaluates the
// shared bundle — so `makeTransportNode` is the factory the binary boots with, not a
// harness assembling the stack a second way.

func TestTwoNodeRequestResponseWS(t *testing.T) {
	runTwoNode(t, "ws", "wsPort", `wsListen: { host: "127.0.0.1", port: 0 },`)
}

// listenArgs is the `listen, wsListen` pair — makeTransportNode's transport config,
// the second being the contact secret (§12.6). Both nodes here are open (no secret), so
// the pair is what selects which transport A binds.
func runTwoNode(t *testing.T, transport, portField, listenArgs string) {
	bootRealm(t)

	// A listens; B dials A and asks; A's probe app echoes the payload back. Both ends load
	// the same app, because a request is an app calling the id the transport claims — there is
	// no host-side request facade to stand in for one.
	sender := testAuthor(t)
	senderHex := hex.EncodeToString(sender.id())
	probeBlob, err := os.ReadFile(writeProbeBundle(t, sender, "probe"))
	if err != nil {
		t.Fatal(err)
	}
	probeKey := appKeyFor(sender.id(), "probe")
	harness := fmt.Sprintf(`
		// A node's network IS the transport bundle, so both ends are stood up by
		// makeTransportNode — the factory bootNode uses — and the policy has to admit
		// the artifact's own transport author before either has a network at all.
		setPolicy(JSON.stringify({ authors: [embeddedTransportAuthor, %q],
		                           grants: { link: [embeddedTransportAuthor] } }));
		globalThis.__probe = null;
		globalThis.loadProbe = (bytes) => { globalThis.__probe = new Uint8Array(bytes); };
		globalThis.startTest = async function () {
		  const idA = sodium.crypto_sign_keypair();
		  const idB = sodium.crypto_sign_keypair();
		  const aId = toHex(idA.publicKey), bId = toHex(idB.publicKey);
		  const a = await makeTransportNode({ identity: idA, %s timeoutMs: 1000 });
		  const b = await makeTransportNode({ identity: idB, timeoutMs: 1000 });
		  await a.transport.start();
		  await a.loadBundleBlob(__probe);
		  await b.loadBundleBlob(__probe);
		  b.transport.addPeerAddr(aId, { host: "127.0.0.1", port: a.transport.%s, transport: "%s" });
		  // The send op's own argument order (transport/src/core.js):
		  // [noReply u8][deadline u32][to blob][proto blob][payload blob]. The op NAME and
		  // the caller id are the shell's framing (invoke), never written here.
		  const proto = new TextEncoder().encode("probe");
		  const payload = new Uint8Array([10, 20, 30]);
		  const args = new Uint8Array(1 + 4 + 4 + 32 + 4 + proto.length + 4 + payload.length);
		  const dv = new DataView(args.buffer);
		  let off = 1;
		  dv.setUint32(off, 0); off += 4;
		  dv.setUint32(off, 32); off += 4;
		  args.set(fromHex(aId), off); off += 32;
		  dv.setUint32(off, proto.length); off += 4;
		  args.set(proto, off); off += proto.length;
		  dv.setUint32(off, payload.length); off += 4;
		  args.set(payload, off);
		  const r = await b.invoke("send", args, %q);
		  if (r[0] !== 1) throw new Error("net: request failed");
		  return r.slice(1);
		};
	`, senderHex, listenArgs, portField, transport, probeKey)
	if _, err := qc.Eval("transport-harness.js", qjs.Code(harness)); err != nil {
		t.Fatal("harness:", err)
	}
	if _, err := callRealm("loadProbe", 5*time.Second, qc.NewArrayBuffer(probeBlob)); err != nil {
		t.Fatal("loadProbe:", err)
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
