package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"seedloader/qjs"
)

// Serving (README §12.8, §12.10): a node answers a peer's request through the SHARED
// dispatch — the protocol id off the wire is resolved through the bindings table to an
// installed app, and that app answers. There is no native dispatch of its own, which is
// what these tests pin: they drive the real boot path (boot → bootNode → loadBundle →
// serve), so what they exercise is createShell's `dispatch`, byte for byte the same
// function the Node and browser shells run.

// The holder guest: type 1 = STORE (payload already framed for fs/put), type 2 = FETCH
// (payload = key). Local fs only — and it AWAITS, because the fs names round-trip
// (§12.2). A holder is therefore an ordinary async entrypoint like an initiator, and
// the realm serializes the two rather than running one inside the other's parked window.
const holderGuestSource = `
	register("handle", async (arg) => {
	  const sender = arg.slice(0, 32);
	  const type = arg[32];
	  const payload = arg.slice(33);
	  if (type === 1) { await host.call("fs/put", payload); return new Uint8Array([1]); }
	  if (type === 2) { return await host.call("fs/get", payload); }
	  return new Uint8Array(0);
	});
`

// The echo guest: forwards its input to the bundle's own "fwd" module by name through
// module/call — the shape every app has now that module-only apps are retired (§12.4):
// inbound delivery reaches the guest, and the guest drives its module library.
const echoGuestSource = `
	register("handle", (arg) => {
	  const name = new TextEncoder().encode("fwd");
	  return host.call("module/call", new Uint8Array([name.length, ...name, ...arg]));
	});
`

// requesterJS stands a second, bundle-less node up in the same realm — just a network
// and a Transport — so a test can put a real request on a real socket. The node under
// test is the one bootNode built; this is only the peer knocking on its door.
const requesterJS = `
"use strict";
globalThis.startRequester = async function (holderId, port, contactSecretHex) {
  const id = sodium.crypto_sign_keypair();
  globalThis.__peerId = toHex(id.publicKey);
  const { net } = await makeTransportNode({
    identity: id, contactSecret: fromHex(contactSecretHex), timeoutMs: 2000,
  });
  globalThis.__net2 = net;
  // The secret rides in the ADDRESS, not in this node's own config: on a dial it is the
  // PEER's contact secret (§12.6), and without it the holder answers a stranger's msg1
  // with silence — which is the whole point of the gate, and would show up here only as
  // a request timeout.
  __net2.addPeerAddr(holderId, {
    host: "127.0.0.1", port, transport: "tcp", contactSecret: fromHex(contactSecretHex),
  });
  await __net2.start();
  return new Uint8Array(0);
};
// Go stages bytes as ArrayBuffers; request takes the Uint8Array view every other
// caller hands it, so make one here rather than loosening the shared signature.
globalThis.ask = (holderId, proto, payload) =>
  __net2.request(holderId, new TextEncoder().encode(proto), new Uint8Array(payload));
`

// startRequester boots the second node and returns its peer id.
func startRequester(t *testing.T, holderID string, port int) string {
	t.Helper()
	if _, err := qc.Eval("requester.js", qjs.Code(requesterJS)); err != nil {
		t.Fatal("requester:", err)
	}
	if _, err := callRealm("startRequester", 5*time.Second,
		qc.NewString(holderID), qc.NewInt32(int32(port)), qc.NewString(testContactSecretHex)); err != nil {
		t.Fatal("startRequester:", err)
	}
	return mustEvalString(t, qc, `__peerId`)
}

// ask issues one request from the second node to the node under test.
func ask(t *testing.T, holderID, proto string, payload []byte) []byte {
	t.Helper()
	out, err := callRealm("ask", 8*time.Second,
		qc.NewString(holderID), qc.NewString(proto), qc.NewArrayBuffer(payload))
	if err != nil {
		t.Fatal("request:", err)
	}
	return out
}

// bindProto points a wire protocol at an installed app (§12.10) — the operator's one
// action. Install is inert: nothing in loadBundle bound a protocol, so a test that
// wants a protocol answered has to say which app answers it.
func bindProto(t *testing.T, proto, appKey string) {
	t.Helper()
	if _, err := callRealm("bind", 5*time.Second, qc.NewString(proto), qc.NewString(appKey)); err != nil {
		t.Fatal("bind:", err)
	}
}

// serveNode boots a listening node under a policy admitting `authorPub`, and returns
// its status once it is serving.
func serveNode(t *testing.T, authorPub []byte) nodeStatus {
	t.Helper()
	policy := `{"authors":["` + hex.EncodeToString(authorPub) + `"]}`
	return bootShell(t, t.TempDir(), policy, &hostPort{Host: "127.0.0.1", Port: 0})
}

// A guest app serves its request side from its own confined realm: the shell resolves
// the protocol to the app, then calls the guest's synchronous `handle` (§12.8). This
// wires the whole stack — a real socket, the shared Transport, the bindings table, the
// cap-bridge the shell built from the manifest's declared domains, and the realm — and
// proves it against a storage-shaped app: a peer stores a value and fetches it back.
func TestServeGuestApp(t *testing.T) {
	author, authorPub := testAuthor(t)
	st := serveNode(t, authorPub)
	bundlePath, _ := writeBundle(t, author, authorPub, "holderapp", 1, holderGuestSource, []string{"fs/put", "fs/get"})
	holderKey := appKeyFor(authorPub, "holderapp")
	if status := loadBundle(bundlePath); status != "holderapp v1  key "+holderKey {
		t.Fatalf("bundle load: %s", status)
	}
	// The operator's one action (§12.10): install bound nothing, so the protocol is
	// pointed at the app explicitly.
	bindProto(t, "holderapp", holderKey)
	if _, err := callRealm("serve", 10*time.Second); err != nil {
		t.Fatal("serve:", err)
	}
	startRequester(t, st.PeerID, st.Port)
	key := []byte("greeting")
	val := []byte("held by the cohort")
	fsFrame := make([]byte, 4+len(key)+len(val)) // [klen u32][key][bytes]
	fsFrame[3] = byte(len(key))
	copy(fsFrame[4:], key)
	copy(fsFrame[4+len(key):], val)

	if ok := ask(t, st.PeerID, "holderapp", append([]byte{1}, fsFrame...)); len(ok) == 0 || ok[0] != 1 {
		t.Fatalf("store not acked: %v", ok)
	}
	got := ask(t, st.PeerID, "holderapp", append([]byte{2}, key...))
	if len(got) == 0 || got[0] != 1 {
		t.Fatalf("fetch miss: %v", got)
	}
	if !bytes.Equal(got[1:], val) {
		t.Fatalf("fetched %q, want %q", got[1:], val)
	}
}

// Two apps on one node, and each protocol reaches ITS OWN app (§12.10) — the property
// the native target could not hold while it assembled its own dispatch: that one asked
// whether a protocol was bound and then called the single guest whatever the answer
// named, had no arm at all for a module-only app, and dropped the sender. All three
// are checked here at once, since only a node hosting two apps with different code
// shapes can tell the difference.
func TestServeRoutesEachProtocolToItsOwnApp(t *testing.T) {
	author, authorPub := testAuthor(t)
	st := serveNode(t, authorPub)

	// Two guest apps from one author under two app names — so they derive disjoint
	// table names (§5.1). The holder guest reads fs; the echo guest forwards to its own
	// "fwd" module, which echoes its input — so the echo app's response IS whatever the
	// shell handed the guest. Each protocol reaches its own app because the operator
	// bound it there, not because the bundles claimed anything.
	guestBundle, _ := writeBundle(t, author, authorPub, "holderapp", 1, holderGuestSource, []string{"fs/put", "fs/get"})
	holderKey := appKeyFor(authorPub, "holderapp")
	if status := loadBundle(guestBundle); status != "holderapp v1  key "+holderKey {
		t.Fatalf("guest bundle load: %s", status)
	}
	echoBundle, _ := writeBundle(t, author, authorPub, "echoapp", 1, echoGuestSource, nil)
	echoKey := appKeyFor(authorPub, "echoapp")
	if status := loadBundle(echoBundle); status != "echoapp v1  key "+echoKey {
		t.Fatalf("echo bundle load: %s", status)
	}
	// Install is inert (§12.10): the two bundles landed unbound, and the operator's
	// explicit binds are the only reason these protocols have destinations.
	bindProto(t, "holderapp", holderKey)
	bindProto(t, "echoapp", echoKey)
	if _, err := callRealm("serve", 10*time.Second); err != nil {
		t.Fatal("serve:", err)
	}
	peerID := startRequester(t, st.PeerID, st.Port)

	// The module arm: the guest `handle` receives the input, forwards it through
	// module/call, and the forwarder's echo makes both halves directly checkable — the
	// authenticated sender arrives prepended (§12.8), inside the module's input.
	payload := []byte("who is asking?")
	got := ask(t, st.PeerID, "echoapp", payload)
	if want := append(mustHex(t, peerID), payload...); !bytes.Equal(got, want) {
		t.Fatalf("echoapp module input = %x, want senderPk ‖ payload = %x", got, want)
	}

	// The guest arm, on the same node, in the same breath: a FETCH of a key nobody
	// stored answers [0] — a MISS from the holder guest, which is proof it ran. The old
	// dispatch would have sent this to whichever single guest it held regardless of the
	// protocol, and would have had nothing at all to answer the echo request above with.
	if miss := ask(t, st.PeerID, "holderapp", append([]byte{2}, "absent"...)); len(miss) != 1 || miss[0] != 0 {
		t.Fatalf("holderapp fetch of an absent key = %v, want [0] from its own guest", miss)
	}

	// A protocol bound to nothing reaches nobody. The shared Transport still answers the
	// frame (a null dispatch result is an EMPTY response, not a dropped one — that is
	// dispatchRequest's contract on every target), so the check is that the answer is
	// empty rather than either app's.
	if resp := ask(t, st.PeerID, "nobody-serves-this", []byte{2}); len(resp) != 0 {
		t.Fatalf("an unbound protocol was answered with %d B — no app is bound to it", len(resp))
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(fmt.Errorf("hex %q: %w", s, err))
	}
	return b
}
