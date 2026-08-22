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

// Serving (README §12.8, §12.10): the protocol id off the wire is resolved to the
// installed app whose manifest claims it, and that app answers. There is no native
// dispatch, which is what these pin — they drive the real boot path (boot → bootNode →
// loadBundle → serve), so what runs is the shell's `dispatch`, the same function the
// Node and browser shells use.

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

// The echo guest: forwards its input to the bundle's own "fwd" module by its bare name
// over the same host.call as everything else (§12.2) — the shape every app has now that
// module-only apps are retired (§12.4): inbound delivery reaches the guest, and the guest
// drives its module library.
const echoGuestSource = `
	register("handle", (arg) => host.call("fwd", arg));
`

// requesterJS stands a second, bundle-less node up in the same realm — just a network
// and a Transport — so a test can put a real request on a real socket. The node under
// test is the one bootNode built; this is only the peer knocking on its door.
const requesterJS = `
"use strict";
globalThis.startRequester = async function (holderId, port, contactSecretHex) {
  const id = sodium.crypto_sign_keypair();
  globalThis.__peerId = toHex(id.publicKey);
  const node = await makeTransportNode({
    identity: id, contactSecret: fromHex(contactSecretHex), timeoutMs: 2000,
  });
  globalThis.__requesterNode = node;
  const net = node.transport;
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
globalThis.__requester = null;
// The requester loads the probe app and asks through it: a request is an app calling
// the id the transport claims, so there is nothing host-side to call instead.
globalThis.loadIntoRequester = (bytes) => __requesterNode.shell.loadBundleBlob(new Uint8Array(bytes));
globalThis.ask = async (appKey, sendArgs) => {
  // The op is a NAME the shell frames (invoke, shell-core.ts) — the probe app's own
  // local vocabulary, which the shell passes through without reading.
  const r = await __requesterNode.shell.invoke("send", new Uint8Array(sendArgs), appKey);
  if (r[0] !== 1) throw new Error("net: request failed");
  return r.slice(1);
};
`

// requesterAppKey is the app key the probe bundle binds under on the requester — the
// app `ask` invokes, since a request is a local loopback into an app.
var requesterAppKey string

// startRequester boots the second node, loads the probe app into it, and returns its
// peer id. The app is what actually sends: there is no host-side request facade.
func startRequester(t *testing.T, holderAuthorHex, holderID string, port int) string {
	t.Helper()
	if _, err := qc.Eval("requester.js", qjs.Code(requesterJS)); err != nil {
		t.Fatal("requester:", err)
	}
	if _, err := callRealm("startRequester", 5*time.Second,
		qc.NewString(holderID), qc.NewInt32(int32(port)), qc.NewString(testContactSecretHex)); err != nil {
		t.Fatal("startRequester:", err)
	}
	sender := testAuthor(t)
	// Widen the policy to admit the probe app's author too — the node under test still
	// answers only what the holder's bundle claims; this is the requester's own key.
	if err := applyPolicy(`{"authors":["` + holderAuthorHex + `","` + hex.EncodeToString(sender.id()) + `"]}`); err != nil {
		t.Fatal("applyPolicy:", err)
	}
	blob, err := os.ReadFile(writeProbeBundle(t, sender, "probe"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := callRealm("loadIntoRequester", 5*time.Second, qc.NewArrayBuffer(blob)); err != nil {
		t.Fatal("loadIntoRequester:", err)
	}
	requesterAppKey = appKeyFor(sender.id(), "probe")
	return mustEvalString(t, qc, `__peerId`)
}

// ask issues one request from the second node to the node under test.
func ask(t *testing.T, holderID, proto string, payload []byte) []byte {
	t.Helper()
	out, err := callRealm("ask", 8*time.Second,
		qc.NewString(requesterAppKey), qc.NewArrayBuffer(probeSendArgs(holderID, proto, payload)))
	if err != nil {
		t.Fatal("request:", err)
	}
	return out
}

// loadedLine is the console line a successful load prints (§12.4, §12.10): the app, its
// version, its app key, and the protocol ids the manifest claimed — the routing came with
// the bundle, so the line reports it rather than the operator supplying it.
func loadedLine(app string, version int, appKey string, serves string) string {
	return fmt.Sprintf("%s v%d  key %s  serves %s", app, version, appKey, serves)
}

// serveNode boots a listening node under a policy admitting `authorID`, and returns
// its status once it is serving.
func serveNode(t *testing.T, authorID []byte) nodeStatus {
	t.Helper()
	policy := `{"authors":["` + hex.EncodeToString(authorID) + `"]}`
	return bootShell(t, t.TempDir(), policy, &hostPort{Host: "127.0.0.1", Port: 0})
}

// A guest app serves its request side from its own confined realm: the shell resolves
// the protocol to the app, then calls the guest's synchronous `handle` (§12.8). This
// wires the whole stack — a real socket, the shared Transport, the protocol routing, the
// guest seam the shell built from the manifest's declared domains, and the realm — and
// proves it against a storage-shaped app: a peer stores a value and fetches it back.
func TestServeGuestApp(t *testing.T) {
	author := testAuthor(t)
	st := serveNode(t, author.id())
	bundlePath, _ := writeBundle(t, author, "holderapp", 1, holderGuestSource, []string{"fs/put", "fs/get"})
	holderKey := appKeyFor(author.id(), "holderapp")
	// The load is the whole of it (§12.10): the manifest claims `holderapp`, so the
	// bundle that landed is already the destination for that protocol, and its guest is
	// already standing — there is no second call between installing and serving.
	if status := loadBundle(bundlePath); status != loadedLine("holderapp", 1, holderKey, "holderapp") {
		t.Fatalf("bundle load: %s", status)
	}
	startRequester(t, hex.EncodeToString(author.id()), st.PeerID, st.Port)
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

// Two apps on one node, and each protocol reaches ITS OWN app (§12.10) — the property the
// native target could not hold while it assembled its own dispatch, which called the
// single guest whatever the answer named, had no arm for a module-only app, and dropped
// the sender. Only a node hosting two apps with different code shapes can tell.
func TestServeRoutesEachProtocolToItsOwnApp(t *testing.T) {
	author := testAuthor(t)
	st := serveNode(t, author.id())

	// Two guest apps from one author under two app names — so they derive disjoint
	// table names (§5.1). The holder guest reads fs; the echo guest forwards to its own
	// "fwd" module, which echoes its input — so the echo app's response IS whatever the
	// shell handed the guest. Each protocol reaches its own app because each manifest
	// claims its own id (§12.10) and the two claims cannot collide.
	guestBundle, _ := writeBundle(t, author, "holderapp", 1, holderGuestSource, []string{"fs/put", "fs/get"})
	holderKey := appKeyFor(author.id(), "holderapp")
	if status := loadBundle(guestBundle); status != loadedLine("holderapp", 1, holderKey, "holderapp") {
		t.Fatalf("guest bundle load: %s", status)
	}
	echoBundle, _ := writeBundle(t, author, "echoapp", 1, echoGuestSource, nil)
	echoKey := appKeyFor(author.id(), "echoapp")
	if status := loadBundle(echoBundle); status != loadedLine("echoapp", 1, echoKey, "echoapp") {
		t.Fatalf("echo bundle load: %s", status)
	}
	peerID := startRequester(t, hex.EncodeToString(author.id()), st.PeerID, st.Port)

	// The module arm: the guest `handle` receives the input, forwards it through
	// a bare-name module call, and the forwarder's echo makes both halves checkable — the
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
