package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"
)

// Serving (§12.8, §12.10): the protocol id from the wire is resolved to the installed app
// whose manifest claims it, and that app answers. Routing is the shared shell code, not
// Go; these tests use the real boot path (boot, standUp, install, serve), so the routing
// that runs is the same as on Node and in the browser.

// The holder guest: type 1 = STORE (payload already framed for fs/put), type 2 = FETCH
// (payload = key). Local fs only, awaited, since the fs names are async (§12.2). A holder
// is an ordinary async entrypoint like an initiator, and the realm serializes the two
// instead of running one while the other waits.
const holderGuestSource = `
	async function handle(arg) {
	  const sender = arg.slice(0, 32);
	  const type = arg[32];
	  const payload = arg.slice(33);
	  if (type === 1) { await host.call("fs/put", payload); return new Uint8Array([1]); }
	  if (type === 2) { return await host.call("fs/get", payload); }
	  return new Uint8Array(0);
	}
`

// The echo guest: forwards its input to the bundle's own "fwd" module by its bare name,
// over the same host.call as everything else (§12.2). Every app has this shape (§12.4):
// inbound delivery reaches the guest, and the guest calls its modules.
const echoGuestSource = `
	function handle(arg) { return host.call("fwd", arg); }
`

// requesterJS boots a second node in the same realm, just a network and the transport, so
// a test can send a real request over a real socket. The node under test is the one
// startNode booted; this is only the peer calling it, under a policy of its own that
// admits the probe app it sends through.
const requesterJS = `
"use strict";
globalThis.startRequester = async function (holderId, port, contactSecretHex, policyJson) {
  const id = sodium.crypto_sign_keypair();
  globalThis.__peerId = toHex(id.publicKey);
  const node = await standUp({
    dir: __dir, identity: id, policyJson,
    // Contact policy is transport config (§12.6.3).
    transport: { config: { contactSecret: contactSecretHex } },
  });
  globalThis.__requesterNode = node;
  const net = node.transport;
  globalThis.__net2 = net;
  // The secret is added with the address, not read from this node's own config: on a dial
  // it is the peer's contact secret (§12.6), and without it the holder answers a stranger's
  // msg1 with silence, which would show up here only as a request timeout.
  teachAddr(node.shell, holderId, "tcp://127.0.0.1:" + port, fromHex(contactSecretHex));
  await __net2.start();
  return new Uint8Array(0);
};
// Go passes bytes as ArrayBuffers; request takes a Uint8Array like every other caller, so
// make one here instead of loosening the shared signature.
globalThis.__requester = null;
// The requester installs the probe app and sends through it: a request is an app calling
// the id the transport claims.
globalThis.loadIntoRequester = async (bytes) => {
  globalThis.__requester = await __requesterNode.shell.install(new Uint8Array(bytes));
};
globalThis.ask = async (sendArgs) => {
  // The op name is the probe app's own (the shell passes bytes unread; this file builds
  // the frame the app's handle reads).
  const op = "send", args = new Uint8Array(sendArgs);
  const framed = new Uint8Array(1 + op.length + args.length);
  framed[0] = op.length;
  for (let i = 0; i < op.length; i++) framed[1 + i] = op.charCodeAt(i);
  framed.set(args, 1 + op.length);
  const r = await __requester.invoke(framed);
  if (r[0] !== 1) throw new Error("net: request failed");
  return r.slice(1);
};
`

// startRequester boots the second node, installs the probe app, and returns its peer id.
// The app is what sends.
func startRequester(t *testing.T, holderID string, port int) string {
	t.Helper()
	if _, err := qc.Eval("requester.js", requesterJS); err != nil {
		t.Fatal("requester:", err)
	}
	// The requester's own policy admits the probe app's author; the node under test keeps
	// its own, and answers only what the holder's bundle claims.
	sender := testAuthor(t)
	if _, err := callRealm("startRequester", 5*time.Second,
		qc.NewString(holderID), qc.NewInt32(int32(port)), qc.NewString(testContactSecretHex),
		qc.NewString(authorsPolicy(sender.id()))); err != nil {
		t.Fatal("startRequester:", err)
	}
	blob, err := os.ReadFile(writeProbeBundle(t, sender, "probe"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := callRealm("loadIntoRequester", 5*time.Second, qc.NewArrayBuffer(blob)); err != nil {
		t.Fatal("loadIntoRequester:", err)
	}
	return mustEvalString(t, qc, `__peerId`)
}

// ask issues one request from the second node to the node under test.
func ask(t *testing.T, holderID, proto string, payload []byte) []byte {
	t.Helper()
	out, err := callRealm("ask", 8*time.Second,
		qc.NewArrayBuffer(probeSendArgs(holderID, proto, payload)))
	if err != nil {
		t.Fatal("request:", err)
	}
	return out
}

// loadedLine is the console line a successful install prints (§12.4, §12.10): the app, its
// version, its author, and the protocol ids the manifest claimed.
func loadedLine(app string, version int, author []byte, serves string) string {
	return fmt.Sprintf("%s v%d  author %s  serves %s", app, version, hex.EncodeToString(author), serves)
}

// serveNode boots a listening node under a policy admitting `authorID`, and returns
// its status once it is serving.
func serveNode(t *testing.T, authorID []byte) nodeStatus {
	t.Helper()
	return bootShell(t, t.TempDir(), authorsPolicy(authorID), &hostPort{Host: "127.0.0.1", Port: 0})
}

// A guest app serves requests from its own confined realm: the shell resolves the protocol
// to the app, then calls the guest's `handle` (§12.8). This uses the whole stack (a real
// socket, the transport, protocol routing, the guest seam built from the manifest's
// requires, and the realm) with a storage-like app: a peer stores a value and fetches it
// back.
func TestServeGuestApp(t *testing.T) {
	author := testAuthor(t)
	st := serveNode(t, author.id())
	bundlePath, _ := writeBundle(t, author, "holderapp", 1, holderGuestSource, []string{"fs"})
	// Installing is enough (§12.10): the manifest claims `holderapp`, so the installed
	// bundle already receives that protocol and its guest is already running, with no
	// second step between installing and serving.
	if status := loadBundle(bundlePath); status != loadedLine("holderapp", 1, author.id(), "holderapp") {
		t.Fatalf("bundle load: %s", status)
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

// Two apps on one node, and each protocol reaches its own app (§12.10), with the
// authenticated sender passed along. Only a node hosting two different apps can show this.
func TestServeRoutesEachProtocolToItsOwnApp(t *testing.T) {
	author := testAuthor(t)
	st := serveNode(t, author.id())

	// Two guest apps under two app labels, so two slots (§5). The holder guest reads fs;
	// the echo guest forwards to its own "fwd" module, which echoes its input, so the echo
	// app's response is exactly what the shell gave the guest. Each protocol reaches its
	// own app because each manifest claims its own id (§12.10).
	guestBundle, _ := writeBundle(t, author, "holderapp", 1, holderGuestSource, []string{"fs"})
	if status := loadBundle(guestBundle); status != loadedLine("holderapp", 1, author.id(), "holderapp") {
		t.Fatalf("guest bundle load: %s", status)
	}
	echoBundle, _ := writeBundle(t, author, "echoapp", 1, echoGuestSource, nil)
	if status := loadBundle(echoBundle); status != loadedLine("echoapp", 1, author.id(), "echoapp") {
		t.Fatalf("echo bundle load: %s", status)
	}
	peerID := startRequester(t, st.PeerID, st.Port)

	// The module case: the guest `handle` receives the input and forwards it through a
	// bare-name module call, and the forwarder's echo makes both halves checkable: the
	// authenticated sender arrives prepended (§12.8), inside the module's input.
	payload := []byte("who is asking?")
	got := ask(t, st.PeerID, "echoapp", payload)
	if want := append(mustHex(t, peerID), payload...); !bytes.Equal(got, want) {
		t.Fatalf("echoapp module input = %x, want senderPk ‖ payload = %x", got, want)
	}

	// The holder case, on the same node: a FETCH of a key nobody stored answers [0], a
	// miss from the holder guest, which shows it ran.
	if miss := ask(t, st.PeerID, "holderapp", append([]byte{2}, "absent"...)); len(miss) != 1 || miss[0] != 0 {
		t.Fatalf("holderapp fetch of an absent key = %v, want [0] from its own guest", miss)
	}

	// A protocol nothing claims reaches nobody. The transport still answers the frame (an
	// unclaimed protocol gets an empty response, not a dropped one, on every target), so
	// the check is that the answer is empty, not either app's.
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
