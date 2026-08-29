package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
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

// TestNativeAcceptedLinksShareRemoteSourceBudget proves the native accept bridge carries
// the peer IP all the way into RawLink.remoteAddr. Eight silent loopback connections fill
// the transport's per-source budget; the ninth must be closed while the first eight stay
// open. If the Go callback or native-shim drops the address, all nine remain admitted.
func TestNativeAcceptedLinksShareRemoteSourceBudget(t *testing.T) {
	bootRealm(t)
	if _, err := qc.Eval("source-cap-harness.js", qjs.Code(`
		setPolicy(JSON.stringify({ authors: [embeddedTransportAuthor],
		                           grants: { link: [embeddedTransportAuthor] } }));
		globalThis.__startSourceCapTest = async () => {
		  globalThis.__sourceCapNode = await makeTransportNode({
		    identity: sodium.crypto_sign_keypair(),
		    listen: { host: "127.0.0.1", port: 0 },
		  });
		  return new Uint8Array(0);
		};
		globalThis.__stopSourceCapTest = () => {
		  __sourceCapNode.shell.close();
		  return new Uint8Array(0);
		};
	`)); err != nil {
		t.Fatal("harness:", err)
	}
	if _, err := callRealm("__startSourceCapTest", 10*time.Second); err != nil {
		t.Fatal("start:", err)
	}
	defer func() { _, _ = callRealm("__stopSourceCapTest", 5*time.Second) }()
	port, err := strconv.Atoi(evalString(t, "String(__sourceCapNode.transport.port)"))
	if err != nil || port == 0 {
		t.Fatalf("listener port = %d, err = %v", port, err)
	}

	conns := make([]net.Conn, 0, 9)
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()
	for i := 0; i < 9; i++ {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i+1, err)
		}
		conns = append(conns, conn)
	}
	// Drive the Go-owned QuickJS loop so every posted accept reaches the transport guest.
	if kind, _, msg, err := el.await(`(async () => {
		await new Promise((resolve) => setTimeout(resolve, 100));
		return new Uint8Array(0);
	})()`, 2*time.Second); err != nil || kind != 0 {
		t.Fatalf("drain accepts: kind=%d msg=%q err=%v", kind, msg, err)
	}

	// Every admitted socket is silent and therefore has nothing to read, but remains open.
	for i, conn := range conns[:8] {
		_ = conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		_, err := conn.Read(make([]byte, 1))
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Fatalf("admitted connection %d closed early: %v", i+1, err)
		}
	}
	_ = conns[8].SetReadDeadline(time.Now().Add(time.Second))
	_, err = conns[8].Read(make([]byte, 1))
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("ninth connection from 127.0.0.1 was not refused by the per-source cap")
	}
	if err == nil {
		t.Fatal("refused connection unexpectedly delivered bytes")
	}
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
		  await a.shell.loadBundleBlob(__probe);
		  const bApp = await b.shell.loadBundleBlob(__probe);
		  teachAddr(b.shell, aId, "%s://127.0.0.1:" + a.transport.%s);
		  // The send op's own argument order (transport/src/core.js):
		  // [noReply u8][deadline u32][to blob][proto blob][payload blob]. The op NAME that
		  // leads it is the APP's framing, composed here (the shell passes bytes unread;
		  // the caller id is the shell's).
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
		  const opFrame = (name, b) => {
		    const out = new Uint8Array(1 + name.length + b.length);
		    out[0] = name.length;
		    for (let i = 0; i < name.length; i++) out[1 + i] = name.charCodeAt(i);
		    out.set(b, 1 + name.length);
		    return out;
		  };
		  const r = await bApp.invoke(opFrame("send", args));
		  if (r[0] !== 1) throw new Error("net: request failed");
		  return r.slice(1);
		};
	`, senderHex, listenArgs, transport, portField)
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
