package main

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"

	"seedloader/qjs"
)

// The channel-identity handshake runs as
// the shared net-link.ts PeerLink inside QuickJS, over the Go TCP socket primitive
// (sock.go) and signing through the real `sodium`. Two PeerLinks complete the
// mutual HELLO/AUTH over a real loopback socket, attribute frames to the
// authenticated peerId, and honour expectPeerId — none of it logic in Go.

// netNode builds the minimal JS host stack a networking test needs: libsodium in
// its own wazero runtime, a QuickJS realm with the event loop, polyfills, sodium,
// the Go socket primitive, and the shared net-link bundle.
func netNode(t *testing.T) (*eventLoop, *qjs.Context, func()) {
	t.Helper()
	wrt := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfigCompiler())
	sd := bootSodium(wrt)

	rt, err := qjs.New()
	if err != nil {
		wrt.Close(ctx)
		t.Fatal(err)
	}
	qc := rt.Context()
	el := newEventLoop(qc)
	installPolyfills(qc)
	exposeSodium(qc, sd)
	exposeNet(qc, el)
	if _, err := qc.Eval("host-netlink.gen.js", qjs.Code(hostNetLinkJS)); err != nil {
		rt.Close()
		wrt.Close(ctx)
		t.Fatal("eval net-link bundle:", err)
	}
	return el, qc, func() { rt.Close(); wrt.Close(ctx) }
}

// The handshake runs identically over TCP and over WebSocket — the Go socket
// primitive presents the same RawChannel for both, so the shared PeerLink is
// transport-agnostic. WS additionally exercises the RFC 6455 handshake, masking
// direction, and framing in ws.go.
func TestPeerLinkHandshakeOverTCP(t *testing.T) { runHandshake(t, "netConnect", "netListen") }
func TestPeerLinkHandshakeOverWebSocket(t *testing.T) {
	runHandshake(t, "netConnectWS", "netListenWS")
}

func runHandshake(t *testing.T, connectFn, listenFn string) {
	el, qc, done := netNode(t)
	defer done()

	// A dials B; both authenticate; A sends a frame which B must receive attributed
	// to A's authenticated peerId. expectPeerId pins B's key on the dial.
	harness := fmt.Sprintf(`
		globalThis.__result = { aAuthed: false, bAuthed: false, aPeerId: "", bPeerId: "", frameFrom: "", frame: null };
		globalThis.startTest = function () {
		  const r = __result;
		  const idA = sodium.crypto_sign_keypair();
		  const idB = sodium.crypto_sign_keypair();
		  globalThis.__aPub = toHex(idA.publicKey);
		  globalThis.__bPub = toHex(idB.publicKey);
		  const maybeDone = () => { if (r.aAuthed && r.bAuthed && r.frame) __signal(); };

		  const port = %s("127.0.0.1", 0, (channel) => {
		    new PeerLink({
		      channel, identity: idB, sodium, weDialed: false,
		      onAuth: (peerId) => { r.bAuthed = true; r.bPeerId = peerId; maybeDone(); },
		      onFrame: (peerId, frame) => { r.frameFrom = peerId; r.frame = frame; maybeDone(); },
		      onClose: () => {},
		    });
		  });

		  const chA = %s("127.0.0.1", port);
		  new PeerLink({
		    channel: chA, identity: idA, sodium, weDialed: true,
		    expectPeerId: toHex(idB.publicKey),
		    onAuth: (peerId, link) => { r.aAuthed = true; r.aPeerId = peerId; link.send(new Uint8Array([42, 7, 9])); maybeDone(); },
		    onFrame: () => {},
		    onClose: () => {},
		  });
		};
	`, listenFn, connectFn)
	if _, err := qc.Eval("peerlink-harness.js", qjs.Code(harness)); err != nil {
		t.Fatal("harness:", err)
	}

	if err := el.runUntilSignal("startTest()", 5*time.Second); err != nil {
		t.Fatal(err)
	}

	r := qc.Global().GetPropertyStr("__result")
	if r.GetPropertyStr("aAuthed").String() != "true" || r.GetPropertyStr("bAuthed").String() != "true" {
		t.Fatalf("handshake did not complete: A=%s B=%s",
			r.GetPropertyStr("aAuthed").String(), r.GetPropertyStr("bAuthed").String())
	}
	aPub := qc.Global().GetPropertyStr("__aPub").String()
	bPub := qc.Global().GetPropertyStr("__bPub").String()
	if got := r.GetPropertyStr("aPeerId").String(); got != bPub {
		t.Fatalf("A authenticated peerId = %s, want B's pubkey %s", got, bPub)
	}
	if got := r.GetPropertyStr("bPeerId").String(); got != aPub {
		t.Fatalf("B authenticated peerId = %s, want A's pubkey %s", got, aPub)
	}
	if got := r.GetPropertyStr("frameFrom").String(); got != aPub {
		t.Fatalf("frame attributed to %s, want A's pubkey %s", got, aPub)
	}
	frame, err := qjs.JsTypedArrayToGo(r.GetPropertyStr("frame"))
	if err != nil {
		t.Fatal("frame bytes:", err)
	}
	if want := []byte{42, 7, 9}; !bytes.Equal(frame, want) {
		t.Fatalf("frame = %v, want %v", frame, want)
	}
}

func TestPeerLinkExpectPeerIdMismatch(t *testing.T) {
	el, qc, done := netNode(t)
	defer done()

	// A dials B but pins the WRONG expected key. On B's HELLO, A finds peerId !=
	// expectPeerId and drops the socket without sending AUTH — so A never auths and B
	// never auths. PeerLink.close() is intentionally silent on the closing side, so
	// the observable signal is B seeing the socket drop (its onClose).
	const harness = `
		globalThis.__res = { aAuthed: false, bAuthed: false, bClosed: false };
		globalThis.startTest = function () {
		  const r = __res;
		  const idA = sodium.crypto_sign_keypair();
		  const idB = sodium.crypto_sign_keypair();
		  const idWrong = sodium.crypto_sign_keypair();
		  const port = netListen("127.0.0.1", 0, (channel) => {
		    new PeerLink({ channel, identity: idB, sodium, weDialed: false,
		      onAuth: () => { r.bAuthed = true; }, onFrame: () => {},
		      onClose: () => { r.bClosed = true; __signal(); } });
		  });
		  const chA = netConnect("127.0.0.1", port);
		  new PeerLink({
		    channel: chA, identity: idA, sodium, weDialed: true,
		    expectPeerId: toHex(idWrong.publicKey),
		    onAuth: () => { r.aAuthed = true; __signal(); },
		    onFrame: () => {},
		    onClose: () => {},
		  });
		};
	`
	if _, err := qc.Eval("mismatch-harness.js", qjs.Code(harness)); err != nil {
		t.Fatal("harness:", err)
	}
	if err := el.runUntilSignal("startTest()", 5*time.Second); err != nil {
		t.Fatal(err)
	}
	res := qc.Global().GetPropertyStr("__res")
	if res.GetPropertyStr("aAuthed").String() == "true" {
		t.Fatal("A authenticated despite an expectPeerId mismatch")
	}
	if res.GetPropertyStr("bAuthed").String() == "true" {
		t.Fatal("B authenticated though A never sent AUTH")
	}
	if res.GetPropertyStr("bClosed").String() != "true" {
		t.Fatal("B did not observe the socket drop after A rejected the mismatch")
	}
}
