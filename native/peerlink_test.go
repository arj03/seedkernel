package main

import (
	"bytes"
	"fmt"
	"testing"
	"time"



	"seedloader/qjs"
)

// The channel-identity handshake runs as
// the shared net-link.ts PeerLink inside QuickJS, over the Go TCP socket primitive
// (sock.go) and signing through the real `sodium`. Two PeerLinks complete the
// mutual HELLO/AUTH over a real loopback socket, attribute frames to the
// authenticated peerId, and honour expectPeerId — none of it logic in Go.

// These run in the production realm (bootRealm → boot): the Go socket primitive, the
// ws.wasm codec, and the shared bundle that carries PeerLink and the WS channels — so
// the test exercises no wiring of its own.

// The handshake runs identically over TCP and over WebSocket — the WS path wraps
// the same raw Go byte stream in the shared net-frame WsChannel, presenting the
// same RawChannel, so the shared PeerLink is transport-agnostic. WS additionally
// exercises the RFC 6455 handshake, masking direction, and framing (ws.wasm via
// __ws).
func TestPeerLinkHandshakeOverTCP(t *testing.T) { runHandshake(t, "netConnect", "netListen") }
func TestPeerLinkHandshakeOverWebSocket(t *testing.T) {
	runHandshake(t, "netConnectWS", "netListenWS")
}

func runHandshake(t *testing.T, connectFn, listenFn string) {
	bootRealm(t)

	// A dials B; both authenticate; A sends a frame which B must receive attributed
	// to A's authenticated peerId. expectPeerId pins B's key on the dial.
	harness := fmt.Sprintf(`
		globalThis.__result = { aAuthed: false, bAuthed: false, aPeerId: "", bPeerId: "", frameFrom: "", frame: null };
		globalThis.startTest = function () {
		  const r = __result;
		  const CONTACT = new Uint8Array(32).fill(3);
		  const idA = sodium.crypto_sign_keypair();
		  const idB = sodium.crypto_sign_keypair();
		  globalThis.__aPub = toHex(idA.publicKey);
		  globalThis.__bPub = toHex(idB.publicKey);
		  const maybeDone = () => { if (r.aAuthed && r.bAuthed && r.frame) __signal(); };

		  const port = %s("127.0.0.1", 0, (channel) => {
		    new PeerLink({
		      channel, identity: idB, sodium, weDialed: false, contactSecret: CONTACT,
		      onAuth: (peerId) => { r.bAuthed = true; r.bPeerId = peerId; maybeDone(); },
		      onFrame: (peerId, frame) => { r.frameFrom = peerId; r.frame = frame; maybeDone(); },
		      onClose: () => {},
		    });
		  });

		  const chA = %s("127.0.0.1", port);
		  new PeerLink({
		    channel: chA, identity: idA, sodium, weDialed: true, contactSecret: CONTACT,
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
	bootRealm(t)

	// A dials B but pins the WRONG expected key. Under the concealed suite (0x02) the
	// identities come LAST: A names itself at msg3 and B answers at msg4, so A can only
	// check `expectPeerId` after it has already revealed itself — net-link.ts says so in
	// as many words, and it is the standard Noise-XX limitation the four-message ordering
	// buys its identity hiding with. So the mismatch aborts A at msg4, and B — which saw
	// a perfectly good msg3 — HAS authenticated by then. That asymmetry is the assertion:
	// the pin protects A from talking to the wrong node, not from having said hello to it.
	//
	// PeerLink.close() is intentionally silent on the closing side, so the observable
	// signal is B seeing the socket drop (its onClose).
	const harness = `
		globalThis.__res = { aAuthed: false, bAuthed: false, bClosed: false };
		globalThis.startTest = function () {
		  const r = __res;
		  const CONTACT = new Uint8Array(32).fill(3);
		  const idA = sodium.crypto_sign_keypair();
		  const idB = sodium.crypto_sign_keypair();
		  const idWrong = sodium.crypto_sign_keypair();
		  const port = netListen("127.0.0.1", 0, (channel) => {
		    new PeerLink({ channel, identity: idB, sodium, weDialed: false, contactSecret: CONTACT,
		      onAuth: () => { r.bAuthed = true; }, onFrame: () => {},
		      onClose: () => { r.bClosed = true; __signal(); } });
		  });
		  const chA = netConnect("127.0.0.1", port);
		  new PeerLink({
		    channel: chA, identity: idA, sodium, weDialed: true, contactSecret: CONTACT,
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
	if res.GetPropertyStr("bAuthed").String() != "true" {
		t.Fatal("B should have authenticated at msg3 — A's identity is sent before it can check the pin")
	}
	if res.GetPropertyStr("bClosed").String() != "true" {
		t.Fatal("B did not observe the socket drop after A rejected the mismatch")
	}
}
