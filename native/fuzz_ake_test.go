//go:build fuzz

package main

import (
	"encoding/json"
	"testing"
	"time"

	"seedloader/qjs"
)

// ── fuzzing the handshake a stranger reaches (§12.6.2) ───────────────────────
//
// transport/src/ake.js is the widest pre-trust surface the kernel has. A node accepts up
// to `maxHalfOpenUnverified` connections at once, and every line this file runs on one of
// them runs before it knows who is on the other end: the router that decides which
// handshake step some bytes are, the four length checks, the AEAD probe the door gates on,
// and the identity proof. There is no signature to check first — checking one is what the
// exchange is FOR.
//
// The property is not "these bytes are rejected". It is the concealment claim itself:
//
//	an accepting link answers a stranger with SILENCE. Whatever bytes arrive, in
//	whatever pieces, the link never authenticates, never delivers a frame, never writes
//	anything but the one msg2 the protocol owes a proved msg1, and never closes for a
//	reason the sender could not already see.
//
// A refusal that closed the socket, or answered a wrong-length message differently from a
// wrong-key one, would hand a scanner an oracle for "this address speaks seedkernel, and
// that network key was close" — which is the whole thing §12.6.2 is built not to give.
//
// The links are the SIGNED transport bundle's own, evaluated in their module scope like
// framing's targets, over a REAL seam: this node's libsodium behind every crypto name,
// node/sign and node/verify bound to the link scope, and the bundle's own ML-KEM module
// run by Go. Nothing about the handshake is stubbed, so a forged proof has to beat the
// primitives rather than a harness that says yes.

// akeModulesJS lifts the two modules the handshake reaches out of the bundle the host
// embeds — the same ones the shipped guest calls by logical name.
const akeModulesJS = `
globalThis.__akeModuleBytes = (name) => unpackBundle(transportBundleBytes())[name + ".wasm"];
`

// akeFuzzJS stands one node's AKE up: the seam, the guest program's module scope, and the
// probes. Every probe answers ONE JSON line, so each assertion below is a Go statement
// about what the shared code did rather than a JS assertion the fuzzer cannot minimize.
const akeFuzzJS = `
"use strict";
{
  const enc0 = new TextEncoder(), dec0 = new TextDecoder();
  const fz = (o) => enc0.encode(JSON.stringify(o));

  const blob = transportBundleBytes();
  const bundle = verifyBundle(sodium, blob);
  const src = dec0.decode(unpackBundle(blob)["guest.js"]);
  // The author's own signed policy numbers, so the caps and deadlines applied here are a
  // deployment's rather than ones this test picked.
  const APP = bundle.manifest.guest.config;

  // The two secrets a stranger does not hold: the deployment's network key, which seeds
  // every handshake root, and the contact secret its door gates on. Fixed so both ends of
  // a harness exchange share them, and out of a mutator's reach either way — no sequence
  // of byte flips arrives at a BLAKE2b preimage. That is exactly the position the code
  // under test assumes it is in, so it is the position the fuzzer must attack from.
  const NETWORK_KEY = "1a".repeat(32);
  const CONTACT = "b7".repeat(32);
  const LOCAL = { networkKey: NETWORK_KEY, contactSecret: CONTACT, peers: [], admitPeers: [] };

  // What the handshake reaches that is not crypto: a socket and a clock. Both are
  // RECORDED rather than performed. The wire is what every assertion here is about, and a
  // deadline that actually fired would retire an exchange the fuzzer is still driving —
  // the timers are a different property (transport_test) and would only add flakiness.
  let wire = [], closes = 0, delivered = 0, authed = 0;
  const armedTimers = new Map();
  const rawNet = {
    open: () => ({ linkId: 0, stream: true }),   // no route: this harness dials nothing
    send: (linkId, bytes) => { wire.push(bytes.slice()); },
    close: () => { closes++; },
    deliver: () => { delivered++; return Promise.resolve(new Uint8Array(0)); },
  };
  const hostTimers = {
    arm: (id, ms) => { armedTimers.set(id, ms); },
    clear: (id) => { armedTimers.delete(id); },
  };

  // The guest program in its own module scope: the handshake reads its caps and deadlines
  // as file-scope constants, and ownPk is the let that start() fills from node/identity.
  const RET = "\nreturn {"
    + " Link: Link,"
    + " newLimiter: () => new LinkLimiter(maxUnverified, maxPerSource, maxVerified, maxAuthed),"
    + " setOwnPk: (pk) => { ownPk = pk; },"
    + " drainDeferred: () => { for (const f of deferQueue.splice(0)) { try { f(); } catch (e) { /* gone */ } } },"
    + " lens: { m1: M1_LEN, m2: M2_LEN, m3: M3_LEN, m4: M4_LEN, cap: MAX_HANDSHAKE_FRAME_BYTES, frame: maxFrameBytes }"
    + " };";

  // One node: its own identity, its own seam, its own copy of the guest program's module
  // scope. The seam is wired the way a link slot's is (shell-core.ts slotSignScope) —
  // libsodium behind the crypto names, node/sign and node/verify bound to
  // DOMAIN_link_scope with this network key, and the bundle's own modules over the §4 ABI.
  const mkNode = () => {
    const identity = sodium.crypto_sign_keypair();
    const seam = createGuestSeam({
      platform: { sodium: sodium, identity: identity, now: () => Date.now() },
      grants: {
        names: bundle.manifest.guest.requires,
        signScope: linkSignScope(identity, fromHex(NETWORK_KEY)),
        rawNet: rawNet,
        timers: hostTimers,
        calls: { call: () => null },
      },
      modules: {
        names: new Set(["ws", "mlkem"]),
        call: (name, payload) => Promise.resolve({
          bytes: new Uint8Array(name === "mlkem" ? __mlkemRun(payload) : __wsRun(payload)),
          ms: 0,
        }),
      },
    });
    const host = { call: (name, bytes) => seam(name, bytes) };
    const F = new Function("APP", "LOCAL", "host", src + RET)(APP, LOCAL, host);
    F.setOwnPk(identity.publicKey.slice());
    return F;
  };

  // TWO nodes, because a node refuses its own key as reflected traffic — openIdentity
  // says so at msg3 — so one scope playing both ends could never reach a session.
  const A = mkNode(), B = mkNode();
  const drain = () => { A.drainDeferred(); B.drainDeferred(); };

  let nextLink = 1;
  // PLATFORM-FRAMED (stream: false), which is the browser WebSocket and the RTC data
  // channel: message boundaries arrive with the bytes, so the fuzzer chooses them
  // directly. Stream framing is fuzz_framing_test's subject, and putting a codec in front
  // of this one would only spend the mutator's budget re-deriving length prefixes.
  const mkLink = (F, weDialed, limiter, source) => new F.Link({
    linkId: nextLink++,
    stream: false,
    dest: "", listener: "",
    weDialed: weDialed,
    expectPeerId: null,
    linkSecret: null,
    source: source,
    limiter: limiter,
    onAuth: () => { authed++; },
    onFrame: () => { delivered++; },
    onClose: () => {},
  });

  // Every seam name answers inline here, so a link's whole work chain drains in a handful
  // of microtask turns and needs no clock. Re-read each round: a step may append another.
  const settle = async (l) => {
    for (let i = 0; i < 6; i++) { await l.work; drain(); }
  };
  const take = () => { const out = wire; wire = []; return out; };
  const reset = () => { wire = []; closes = 0; delivered = 0; authed = 0; };

  // Cut the fuzzer's stream at the offsets it chose; each piece is one platform-framed
  // message. Zero-length pieces are dropped, so the splits only ever name real messages.
  const cut = (stream, splits) => {
    const out = [];
    let off = 0;
    for (const s of splits) {
      const n = Math.min(s, stream.length - off);
      if (n > 0) out.push(stream.subarray(off, off + n));
      off += n;
      if (off >= stream.length) break;
    }
    if (off < stream.length) out.push(stream.subarray(off));
    return out;
  };

  const feed = async (l, streamAB, splitsAB) => {
    const stream = new Uint8Array(streamAB);
    let threw = null, fed = 0, maxFed = 0, wantClose = false;
    for (const m of cut(stream, new Uint8Array(splitsAB))) {
      fed++;
      if (m.length > maxFed) maxFed = m.length;
      // The one message an accepting link is allowed to be loud about: one past the
      // pre-auth cap, whose length the sender measured itself. Recorded against the state
      // the link is in when it ARRIVES, because a link that has already refused reads no
      // further — silence is terminal, so an over-cap message behind a refusal is not a
      // message this link ever saw.
      if (!l.closed && !l.stalled && m.length > (l.authed ? A.lens.frame : A.lens.cap)) wantClose = true;
      // A throw out of onWire is itself the finding: it would unwind into the driver's
      // read pump, on the one realm every other link on this node shares.
      try { await l.onWire(m); } catch (e) { threw = String((e && e.message) || e); break; }
      drain();
    }
    await settle(l);
    return { threw: threw, fed: fed, maxFed: maxFed, wantClose: wantClose };
  };

  const report = (l, r) => fz({
    threw: r.threw, fed: r.fed, maxFed: r.maxFed, wantClose: r.wantClose,
    authed: l.authed, nAuth: authed, delivered: delivered,
    wire: take().map((b) => b.length),
    closes: closes, closed: l.closed, stalled: l.stalled,
    recvCtr: l.recvCtr, recvEpoch: l.recvEpoch,
  });

  globalThis.__akeLens = () => fz(A.lens);

  // One REAL msg1, for the corpus: what an initiator holding this network key and this
  // contact secret puts on the wire. A mutator that starts from a message which opens
  // reaches the KEM and the identity proof; one starting from noise never leaves the
  // first length check.
  globalThis.__akeMsg1 = async () => {
    reset();
    const d = mkLink(A, true, null, undefined);
    await settle(d);
    const out = take();
    return out.length === 1 ? out[0] : new Uint8Array(0);
  };

  // A stranger on an accepted link: our address, none of our secrets, arbitrary bytes in
  // pieces of its choosing. The half-open slot is real, since being turned away at the
  // door is one of the outcomes concealment has to cover.
  globalThis.__fuzzAkeAccept = async (streamAB, splitsAB) => {
    reset();
    const l = mkLink(B, false, B.newLimiter(), "203.0.113.7");
    await settle(l);
    take();   // an accept says nothing unprompted; this is empty, and asserted to be
    const r = await feed(l, streamAB, splitsAB);
    return report(l, r);
  };

  // Both ends of one exchange, run FOR REAL to a given point, and the link the fuzzer then
  // plays against:
  //   3 — a responder holding a proved msg1, waiting for the initiator's identity
  //   4 — an initiator that named itself, waiting for the responder's
  //   5 — a finished session, and its record layer
  // Stages 3 and 4 are the part of ake.js a stranger cannot reach but a cohort member
  // can: past the contact-secret probe, and still before anyone is authenticated.
  const pairTo = async (stage) => {
    reset();
    const d = mkLink(A, true, null, undefined);
    const r = mkLink(B, false, B.newLimiter(), "198.51.100.9");
    await settle(d); await settle(r);
    const w1 = take();
    if (w1.length !== 1 || w1[0].length !== A.lens.m1) return { bad: "initiator wrote " + w1.length + " message(s) as msg1" };
    await r.onWire(w1[0]); await settle(r);
    const w2 = take();
    if (w2.length !== 1 || w2[0].length !== A.lens.m2) return { bad: "responder answered a real msg1 with " + w2.length + " message(s)" };
    if (stage === 3) { reset(); return { l: r }; }
    await d.onWire(w2[0]); await settle(d);
    const w3 = take();
    if (w3.length !== 1 || w3[0].length !== A.lens.m3) return { bad: "initiator answered a real msg2 with " + w3.length + " message(s)" };
    if (stage === 4) { reset(); return { l: d }; }
    await r.onWire(w3[0]); await settle(r);
    const w4 = take();
    if (w4.length !== 1 || w4[0].length !== A.lens.m4) return { bad: "responder answered a real msg3 with " + w4.length + " message(s)" };
    await d.onWire(w4[0]); await settle(d);
    if (!d.authed || !r.authed) return { bad: "the harness handshake did not authenticate both ends" };
    reset();
    return { l: r };
  };

  globalThis.__fuzzAkeStage = async (stage, streamAB, splitsAB) => {
    const p = await pairTo(stage);
    if (p.bad) return fz({ bad: p.bad });
    const r = await feed(p.l, streamAB, splitsAB);
    return report(p.l, r);
  };
}
`

// akeOutcome is one probe's answer: what the link did, in the terms the claims are made
// in. Write LENGTHS rather than bytes — a write's size is what the concealment property is
// about, and the bytes themselves are the session's, not the fuzzer's to recognize.
type akeOutcome struct {
	Bad       string `json:"bad"`
	Threw     string `json:"threw"`
	Fed       int    `json:"fed"`
	MaxFed    int    `json:"maxFed"`
	WantClose bool   `json:"wantClose"`
	Authed    bool   `json:"authed"`
	NAuth     int    `json:"nAuth"`
	Delivered int    `json:"delivered"`
	Wire      []int  `json:"wire"`
	Closes    int    `json:"closes"`
	Closed    bool   `json:"closed"`
	Stalled   bool   `json:"stalled"`
	RecvCtr   int    `json:"recvCtr"`
	RecvEpoch int    `json:"recvEpoch"`
}

// akeLens is the handshake's own arithmetic, read out of the module scope rather than
// restated here: a Go copy of the four message widths would go stale the day the suite
// changes, and would be asserting against itself in the meantime.
type akeLens struct {
	M1    int `json:"m1"`
	M2    int `json:"m2"`
	M3    int `json:"m3"`
	M4    int `json:"m4"`
	Cap   int `json:"cap"`
	Frame int `json:"frame"`
}

var akeSizes akeLens

// akeFuzzRealm boots the realm once, hangs the bundle's two modules off it as the
// handshake's own host names, and evaluates the AKE in its module scope. Fuzzing re-enters
// a target thousands of times in one process, so none of this is per-iteration.
func akeFuzzRealm(f testing.TB) {
	f.Helper()
	bootRealm(f)
	if _, err := qc.Eval("fuzz-ake-modules.js", qjs.Code(akeModulesJS)); err != nil {
		f.Fatal("ake module probe:", err)
	}
	for _, m := range []struct{ name, global string }{{"ws", "__wsRun"}, {"mlkem", "__mlkemRun"}} {
		wasm, err := callRealm("__akeModuleBytes", 20*time.Second, qc.NewString(m.name))
		if err != nil {
			f.Fatalf("%s.wasm out of the transport bundle: %v", m.name, err)
		}
		w, err := instantiateWasm(wasm, fuzzScratchFloor, -1)
		if err != nil {
			f.Fatalf("instantiate %s.wasm: %v", m.name, err)
		}
		f.Cleanup(func() { closeModule(w) })
		qc.Global().SetPropertyStr(m.global, qc.Function(func(t *qjs.This) (*qjs.Value, error) {
			req, err := qjs.JsTypedArrayToGo(t.Args()[0])
			if err != nil {
				return nil, err
			}
			return bytesAB(t, callModuleRaw(w, req)), nil
		}))
	}
	if _, err := qc.Eval("fuzz-ake.js", qjs.Code(akeFuzzJS)); err != nil {
		f.Fatal("transport AKE scope:", err)
	}
	out, err := callRealm("__akeLens", 20*time.Second)
	if err != nil {
		f.Fatal("handshake message widths:", err)
	}
	if err := json.Unmarshal(out, &akeSizes); err != nil {
		f.Fatal("handshake message widths:", err)
	}
}

// akeRun drives one probe and decodes its answer.
func akeRun(t *testing.T, probe string, args ...*qjs.Value) akeOutcome {
	t.Helper()
	out, err := callRealm(probe, 60*time.Second, args...)
	if err != nil {
		// The probe catches what the link throws, so a rejection here is the REALM
		// failing — an out-of-memory, an engine fault, a wedged work chain — which is a
		// finding rather than a broken harness.
		t.Fatalf("%s: the realm itself failed: %v", probe, err)
	}
	var o akeOutcome
	if err := json.Unmarshal(out, &o); err != nil {
		t.Fatalf("%s: undecodable probe answer %q: %v", probe, out, err)
	}
	if o.Bad != "" {
		t.Fatalf("%s: the harness handshake broke before the fuzz input was fed: %s", probe, o.Bad)
	}
	return o
}

// silentUnderFire is the concealment claim, stated once for every pre-authentication link:
// whatever arrives, nothing escapes into the shared realm, nobody is authenticated,
// nothing is delivered, and the link is torn down only for something the sender could
// already see — an over-cap message, which it measured itself.
func silentUnderFire(t *testing.T, what string, o akeOutcome, stream, splits []byte) {
	t.Helper()
	if o.Threw != "" {
		t.Fatalf("%s: threw out of onWire (%q) — stream %d bytes, splits %v: %x",
			what, o.Threw, len(stream), head(splits), head(stream))
	}
	if o.Authed || o.NAuth != 0 {
		t.Fatalf("%s: AUTHENTICATED a peer that proved nothing (%d onAuth) — stream %d bytes, splits %v: %x",
			what, o.NAuth, len(stream), head(splits), head(stream))
	}
	if o.Delivered != 0 {
		t.Fatalf("%s: delivered %d frame(s) off an unauthenticated link — stream %d bytes, splits %v: %x",
			what, o.Delivered, len(stream), head(splits), head(stream))
	}
	// The one thing a refusal must not be is distinguishable from silence. A close for
	// anything but a message past the pre-auth cap — which the sender measured when it
	// built it — tells a scanner it guessed something right. Stated twice on purpose: the
	// first form is arithmetic on the input alone and cannot move with a bug, and the
	// second adds that an over-cap message on a LIVE link really does end it.
	if o.Closed && o.MaxFed <= akeSizes.Cap {
		t.Fatalf("%s: closed with nothing longer than %d bytes fed (the pre-auth cap is %d) — a refusal must be silence; stream %d bytes, splits %v: %x",
			what, o.MaxFed, akeSizes.Cap, len(stream), head(splits), head(stream))
	}
	if o.Closed != o.WantClose {
		t.Fatalf("%s: closed=%v, want %v (longest message %d bytes, pre-auth cap %d) — stream %d bytes, splits %v: %x",
			what, o.Closed, o.WantClose, o.MaxFed, akeSizes.Cap, len(stream), head(splits), head(stream))
	}
	if o.Closed != (o.Closes > 0) {
		t.Fatalf("%s: link closed=%v but %d socket close(s) — a link that gave up must release its socket; stream %d bytes: %x",
			what, o.Closed, o.Closes, len(stream), head(stream))
	}
}

// FuzzAkeAccept is the stranger's whole surface: an accepted socket, and bytes. Nothing
// here holds the network key or the contact secret, which is the position every one of the
// `maxHalfOpenUnverified` connections a node admits at once is in.
func FuzzAkeAccept(f *testing.F) {
	akeFuzzRealm(f)
	msg1, err := callRealm("__akeMsg1", 60*time.Second)
	if err != nil || len(msg1) != akeSizes.M1 {
		f.Fatalf("could not capture a real msg1 for the corpus (%d bytes, want %d): %v", len(msg1), akeSizes.M1, err)
	}
	// A message that OPENS, and the shapes around it: the mutator works outward from the
	// one input that reaches the KEM and the identity proof.
	f.Add(msg1, []byte{})
	f.Add(msg1, []byte{200, 200, 200, 200, 200, 200, 200})
	f.Add(append(append([]byte{}, msg1...), msg1...), []byte{byte(akeSizes.M1 % 256)})
	f.Add(msg1[:len(msg1)-1], []byte{})
	f.Add(append(append([]byte{}, msg1...), 0), []byte{})
	// A msg1 whose suite byte is not this transport's, and one whose sealed probe is all
	// zeroes: two refusals that must be indistinguishable from outside.
	other := append([]byte{}, msg1...)
	other[0] = 0x01
	f.Add(other, []byte{})
	f.Add(make([]byte, akeSizes.M1), []byte{})
	// The other widths, so a message that is the right size for the WRONG step is tried
	// against a link that is not at that step.
	f.Add(make([]byte, akeSizes.M2), []byte{})
	f.Add(make([]byte, akeSizes.M3), []byte{})
	f.Add([]byte{}, []byte{})
	f.Add([]byte{0x03}, []byte{})
	// Past the pre-auth cap: the one refusal that is allowed to be loud.
	f.Add(make([]byte, akeSizes.Cap+1), []byte{})
	// The same, but behind a message that already stalled the link — which onWire reads no
	// further, so this one is never seen and the link stays silent. Found by the fuzzer.
	f.Add(make([]byte, akeSizes.Cap+2), []byte{1})

	f.Fuzz(func(t *testing.T, stream, splits []byte) {
		if len(stream) > 1<<18 {
			t.Skip()
		}
		o := akeRun(t, "__fuzzAkeAccept", qc.NewArrayBuffer(stream), qc.NewArrayBuffer(splits))
		silentUnderFire(t, "accept", o, stream, splits)
		// An accepting link owes a stranger exactly one message, and only for a msg1 that
		// opened under the contact secret: msg2, at its one width. A second write, or one
		// of any other size, is the exchange leaking how far the sender got.
		if len(o.Wire) > 1 {
			t.Fatalf("accept: wrote %d messages (%v) before authenticating anyone — stream %d bytes, splits %v: %x",
				len(o.Wire), o.Wire, len(stream), head(splits), head(stream))
		}
		for _, n := range o.Wire {
			if n != akeSizes.M2 {
				t.Fatalf("accept: answered with a %d-byte message; the only thing owed here is msg2 (%d bytes) — stream %d bytes, splits %v: %x",
					n, akeSizes.M2, len(stream), head(splits), head(stream))
			}
		}
	})
}

// FuzzAkeIdentity is the half of the handshake past the door: the harness runs a real
// exchange up to the identity proof and then lets the fuzzer supply it. Reachable only by
// something that already opened a msg1 under the contact secret — a cohort member, or
// whoever stole that secret — and still entirely before anyone is authenticated, which is
// what makes it worth a target of its own.
//
//	side 0 — a responder waiting for msg3, the initiator's identity
//	side 1 — an initiator waiting for msg4, the responder's
func FuzzAkeIdentity(f *testing.F) {
	akeFuzzRealm(f)
	f.Add(byte(0), make([]byte, akeSizes.M3), []byte{})
	f.Add(byte(1), make([]byte, akeSizes.M4), []byte{})
	f.Add(byte(0), []byte{}, []byte{})
	f.Add(byte(1), []byte{}, []byte{})
	f.Add(byte(0), make([]byte, akeSizes.M3-1), []byte{})
	f.Add(byte(1), make([]byte, akeSizes.M4+1), []byte{})
	f.Add(byte(0), make([]byte, akeSizes.M3*3), []byte{byte(akeSizes.M3)})
	f.Add(byte(0), make([]byte, akeSizes.Cap+1), []byte{})

	f.Fuzz(func(t *testing.T, side byte, stream, splits []byte) {
		if len(stream) > 1<<18 {
			t.Skip()
		}
		stage, what := 3, "msg3 at a responder"
		if side&1 == 1 {
			stage, what = 4, "msg4 at an initiator"
		}
		o := akeRun(t, "__fuzzAkeStage", qc.NewInt64(int64(stage)),
			qc.NewArrayBuffer(stream), qc.NewArrayBuffer(splits))
		silentUnderFire(t, what, o, stream, splits)
		// Neither end answers an identity it could not verify. The responder's msg4 is the
		// reply to a PROVED msg3 and nothing else; the initiator, already named, writes
		// nothing at all here. A write is this node signing over a transcript a stranger
		// chose.
		if len(o.Wire) != 0 {
			t.Fatalf("%s: wrote %v in answer to an identity that does not verify — stream %d bytes, splits %v: %x",
				what, o.Wire, len(stream), head(splits), head(stream))
		}
	})
}

// FuzzAkeRecord is the record layer on a link that DID authenticate: a real session
// between two harness ends, then forged bodies. Reached by anything that can write on that
// socket — an injector on the path, or a peer gone bad — so a body that opens is the whole
// of what the AEAD's authenticity claim rests on.
//
// The setup is a full ML-KEM exchange per iteration, so this target runs orders of
// magnitude slower than the other two. That is the honest cost of testing the shipped
// handshake rather than a link with keys poked into it, and the invariant it states is
// checked on every `go test` run through the seed corpus regardless.
func FuzzAkeRecord(f *testing.F) {
	akeFuzzRealm(f)
	f.Add([]byte{}, []byte{})
	f.Add(make([]byte, 16), []byte{}) // exactly a tag, no ciphertext
	f.Add(make([]byte, 15), []byte{}) // one byte short of a tag
	f.Add(make([]byte, 64), []byte{})
	f.Add(make([]byte, 64), []byte{16}) // two bodies, so the second meets a dead link
	f.Add(make([]byte, akeSizes.Frame+1), []byte{})

	f.Fuzz(func(t *testing.T, stream, splits []byte) {
		if len(stream) > akeSizes.Frame+(1<<12) {
			t.Skip()
		}
		o := akeRun(t, "__fuzzAkeStage", qc.NewInt64(5),
			qc.NewArrayBuffer(stream), qc.NewArrayBuffer(splits))
		if o.Threw != "" {
			t.Fatalf("record: threw out of onWire (%q) — stream %d bytes, splits %v: %x",
				o.Threw, len(stream), head(splits), head(stream))
		}
		if o.Delivered != 0 || o.NAuth != 0 {
			t.Fatalf("record: a forged body was ACCEPTED (%d delivered, %d auth) — stream %d bytes, splits %v: %x",
				o.Delivered, o.NAuth, len(stream), head(splits), head(stream))
		}
		if len(o.Wire) != 0 {
			t.Fatalf("record: answered a forged body with %v — stream %d bytes, splits %v: %x",
				o.Wire, len(stream), head(splits), head(stream))
		}
		// "Advance only on success — a failed decrypt must never move the counter." A
		// counter that moved would desynchronize the nonce sequence, and an injector who
		// could nudge it could silently kill the next real record.
		if o.RecvCtr != 0 || o.RecvEpoch != 0 {
			t.Fatalf("record: a failed open moved the receive counter to epoch %d ctr %d — stream %d bytes: %x",
				o.RecvEpoch, o.RecvCtr, len(stream), head(stream))
		}
		// Post-authentication the link SPEAKS: concealment is owed to strangers, and this
		// peer proved who it is. So one forged body is enough to end the link, and a link
		// fed nothing must still be up.
		if wantClosed := o.Fed > 0; o.Closed != wantClosed {
			t.Fatalf("record: closed=%v after %d forged body/bodies — stream %d bytes: %x",
				o.Closed, o.Fed, len(stream), head(stream))
		}
	})
}
