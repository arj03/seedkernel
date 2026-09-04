package main

import (
	"bytes"
	"encoding/binary"
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

  // ── entropy a fuzzer can reproduce ─────────────────────────────────────────
  //
  // Everything random in this handshake arrives through one host name (ake.js randomBytes →
  // node/random): the x25519 ephemeral, the ML-KEM keygen seed, its encapsulation coins,
  // and the nonce msg1 seals. Left to libsodium, one fuzz input drives a DIFFERENT exchange
  // on every execution — so a crash the corpus records need not reproduce when it is
  // replayed, and a shaped-record patch that happened to overwrite a ciphertext byte with
  // the value already there in one run changes it in the next. A target whose answer
  // depends on which run it is cannot be minimized.
  //
  // A xorshift32 stream, restarted at the head of every probe, makes an input a function of
  // itself again. It is entropy for a HARNESS, not for a peer: the two things a stranger
  // must not be able to guess are NETWORK_KEY and CONTACT above, which are fixed constants
  // either way, and no probe below asks anything of the ephemerals but that the code under
  // test refuse what it should.
  let rng = 0;
  const reseed = () => { rng = 0x9e3779b9 | 0; }; // never zero: xorshift32 sticks there
  const fuzzRandom = (n) => {
    const out = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
      rng ^= rng << 13; rng |= 0;
      rng ^= rng >>> 17;
      rng ^= rng << 5; rng |= 0;
      out[i] = rng & 0xff;
    }
    return out;
  };
  reseed();
  // Real libsodium behind every primitive; only the one call that must not vary is ours.
  const fuzzSodium = Object.assign({}, sodium, { randombytes_buf: fuzzRandom });

  // Which host names an execution actually reached, recorded at the seam the harness already
  // owns. This is the handshake's own progress: ake.js is not instrumented and does not need
  // to be, because the names it calls ARE its milestones — the x25519 over a point the input
  // chose, the ML-KEM call, the identity verify. Nothing else separates a msg1 refused on its
  // suite byte from one that got a responder all the way to an encapsulation, and the fuzzer
  // has to be able to tell those apart to climb from one to the other (fuzz_cov_test.go).
  //
  // The mlkem module's op byte rides along: keygen, encapsulation and decapsulation are three
  // different distances into the exchange.
  let reached = [];
  const noteCall = (name, bytes) => {
    const tag = name === "mlkem" ? "mlkem:" + bytes[0] : name;
    if (reached.indexOf(tag) < 0) reached.push(tag);
  };

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
    // The two step labels, for the shaped probes below: they build a message the link will
    // OPEN, using the link's own kdf, and a label restated here would be a second copy of
    // the one thing that separates one step's key from another's.
    + " labels: { m3: LABEL_M3, m4: LABEL_M4 },"
    + " lens: { m1: M1_LEN, m2: M2_LEN, m3: M3_LEN, m4: M4_LEN, cap: MAX_HANDSHAKE_FRAME_BYTES,"
    + "   frame: maxFrameBytes, suite: SUITE_LEN, eph: EPH_LEN, kemPk: KEM_PK_LEN,"
    + "   nonce: NONCE_LEN, tag: TAG_LEN }"
    + " };";

  // One node: its own identity, its own seam, its own copy of the guest program's module
  // scope. The seam is wired the way a link slot's is (shell-core.ts slotSignScope) —
  // libsodium behind the crypto names, node/sign and node/verify bound to
  // DOMAIN_link_scope with this network key, and the bundle's own modules over the §4 ABI.
  const mkNode = (seedByte) => {
    // A FIXED identity per node, for the same reason the entropy above is fixed: this key
    // is signed over in every transcript the harness builds, so a fresh keypair per process
    // would make a recorded failure a different exchange to replay. Distinct per node
    // because a link refuses its own key reflected back at it (openIdentity).
    const identity = sodium.crypto_sign_seed_keypair(new Uint8Array(32).fill(seedByte));
    const seam = createGuestSeam({
      platform: { sodium: fuzzSodium, identity: identity, now: () => Date.now() },
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
    const host = { call: (name, bytes) => { noteCall(name, bytes); return seam(name, bytes); } };
    const F = new Function("APP", "LOCAL", "host", src + RET)(APP, LOCAL, host);
    F.setOwnPk(identity.publicKey.slice());
    return F;
  };

  // TWO nodes, because a node refuses its own key as reflected traffic — openIdentity
  // says so at msg3 — so one scope playing both ends could never reach a session.
  const A = mkNode(0x11), B = mkNode(0x22);
  const drain = () => { A.drainDeferred(); B.drainDeferred(); };

  // Every link this scope has built and not yet released.
  //
  // A stalled link keeps its deadline ARMED — that is the design, since silence has to cost
  // the sender its slot until the normal timeout — and the guest's timer table holds the
  // callback, which holds the link, which holds its ephemeral and its KEM state. Nothing
  // here ever fires a clock, so an execution that does not release its links leaves them in
  // that table for the life of the worker: at a few thousand executions a second the process
  // is gigabytes deep and killed long before its ten minutes are up.
  //
  // Swept at the START of an execution, never the end, so a report is always built while its
  // link is still live.
  const live = [];
  const sweep = () => {
    for (const l of live.splice(0)) {
      // What the host calls when a socket goes away: it clears the deadline — and with it the
      // guest's timer entry — releases the slot and wipes the keys.
      try { l.onChannelClosed(); } catch (e) { /* already gone */ }
    }
    drain();
    armedTimers.clear();
    // Once per probe, and this is the one place that is true — so the entropy every
    // exchange below draws on starts at the same byte for the same input, however many
    // executions the fuzzer has already run in this process.
    reseed();
  };

  let nextLink = 1;
  // PLATFORM-FRAMED (stream: false), which is the browser WebSocket and the RTC data
  // channel: message boundaries arrive with the bytes, so the fuzzer chooses them
  // directly. Stream framing is fuzz_framing_test's subject, and putting a codec in front
  // of this one would only spend the mutator's budget re-deriving length prefixes.
  const mkLink = (F, weDialed, limiter, source) => {
    const l = new F.Link({
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
    live.push(l);
    return l;
  };

  // Every seam name answers inline here, so a link's whole work chain drains in a handful
  // of microtask turns and needs no clock. Re-read each round: a step may append another.
  const settle = async (l) => {
    for (let i = 0; i < 6; i++) { await l.work; drain(); }
  };
  const take = () => { const out = wire; wire = []; return out; };
  // Cleared here, which is exactly where the harness stops setting an exchange up and starts
  // feeding it the fuzzer's bytes — so the call log names what the INPUT reached, not what
  // building a session to feed it to costs.
  const reset = () => { wire = []; closes = 0; delivered = 0; authed = 0; reached = []; };

  // Cut the fuzzer's stream at the sizes it chose, each a big-endian uint32; every piece is
  // one platform-framed message. A byte apiece could not name the two widths that matter —
  // msg1 and msg2 both run past a kilobyte, since each carries an ML-KEM key — so the only
  // splits that ever landed on a message boundary were the ones the trailing remainder
  // produced by accident, and a seed meaning "cut after msg1" was really saying that width
  // modulo 256. Four bytes reaches a whole maximum-sized record as easily as a msg3.
  // Zero-length pieces are dropped, so the splits only ever name real messages.
  const cut = (stream, splits) => {
    const out = [];
    let off = 0;
    for (let i = 0; i + 3 < splits.length; i += 4) {
      const want = ((splits[i] << 24) | (splits[i + 1] << 16) | (splits[i + 2] << 8) | splits[i + 3]) >>> 0;
      const n = Math.min(want, stream.length - off);
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

  const report = (l, r, extra) => fz(Object.assign({
    threw: r.threw, fed: r.fed, maxFed: r.maxFed, wantClose: r.wantClose,
    authed: l.authed, nAuth: authed, delivered: delivered,
    wire: take().map((b) => b.length),
    closes: closes, closed: l.closed, stalled: l.stalled,
    recvCtr: l.recvCtr, recvEpoch: l.recvEpoch, reached: reached.slice(),
  }, extra || {}));

  // Rewrite bytes at offsets the fuzzer chose, and report how many POSITIONS ended up
  // holding something other than what they held before. What the callers key on is "is this
  // still the message this session built", so the answer has to come from comparing the
  // finished buffer against a snapshot of it — counting writes that changed the byte under
  // them at the time gets it wrong in both directions: a write of the value already there
  // changes nothing, and two writes to one offset can put the original back while the count
  // says the message was corrupted.
  const patchBytes = (buf, patch) => {
    const before = buf.slice();
    for (let i = 0; i + 2 < patch.length; i += 3) {
      buf[(((patch[i] << 8) | patch[i + 1]) >>> 0) % buf.length] = patch[i + 2];
    }
    let n = 0;
    for (let i = 0; i < buf.length; i++) if (buf[i] !== before[i]) n++;
    return n;
  };

  const cat = (a, b) => {
    const out = new Uint8Array(a.length + b.length);
    out.set(a); out.set(b, a.length);
    return out;
  };

  globalThis.__akeLens = () => fz(A.lens);

  // One REAL msg1, for the corpus: what an initiator holding this network key and this
  // contact secret puts on the wire. A mutator that starts from a message which opens
  // reaches the KEM and the identity proof; one starting from noise never leaves the
  // first length check.
  globalThis.__akeMsg1 = async () => {
    sweep(); reset();
    const d = mkLink(A, true, null, undefined);
    await settle(d);
    const out = take();
    return out.length === 1 ? out[0] : new Uint8Array(0);
  };

  // A stranger on an accepted link: our address, none of our secrets, arbitrary bytes in
  // pieces of its choosing. The half-open slot is real, since being turned away at the
  // door is one of the outcomes concealment has to cover.
  globalThis.__fuzzAkeAccept = async (streamAB, splitsAB) => {
    sweep(); reset();
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
    sweep(); reset();
    const d = mkLink(A, true, null, undefined);
    const r = mkLink(B, false, B.newLimiter(), "198.51.100.9");
    await settle(d); await settle(r);
    const w1 = take();
    if (w1.length !== 1 || w1[0].length !== A.lens.m1) return { bad: "initiator wrote " + w1.length + " message(s) as msg1" };
    await r.onWire(w1[0]); await settle(r);
    const w2 = take();
    if (w2.length !== 1 || w2[0].length !== A.lens.m2) return { bad: "responder answered a real msg1 with " + w2.length + " message(s)" };
    // Both ends every time: the one under test, and the one whose turn it is to speak —
    // which is the only thing that can sign an identity this link will accept.
    if (stage === 3) { reset(); return { l: r, d: d, r: r }; }
    await d.onWire(w2[0]); await settle(d);
    const w3 = take();
    if (w3.length !== 1 || w3[0].length !== A.lens.m3) return { bad: "initiator answered a real msg2 with " + w3.length + " message(s)" };
    if (stage === 4) { reset(); return { l: d, d: d, r: r }; }
    await r.onWire(w3[0]); await settle(r);
    const w4 = take();
    if (w4.length !== 1 || w4[0].length !== A.lens.m4) return { bad: "responder answered a real msg3 with " + w4.length + " message(s)" };
    await d.onWire(w4[0]); await settle(d);
    if (!d.authed || !r.authed) return { bad: "the harness handshake did not authenticate both ends" };
    reset();
    return { l: r, d: d, r: r };
  };

  globalThis.__fuzzAkeStage = async (stage, streamAB, splitsAB) => {
    const p = await pairTo(stage);
    if (p.bad) return fz({ bad: p.bad });
    const r = await feed(p.l, streamAB, splitsAB);
    return report(p.l, r);
  };

  // ── past the door ──────────────────────────────────────────────────────────
  //
  // Everything above attacks from outside the cohort, and a mutator's reach ends at the
  // first proof: msg1's probe key is derived over the suite, the ephemeral and the KEM key,
  // so one flipped byte anywhere changes the key its own seal must open under, and every
  // execution dies at the same check. Whole halves of ake.js are behind that check and have
  // never seen an input — x25519 over a chosen point, ML-KEM encapsulation over 1184 chosen
  // bytes, the identity verify, the record layer's open.
  //
  // So the probes below hold what the cohort holds — the network key and the contact secret
  // — and let the fuzzer choose everything else. That is a member of this deployment, or
  // whoever took its contact secret, and §12.6.2 owes it exactly what it owes a stranger:
  // nothing authenticates without a signature that verifies, nothing is delivered off a
  // link that never authenticated, and a refusal is silence.
  //
  // Each message is built with the implementation's OWN primitives, on the link that will
  // read it — its probeKey, its kdf, its sealZero — so the harness restates no derivation
  // and cannot drift from one.

  // A msg1 the door opens, over fields the fuzzer chose.
  globalThis.__fuzzAkeShapedMsg1 = async (patchAB) => {
    sweep(); reset();
    // A real msg1 for its valid fields; the dialling link is also what holds a root to seal
    // a probe with. The sealed nonce is not recoverable from it and need not be — the
    // responder proves the seal and never reads the plaintext — so this supplies its own.
    const d = mkLink(A, true, null, undefined);
    await settle(d);
    const w1 = take();
    if (w1.length !== 1 || w1[0].length !== A.lens.m1) return fz({ bad: "no msg1 to shape" });
    const headLen = A.lens.suite + A.lens.eph + A.lens.kemPk;
    const fields = new Uint8Array(headLen + A.lens.nonce);
    fields.set(w1[0].subarray(0, headLen));
    const patched = patchBytes(fields, new Uint8Array(patchAB));
    const sealed = await d.sealZero(
      await d.probeKey(fields.subarray(0, A.lens.suite),
        fields.subarray(A.lens.suite, A.lens.suite + A.lens.eph),
        fields.subarray(A.lens.suite + A.lens.eph, headLen)),
      fields.subarray(headLen));
    const msg = cat(fields.subarray(0, headLen), sealed);
    reset();
    const l = mkLink(B, false, B.newLimiter(), "203.0.113.7");
    await settle(l);
    take();
    const r = await feed(l, msg, new Uint8Array(0));
    return report(l, r, { patched: patched });
  };

  // An identity message that DECRYPTS, carrying an identity the fuzzer chose. The AEAD sits
  // in front of the signature check, so this is the only way anything reaches the verify at
  // all — and the only way the reflected-key refusal is reachable.
  const shapedIdentity = async (stage, pt) => {
    const p = await pairTo(stage);
    if (p.bad) return { bad: p.bad };
    const l = p.l;
    const key = await l.kdf([l.ee, l.kemSecret], l.th, stage === 3 ? A.labels.m3 : A.labels.m4);
    return { l: l, msg: await l.sealZero(key, pt) };
  };

  globalThis.__fuzzAkeShapedIdentity = async (stage, ptAB) => {
    const s = await shapedIdentity(stage, new Uint8Array(ptAB));
    if (s.bad) return fz({ bad: s.bad });
    return report(s.l, await feed(s.l, s.msg, new Uint8Array(0)));
  };

  // The two identities no fuzzer can spell, because both need a signature over a transcript
  // that only exists inside a link: the one whose turn it is, and OUR OWN reflected back at
  // us. They are a pair on purpose — the genuine one proves this construction really does
  // reach the signature check and get past it, which is the only thing that makes the
  // reflected one's refusal evidence about the reflection rather than about a message that
  // never opened.
  globalThis.__akeIdentityCase = async (stage, reflected) => {
    const p = await pairTo(stage);
    if (p.bad) return fz({ bad: p.bad });
    const l = p.l;
    // signIdentity takes the transcript, so the peer signs over the one THIS link will
    // verify against — its own is a step behind, and that is the whole of the difference.
    const signer = reflected ? l : (stage === 3 ? p.d : p.r);
    const si = await signer.signIdentity(l.th);
    if (!si) return fz({ bad: "an end would not sign its identity" });
    const key = await l.kdf([l.ee, l.kemSecret], l.th, stage === 3 ? A.labels.m3 : A.labels.m4);
    const msg = await l.sealZero(key, cat(si.id, si.sig));
    return report(l, await feed(l, msg, new Uint8Array(0)));
  };

  // A record this session really sealed, then corrupted at offsets the fuzzer chose. With
  // nothing changed it is the accept path — the only place these targets exercise one.
  globalThis.__fuzzAkeShapedRecord = async (bodyAB, patchAB) => {
    const p = await pairTo(5);
    if (p.bad) return fz({ bad: p.bad });
    p.d.send(new Uint8Array(bodyAB));
    await settle(p.d);
    const w = take();
    if (w.length !== 1) return fz({ bad: "one send sealed " + w.length + " record(s)" });
    const rec = w[0].slice();
    const patched = patchBytes(rec, new Uint8Array(patchAB));
    reset();
    return report(p.l, await feed(p.l, rec, new Uint8Array(0)), { patched: patched });
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
	Patched   int    `json:"patched"` // shaped probes: bytes the fuzzer actually changed
	// Host names this execution reached, for the mutator alone (fuzz_cov_test.go). No
	// assertion reads it: what a link is ALLOWED to do is stated in the fields above, and a
	// claim about which primitives it called on the way would pin the implementation rather
	// than the property.
	Reached []string `json:"reached"`
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
	// msg1's field widths, for the shaped target's patch offsets, and the AEAD tag, which
	// is what separates a step's message width from the plaintext it carries.
	Suite int `json:"suite"`
	Eph   int `json:"eph"`
	KemPk int `json:"kemPk"`
	Nonce int `json:"nonce"`
	Tag   int `json:"tag"`
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

// akeSplitsOf encodes message sizes the way the probes read them: one big-endian uint32
// each. Wider than framing's uint16 because these pieces are whole messages rather than
// stream slices, and one of them is a 2 MiB record. The fuzzer mutates these bytes freely;
// this is for the seeds, which want to NAME a handshake width rather than spell it.
func akeSplitsOf(ns ...int) []byte {
	out := make([]byte, 0, len(ns)*4)
	for _, n := range ns {
		out = binary.BigEndian.AppendUint32(out, uint32(n))
	}
	return out
}

// akeSeamMilestone maps the host names ake.js reaches to the progress each one stands for.
//
// The names it calls on EVERY execution — node/random, link/send, link/close, the timers,
// the transcript hash — are deliberately absent: a milestone every input passes is not a
// gradient, it is a constant. What is left is the sequence a msg1 has to earn its way
// through, one entry per step, so an input that got to the encapsulation and an input that
// died on the suite byte are two different sets of blocks rather than one "closed".
var akeSeamMilestone = map[string]covID{
	"crypto/x25519/dh":                  covAkeDh,
	"mlkem:0":                           covAkeKemKeygen,
	"mlkem:1":                           covAkeKemEncaps,
	"mlkem:2":                           covAkeKemDecaps,
	"crypto/chacha20poly1305-ietf/seal": covAkeAeadSeal,
	"crypto/chacha20poly1305-ietf/open": covAkeAeadOpen,
	"node/verify":                       covAkeVerify,
	"node/sign":                         covAkeSign,
}

// covMarkAke marks how far one link GOT (fuzz_cov_test.go): what it ended as, and every
// step of the handshake it reached on the way. The six targets share these ids because they
// share a subject — one Link, driven from different stages.
func covMarkAke(o akeOutcome) {
	covMarkIf(o.Threw != "", covAkeThrew)
	covMarkIf(o.Closed, covAkeClosed)
	covMarkIf(o.Stalled, covAkeStalled)
	covMarkIf(len(o.Wire) > 0, covAkeWrote)
	covMarkIf(o.Authed, covAkeAuthed)
	covMarkIf(o.Delivered > 0, covAkeDelivered)
	covMarkIf(o.RecvCtr > 0, covAkeRecordOpened)
	for _, name := range o.Reached {
		if id, ok := akeSeamMilestone[name]; ok {
			covMark(id)
		}
	}
}

// silentUnderFire is the concealment claim, stated once for every pre-authentication link:
// whatever arrives, nothing escapes into the shared realm, nobody is authenticated,
// nothing is delivered, and the link is torn down only for something the sender could
// already see — an over-cap message, which it measured itself.
func silentUnderFire(t *testing.T, what string, o akeOutcome, stream, splits []byte) {
	t.Helper()
	covMarkAke(o)
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
	f.Add(msg1, akeSplitsOf())
	f.Add(msg1, akeSplitsOf(200, 200, 200, 200, 200, 200, 200))
	// Two whole msg1s, cut exactly between them — the second one meeting a link that has
	// already answered the first. A byte-wide split could not say this.
	f.Add(append(append([]byte{}, msg1...), msg1...), akeSplitsOf(akeSizes.M1))
	f.Add(msg1[:len(msg1)-1], akeSplitsOf())
	f.Add(append(append([]byte{}, msg1...), 0), akeSplitsOf())
	// One msg1 delivered as two messages, split down the middle: neither half is a message
	// at any width this protocol has.
	f.Add(msg1, akeSplitsOf(akeSizes.M1/2))
	// A msg1 whose suite byte is not this transport's, and one whose sealed probe is all
	// zeroes: two refusals that must be indistinguishable from outside.
	other := append([]byte{}, msg1...)
	other[0] = 0x01
	f.Add(other, akeSplitsOf())
	f.Add(make([]byte, akeSizes.M1), akeSplitsOf())
	// The other widths, so a message that is the right size for the WRONG step is tried
	// against a link that is not at that step.
	f.Add(make([]byte, akeSizes.M2), akeSplitsOf())
	f.Add(make([]byte, akeSizes.M3), akeSplitsOf())
	f.Add([]byte{}, akeSplitsOf())
	f.Add([]byte{0x03}, akeSplitsOf())
	// Past the pre-auth cap: the one refusal that is allowed to be loud.
	f.Add(make([]byte, akeSizes.Cap+1), akeSplitsOf())
	// The same, but behind a message that already stalled the link — which onWire reads no
	// further, so this one is never seen and the link stays silent. Found by the fuzzer.
	f.Add(make([]byte, akeSizes.Cap+2), akeSplitsOf(1))

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
	f.Add(byte(0), make([]byte, akeSizes.M3), akeSplitsOf())
	f.Add(byte(1), make([]byte, akeSizes.M4), akeSplitsOf())
	f.Add(byte(0), []byte{}, akeSplitsOf())
	f.Add(byte(1), []byte{}, akeSplitsOf())
	f.Add(byte(0), make([]byte, akeSizes.M3-1), akeSplitsOf())
	f.Add(byte(1), make([]byte, akeSizes.M4+1), akeSplitsOf())
	// Three back-to-back messages of exactly the width this step expects: the second and
	// third meet a link that already refused the first.
	f.Add(byte(0), make([]byte, akeSizes.M3*3), akeSplitsOf(akeSizes.M3, akeSizes.M3))
	f.Add(byte(0), make([]byte, akeSizes.Cap+1), akeSplitsOf())

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
	f.Add([]byte{}, akeSplitsOf())
	f.Add(make([]byte, 16), akeSplitsOf()) // exactly a tag, no ciphertext
	f.Add(make([]byte, 15), akeSplitsOf()) // one byte short of a tag
	f.Add(make([]byte, 64), akeSplitsOf())
	f.Add(make([]byte, 64), akeSplitsOf(16)) // two bodies, so the second meets a dead link
	f.Add(make([]byte, akeSizes.Frame+1), akeSplitsOf())

	f.Fuzz(func(t *testing.T, stream, splits []byte) {
		if len(stream) > akeSizes.Frame+(1<<12) {
			t.Skip()
		}
		o := akeRun(t, "__fuzzAkeStage", qc.NewInt64(5),
			qc.NewArrayBuffer(stream), qc.NewArrayBuffer(splits))
		covMarkAke(o)
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

// ── the cohort's half of the handshake ───────────────────────────────────────
//
// The three targets above attack from outside, where a byte-level mutation cannot get past
// msg1's contact-secret probe — the probe key is derived over the very fields a mutation
// changes. The three below hold the deployment's own two secrets and let the fuzzer choose
// everything the proof was in front of. See the probes for what that models and why it is
// the right position to attack from.

// patchesOf spells the patch program the shaped probes read: an offset as a big-endian
// uint16 and the byte to write there, three bytes each. The fuzzer mutates these freely;
// this is for the seeds, which want to NAME a field rather than find it.
func patchesOf(atValue ...int) []byte {
	out := make([]byte, 0, len(atValue)/2*3)
	for i := 0; i+1 < len(atValue); i += 2 {
		out = append(out, byte(atValue[i]>>8), byte(atValue[i]), byte(atValue[i+1]))
	}
	return out
}

// patchRange writes one value across a whole field, for the seeds that want a field to be
// all of something — an all-zero ephemeral, say, which is the x25519 result every peer can
// compute and the one an implementation must refuse.
func patchRange(at, n, value int) []byte {
	out := make([]byte, 0, n*3)
	for i := 0; i < n; i++ {
		out = append(out, patchesOf(at+i, value)...)
	}
	return out
}

// FuzzAkeShapedMsg1 is the handshake's expensive half: a msg1 whose probe OPENS, over an
// ephemeral and a KEM public key the fuzzer chose. Past that door the responder does an
// x25519 with the point it was handed and an ML-KEM encapsulation against 1184 bytes it was
// handed, neither of which any other target reaches — and it does both for a peer that has
// still proved nothing but knowing the contact secret.
func FuzzAkeShapedMsg1(f *testing.F) {
	akeFuzzRealm(f)
	suite, eph := 0, akeSizes.Suite
	kemPk := akeSizes.Suite + akeSizes.Eph
	nonce := kemPk + akeSizes.KemPk
	// Nothing changed: a real msg1, and the anchor the target rests on.
	f.Add([]byte{})
	// Another suite, refused before the probe is even derived.
	f.Add(patchesOf(suite, 0x01))
	// One byte of each field, which is the shape a mutator will mostly produce anyway.
	f.Add(patchesOf(eph, 0))
	f.Add(patchesOf(kemPk, 0xff))
	// The sealed plaintext, which the responder proves and never reads.
	f.Add(patchesOf(nonce, 0xff))
	// The all-zero point and the all-ones one: the x25519 results every peer can compute
	// without knowing anything, and the ones an implementation has to refuse.
	f.Add(patchRange(eph, akeSizes.Eph, 0))
	f.Add(patchRange(eph, akeSizes.Eph, 0xff))
	// A KEM key that is all zeroes, and its last two bytes, where ML-KEM's own encoding
	// checks are.
	f.Add(patchRange(kemPk, akeSizes.KemPk, 0))
	f.Add(patchesOf(nonce-1, 0xff, nonce-2, 0xff))

	f.Fuzz(func(t *testing.T, patch []byte) {
		if len(patch) > 3*4096 {
			t.Skip()
		}
		o := akeRun(t, "__fuzzAkeShapedMsg1", qc.NewArrayBuffer(patch))
		silentUnderFire(t, "shaped msg1", o, patch, nil)
		// The anchor. A msg1 nothing changed is a real one, and the responder owes it a
		// msg2 — without this the target is satisfied by a harness that never gets in the
		// door at all, which is exactly what it exists to get past.
		if o.Patched == 0 && len(o.Wire) != 1 {
			t.Fatalf("shaped msg1: an UNMODIFIED msg1 was answered with %v — the probe is not opening, so nothing below the door is being reached", o.Wire)
		}
		// Everything else owes at most one msg2, at its one width: any second write, or one
		// of another size, is the exchange telling the sender how far its fields got.
		if len(o.Wire) > 1 {
			t.Fatalf("shaped msg1: wrote %d messages (%v) for one msg1 — patched %d byte(s): %x",
				len(o.Wire), o.Wire, o.Patched, head(patch))
		}
		for _, n := range o.Wire {
			if n != akeSizes.M2 {
				t.Fatalf("shaped msg1: answered with a %d-byte message; the only thing owed here is msg2 (%d bytes) — patched %d byte(s): %x",
					n, akeSizes.M2, o.Patched, head(patch))
			}
		}
	})
}

// FuzzAkeShapedIdentity is the identity proof itself. FuzzAkeIdentity can only ever fail the
// AEAD in front of it; this one seals with the key the link will derive, so every execution
// gets through to `openIdentity` and spends itself on the signature — the check the whole
// handshake exists to make.
//
//	side 0 — a responder reading msg3, the initiator's identity
//	side 1 — an initiator reading msg4, the responder's
func FuzzAkeShapedIdentity(f *testing.F) {
	akeFuzzRealm(f)
	pt := akeSizes.M3 - akeSizes.Tag
	f.Add(byte(0), make([]byte, pt))
	f.Add(byte(1), make([]byte, pt))
	f.Add(byte(0), bytes.Repeat([]byte{0xff}, pt))
	// A key that is all zeroes with a signature that is not, and the other way round: the
	// two halves are checked together, and an implementation that read only one would pass
	// one of these.
	f.Add(byte(0), append(make([]byte, 32), bytes.Repeat([]byte{0x01}, pt-32)...))
	f.Add(byte(1), append(bytes.Repeat([]byte{0x01}, 32), make([]byte, pt-32)...))
	// The anchor, and the whole reason this target is worth its executions: a message built
	// the way the probe builds one is a message the link OPENS. The same construction
	// carrying the identity whose turn it is authenticates (TestAkeIdentityProof pins both
	// halves), so an execution that gets nowhere below got as far as the signature check and
	// failed there — which is where a fuzzer should be spending its time.
	if o := akeIdentityCase(f, 3, false); !o.Authed {
		f.Fatal("a correctly sealed, correctly signed identity does not authenticate — this target is not reaching openIdentity at all")
	}

	f.Fuzz(func(t *testing.T, side byte, data []byte) {
		stage, what := 3, "shaped msg3"
		if side&1 == 1 {
			stage, what = 4, "shaped msg4"
		}
		// Always the width the step declares: a wrong length is refused before the message
		// is opened at all, which FuzzAkeIdentity already covers, and spending executions
		// there would waste the door this target went to the trouble of opening.
		pt := make([]byte, akeSizes.M3-akeSizes.Tag)
		copy(pt, data)
		o := akeRun(t, "__fuzzAkeShapedIdentity", qc.NewInt64(int64(stage)), qc.NewArrayBuffer(pt))
		silentUnderFire(t, what, o, data, nil)
		// Neither end answers an identity it could not verify, and neither end is talking to
		// one it could: no byte string is a signature over this transcript.
		if len(o.Wire) != 0 {
			t.Fatalf("%s: wrote %v in answer to an identity that does not verify — %d bytes: %x",
				what, o.Wire, len(data), head(data))
		}
	})
}

// akeIdentityCase drives one identity through a link that will open it: the peer's, or the
// link's own reflected back at it.
func akeIdentityCase(t testing.TB, stage int, reflected bool) akeOutcome {
	t.Helper()
	flag := int64(0)
	if reflected {
		flag = 1
	}
	out, err := callRealm("__akeIdentityCase", 60*time.Second,
		qc.NewInt64(int64(stage)), qc.NewInt64(flag))
	if err != nil {
		t.Fatalf("__akeIdentityCase(%d, %v): the realm itself failed: %v", stage, reflected, err)
	}
	var o akeOutcome
	if err := json.Unmarshal(out, &o); err != nil {
		t.Fatalf("__akeIdentityCase(%d, %v): undecodable answer %q: %v", stage, reflected, out, err)
	}
	if o.Bad != "" {
		t.Fatalf("__akeIdentityCase(%d, %v): the harness handshake broke first: %s", stage, reflected, o.Bad)
	}
	return o
}

// TestAkeIdentityProof pins the last two steps of the handshake at the one place a fuzzer
// cannot reach them. Both inputs need a signature over a transcript that exists only inside
// a link, so neither is a byte string any mutation arrives at, and they are a pair on
// purpose:
//
//	the peer's identity, which must be ACCEPTED — the proof that this construction gets
//	through the AEAD and past the signature check at all, without which the refusal below
//	is satisfied by a message that simply never opened; and
//
//	our own identity reflected back at us, correctly signed, which must be refused. It is
//	the last check in openIdentity and the only one behind a signature that verifies, so
//	nothing else in this file can reach it. Taking it would leave a node authenticated
//	against itself, on a transcript an echo can always produce.
func TestAkeIdentityProof(t *testing.T) {
	akeFuzzRealm(t)
	for _, c := range []struct {
		stage int
		what  string
		wire  int // what this end owes a peer it just proved: msg4, or nothing
	}{
		{3, "msg3 at a responder", akeSizes.M4},
		{4, "msg4 at an initiator", 0},
	} {
		o := akeIdentityCase(t, c.stage, false)
		if !o.Authed {
			t.Fatalf("%s: a genuine identity, signed by the end whose turn it is, did NOT authenticate (stalled=%v closed=%v wrote %v)",
				c.what, o.Stalled, o.Closed, o.Wire)
		}
		want := []int{c.wire}
		if c.wire == 0 {
			want = nil
		}
		if len(o.Wire) != len(want) || (len(want) == 1 && o.Wire[0] != want[0]) {
			t.Fatalf("%s: answered a genuine identity with %v, want %v", c.what, o.Wire, want)
		}

		o = akeIdentityCase(t, c.stage, true)
		if o.Authed || o.NAuth != 0 {
			t.Fatalf("%s: AUTHENTICATED against our OWN identity — a peer that echoes our traffic has proved nothing, and this end would now hold a session with itself",
				c.what)
		}
		if o.Delivered != 0 || len(o.Wire) != 0 {
			t.Fatalf("%s: answered our own reflected identity with %v and %d frame(s) — a refusal here is silence",
				c.what, o.Wire, o.Delivered)
		}
	}
}

// FuzzAkeShapedRecord is the record layer with the AEAD on the right side of the fence: a
// record this session really sealed, corrupted at offsets the fuzzer chose. With nothing
// changed it is the ACCEPT path, which nothing else here exercises — and an accept path
// that works is what makes every refusal below evidence rather than a receiver that says no
// to everything.
func FuzzAkeShapedRecord(f *testing.F) {
	akeFuzzRealm(f)
	// Untouched, at both ends of the size range: the accept path.
	f.Add([]byte("hello"), []byte{})
	f.Add(make([]byte, 1), []byte{})
	f.Add(bytes.Repeat([]byte{7}, 4096), []byte{})
	// The ciphertext's first byte, and a byte inside the tag that follows it.
	f.Add([]byte("hello"), patchesOf(0, 0))
	f.Add([]byte("hello"), patchesOf(20, 0))
	f.Add(bytes.Repeat([]byte{7}, 4096), patchesOf(4095, 1))

	f.Fuzz(func(t *testing.T, body, patch []byte) {
		// `send` refuses an empty frame (it is the end-of-stream marker) and one that would
		// seal past the cap, and either would leave the probe with no record to corrupt.
		if len(body) == 0 || len(body) > akeSizes.Frame-akeSizes.Tag || len(body) > 1<<18 {
			t.Skip()
		}
		if len(patch) > 3*4096 {
			t.Skip()
		}
		o := akeRun(t, "__fuzzAkeShapedRecord", qc.NewArrayBuffer(body), qc.NewArrayBuffer(patch))
		covMarkAke(o)
		if o.Threw != "" {
			t.Fatalf("shaped record: threw out of onWire (%q) — body %d bytes, patched %d",
				o.Threw, len(body), o.Patched)
		}
		if len(o.Wire) != 0 {
			t.Fatalf("shaped record: answered a record with %v — a record is not a message this layer replies to", o.Wire)
		}
		if o.Patched == 0 {
			// Untouched: this end sealed it, so the other end must open it — once, moving the
			// counter once, leaving the link up.
			if o.Delivered != 1 || o.RecvCtr != 1 || o.RecvEpoch != 0 || o.Closed {
				t.Fatalf("shaped record: a record this session sealed was not accepted — delivered=%d recvCtr=%d recvEpoch=%d closed=%v, body %d bytes",
					o.Delivered, o.RecvCtr, o.RecvEpoch, o.Closed, len(body))
			}
			return
		}
		// One changed byte anywhere — nonce arithmetic, ciphertext or tag — and it does not
		// open, the counter does not move, and the link is gone.
		if o.Delivered != 0 || o.NAuth != 0 {
			t.Fatalf("shaped record: a record corrupted in %d byte(s) was ACCEPTED (%d delivered) — body %d bytes: %x",
				o.Patched, o.Delivered, len(body), head(patch))
		}
		if o.RecvCtr != 0 || o.RecvEpoch != 0 {
			t.Fatalf("shaped record: a failed open moved the receive counter to epoch %d ctr %d — patched %d byte(s)",
				o.RecvEpoch, o.RecvCtr, o.Patched)
		}
		if !o.Closed {
			t.Fatalf("shaped record: a record corrupted in %d byte(s) left the link up — a proved peer's stream cannot survive one",
				o.Patched)
		}
	})
}
