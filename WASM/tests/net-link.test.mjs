// net-link.test.mjs — regression tests for the §12.6.1 hardening of PeerLink.
//
// Standalone: it drives build/host/net-link.js over an in-process loopback channel
// pair with a node:crypto-backed TransportCrypto, so it needs neither libsodium nor
// a socket. Run after `npx tsc -p host`:  node tests/net-link.test.mjs
//
// Each test names the property it pins, so a failure says which guarantee broke.

import crypto from "node:crypto";
import {
  PeerLink, HalfOpenLimiter, MAX_HALF_OPEN_UNVERIFIED, MAX_HALF_OPEN_VERIFIED,
} from "../build/host/net-link.js";

// ── a real TransportCrypto over node:crypto ──────────────────────────────────
// Raw keys are wrapped into DER so Node will import them, which keeps the wire
// format identical to libsodium's (32-byte keys, 64-byte signatures, tag-appended
// ChaCha20-Poly1305-IETF records).
const ED_PUB_DER = Buffer.from("302a300506032b6570032100", "hex");
const ED_PRV_DER = Buffer.from("302e020100300506032b657004220420", "hex");
const X_PUB_DER = Buffer.from("302a300506032b656e032100", "hex");
const X_PRV_DER = Buffer.from("302e020100300506032b656e04220420", "hex");

const edPub = (raw) => crypto.createPublicKey({ key: Buffer.concat([ED_PUB_DER, Buffer.from(raw)]), format: "der", type: "spki" });
const edPrv = (raw) => crypto.createPrivateKey({ key: Buffer.concat([ED_PRV_DER, Buffer.from(raw)]), format: "der", type: "pkcs8" });
const xPub = (raw) => crypto.createPublicKey({ key: Buffer.concat([X_PUB_DER, Buffer.from(raw)]), format: "der", type: "spki" });
const xPrv = (raw) => crypto.createPrivateKey({ key: Buffer.concat([X_PRV_DER, Buffer.from(raw)]), format: "der", type: "pkcs8" });

const rawOf = (key, priv) => new Uint8Array(
  priv ? key.export({ format: "der", type: "pkcs8" }).subarray(-32)
       : key.export({ format: "der", type: "spki" }).subarray(-32),
);

const sodium = {
  crypto_sign_detached: (msg, sk) => new Uint8Array(crypto.sign(null, Buffer.from(msg), edPrv(sk))),
  crypto_sign_verify_detached: (sig, msg, pk) => crypto.verify(null, Buffer.from(msg), edPub(pk), Buffer.from(sig)),
  crypto_box_keypair: () => {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
    return { publicKey: rawOf(publicKey, false), privateKey: rawOf(privateKey, true) };
  },
  // Node throws on an all-zero X25519 result, matching libsodium's low-order rejection.
  crypto_scalarmult: (sk, pk) => new Uint8Array(crypto.diffieHellman({ privateKey: xPrv(sk), publicKey: xPub(pk) })),
  crypto_generichash: (len, msg) => new Uint8Array(crypto.createHash("blake2b512").update(Buffer.from(msg)).digest().subarray(0, len)),
  crypto_aead_chacha20poly1305_ietf_encrypt: (msg, _ad, _ns, npub, key) => {
    const c = crypto.createCipheriv("chacha20-poly1305", Buffer.from(key), Buffer.from(npub), { authTagLength: 16 });
    return new Uint8Array(Buffer.concat([c.update(Buffer.from(msg)), c.final(), c.getAuthTag()]));
  },
  crypto_aead_chacha20poly1305_ietf_decrypt: (_ns, ct, _ad, npub, key) => {
    const buf = Buffer.from(ct);
    const d = crypto.createDecipheriv("chacha20-poly1305", Buffer.from(key), Buffer.from(npub), { authTagLength: 16 });
    d.setAuthTag(buf.subarray(buf.length - 16));
    return new Uint8Array(Buffer.concat([d.update(buf.subarray(0, buf.length - 16)), d.final()]));
  },
  // Node's generateKeyPairSync has no seed option for ed25519 — passing one is silently
  // ignored and you get a fresh random key. libsodium's seed_keypair means "this seed IS
  // the private scalar source", which in Node is spelled by wrapping the seed as a PKCS8
  // private key and reading its public half back out.
  crypto_sign_seed_keypair: (seed) => {
    const prv = crypto.createPrivateKey({
      key: Buffer.concat([ED_PRV_DER, Buffer.from(seed)]), format: "der", type: "pkcs8",
    });
    return { publicKey: rawOf(crypto.createPublicKey(prv), false), privateKey: rawOf(prv, true) };
  },
  randombytes_buf: (n) => new Uint8Array(crypto.randomBytes(n)),
};

function identity() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return { publicKey: rawOf(publicKey, false), privateKey: rawOf(privateKey, true) };
}

// ── loopback channels ────────────────────────────────────────────────────────
// Delivery is deferred a microtask so nothing re-enters a constructor, mirroring a
// real socket. `tamper` lets a test corrupt bytes in flight.
function channelPair({ remoteAddrA, remoteAddrB, tamper, destructive } = {}) {
  const mk = (name, addr) => ({
    name, remoteAddr: addr, onMsg: null, onCls: null, dead: false,
    sent: [],
    send(bytes) {
      if (this.dead) return;
      this.sent.push(Buffer.from(bytes).toString("hex"));
      const out = tamper ? tamper(bytes, this.name) : bytes;
      if (out === null) return; // dropped in flight
      const seq = ++this.inFlight;
      queueMicrotask(() => {
        // A destructive close zeroes inFlight; anything still queued never made it.
        if (destructive && seq > this.inFlight) return;
        if (!this.peer.dead) this.peer.onMsg?.(out);
      });
    },
    onMessage(cb) { this.onMsg = cb; },
    onClose(cb) { this.onCls = cb; },
    capRaised: false,
    allowLargeFrames() { this.capRaised = true; },
    // `closeArgs` records what PeerLink asked for; `destructive` models a transport
    // that drops whatever has not reached the wire unless the close was graceful —
    // which is what socket.destroy() does to a just-written end-of-stream record.
    closeArgs: [],
    inFlight: 0,
    close(graceful = false) {
      this.closeArgs.push(graceful);
      if (this.dead) return;
      this.dead = true;
      if (destructive && !graceful) this.inFlight = 0;
      queueMicrotask(() => this.peer.kill());
    },
    // The far end going away: fires onClose, the way BufferedChannel.fail() does.
    kill() { if (this.dead) return; this.dead = true; this.onCls?.(); queueMicrotask(() => this.peer.kill()); },
  });
  const a = mk("A", remoteAddrA), b = mk("B", remoteAddrB);
  a.peer = b; b.peer = a;
  return [a, b];
}

const tick = (n = 12) => new Promise((r) => { let i = 0; const step = () => (++i >= n ? r() : queueMicrotask(step)); step(); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A node's contact secret. Per node in production; one value here is enough, since
 *  every test pairs a dialer holding it with the node that owns it. */
const CONTACT = new Uint8Array(32).fill(7);

function link(channel, id, extra = {}) {
  const state = { authed: false, closed: false, frames: [], link: null };
  const { ...rest } = extra;
  state.link = new PeerLink({
    channel, identity: id, sodium, weDialed: extra.weDialed ?? false,
    contactSecret: extra.contactSecret ?? CONTACT,
    networkKey: extra.networkKey,
    onAuth: () => { state.authed = true; },
    onFrame: (_pid, f) => state.frames.push(Buffer.from(f).toString()),
    onClose: () => { state.closed = true; },
    ...rest,
  });
  return state;
}

/** A dialer/acceptor pair, wired so the dialer knows its peer's static key. */
function pair(chans, extraA = {}, extraB = {}) {
  const idA = identity(), idB = identity();
  const A = link(chans[0], idA, { weDialed: true, ...extraA });
  const B = link(chans[1], idB, extraB);
  return { A, B, idA, idB };
}

// ── harness ──────────────────────────────────────────────────────────────────
let pass = 0, fail = 0;
async function test(name, fn) {
  try { await fn(); console.log(`  OK   ${name}`); pass++; }
  catch (e) { console.log(`  FAIL ${name}\n       ${e.message}`); fail++; }
}
function assert(cond, msg) { if (!cond) throw new Error(msg); }

console.log("\nPeerLink hardening (§12.6.1) + concealed handshake (§12.6.2)\n");

await test("baseline: two ends authenticate and exchange frames", async () => {
  const [ca, cb] = channelPair();
  const A = link(ca, identity(), { weDialed: true }), B = link(cb, identity());
  await tick();
  assert(A.authed && B.authed, "both ends should authenticate");
  A.link.send(Buffer.from("ping")); B.link.send(Buffer.from("pong"));
  await tick();
  assert(B.frames[0] === "ping" && A.frames[0] === "pong", `frames not delivered: ${A.frames}/${B.frames}`);
});

await test("handshake messages are exact-length: a trailing byte is refused", async () => {
  // Trailing bytes would ride outside the transcript hash, and so outside what both
  // signatures cover. Exact, not minimum, for every message in the flight.
  for (const tag of [1, 2]) {
    const [ca, cb] = channelPair({
      tamper: (b, from) => (from === "A" && b[0] === tag ? Buffer.concat([Buffer.from(b), Buffer.from([0])]) : b),
    });
    const { A, B } = pair([ca, cb]);
    await tick();
    // The responder is the end that reads a tampered message from A, so it is the end
    // that must refuse. (For tag 2 the initiator has legitimately authenticated by then:
    // it verified msg2 at 1 RTT, a round trip before the responder authenticates it.)
    assert(!B.authed, `responder must refuse an over-long message with tag ${tag}`);
    if (tag === 1) assert(!A.authed, "a rejected msg1 must leave the initiator unauthenticated");
  }
});

await test("CONCEALMENT: a responder says NOTHING to a caller outside the roster", async () => {
  // The enumeration primitive. A node that speaks first is a directory service: one
  // connect reads its identity straight off the wire. A caller without the contact secret
  // must get silence — not an error, not a close, nothing that distinguishes this node
  // from a port that is not listening.
  const [ca, cb] = channelPair();
  const A = link(ca, identity(), { weDialed: true, contactSecret: new Uint8Array(32).fill(9) });
  const B = link(cb, identity());
  await tick();
  assert(cb.sent.length === 0, `responder emitted ${cb.sent.length} message(s); must emit none`);
  assert(!A.authed && !B.authed, "neither end may authenticate");
  assert(!B.closed, "a refusal must not even close — the deadline does that later");
});

await test("CONCEALMENT: neither identity appears in cleartext on the wire", async () => {
  const [ca, cb] = channelPair();
  const { A, B, idA, idB } = pair([ca, cb]);
  await tick();
  assert(A.authed && B.authed, "handshake must complete");
  A.link.send(Buffer.from("payload"));
  await tick();
  const wire = [...ca.sent, ...cb.sent].join("");
  for (const [name, id] of [["initiator", idA], ["responder", idB]]) {
    assert(!wire.includes(Buffer.from(id.publicKey).toString("hex")),
      `${name} identity key found in cleartext on the wire`);
  }
});

await test("CONCEALMENT: msg1 carries no identity, so a seized static key reveals none", async () => {
  // Why identities are deferred past the ephemeral-ephemeral DH instead of sealed to the
  // responder's static key the way Noise IK does. Anything msg1 carries is readable by
  // whoever holds that static key — including an attacker who seizes the node years
  // later and replays a recording. So msg1 carries no identity at all.
  const [ca, cb] = channelPair();
  const { idA } = pair([ca, cb]);
  await tick(2);
  const msg1 = Buffer.from(ca.sent[0], "hex");
  assert(msg1.length === 1 + 81, `msg1 should be tag+81 bytes, got ${msg1.length}`);
  assert(!msg1.includes(Buffer.from(idA.publicKey)), "msg1 must not carry the initiator identity");
});

await test("CONTACT SECRET: the address book alone does not grant a probe", async () => {
  // The property the contact secret exists for. Every peer holding this node's ADDRESS also
  // holds its static key, so without a contact secret an address book leak is a probe
  // capability: elicit msg2, confirm which identity lives at that host, and keep doing
  // it after being removed from the roster. With one, probing needs a secret no address
  // contains — so an address leak costs the address and nothing more.
  const [ca, cb] = channelPair();
  const idB = identity();
  const A = link(ca, identity(), { weDialed: true, contactSecret: new Uint8Array(32).fill(9) });
  const B = link(cb, idB); // holds the address, but not the contact secret
  await tick();
  assert(cb.sent.length === 0, `outsider drew ${cb.sent.length} message(s); must draw none`);
  assert(!A.authed && !B.authed, "a wrong contact secret must not authenticate");
});

await test("FRAME CAP: raised on authentication, and not before", async () => {
  // Transports reassemble under MAX_HANDSHAKE_FRAME_BYTES until a link authenticates, so
  // a stranger cannot reserve megabytes by declaring a frame and dribbling it. If the
  // raise never fires, every application frame over 512 bytes dies on a real transport
  // and nothing in the handshake tests would notice.
  const [ca, cb] = channelPair();
  const A = link(ca, identity(), { weDialed: true });
  const B = link(cb, identity());
  assert(!ca.capRaised && !cb.capRaised, "the cap must start low on both ends");
  await tick();
  assert(A.authed && B.authed, "handshake must complete");
  assert(ca.capRaised && cb.capRaised, "both ends must raise the cap on authentication");
});

await test("FRAME CAP: the caller raises before it flushes its queue", async () => {
  // Ordering, not just occurrence. Queued pre-auth frames are flushed inside the same
  // becomeAuthed() that raises the cap; if the raise came second, the first application
  // frame of every connection would be measured against the handshake cap.
  const [ca, cb] = channelPair();
  const order = [];
  const rawSend = ca.send.bind(ca);
  ca.allowLargeFrames = function () { order.push("raise"); this.capRaised = true; };
  ca.send = (b) => { if (b[0] === 3) order.push("frame"); rawSend(b); };
  const A = link(ca, identity(), { weDialed: true });
  const B = link(cb, identity());
  A.link.send(Buffer.alloc(2000, 7)); // queued: bigger than the handshake cap
  await tick();
  assert(A.authed && B.authed, "handshake must complete");
  assert(order[0] === "raise", `expected the cap raise first, got ${JSON.stringify(order)}`);
  assert(B.frames.length === 1, `the queued frame should have been delivered, got ${B.frames.length}`);
});

await test("SUBKEYS: one master seed, purpose-bound keys, deterministic", async () => {
  const { deriveNodeKeys } = await import("../build/host/subkeys.js");
  const master = new Uint8Array(32).fill(5);
  const a = deriveNodeKeys(sodium, master), b = deriveNodeKeys(sodium, master);
  const hex = (u) => Buffer.from(u).toString("hex");
  // Deterministic: a node rebuilds every subkey at boot from the one secret it stores.
  assert(hex(a.channel.publicKey) === hex(b.channel.publicKey), "derivation must be deterministic");
  assert(hex(a.guest.publicKey) === hex(b.guest.publicKey), "derivation must be deterministic");
  // Purpose-bound: the channel signing path structurally cannot emit a guest signature
  // or vice versa, whatever happens to the domain prefixes.
  assert(hex(a.channel.publicKey) !== hex(a.guest.publicKey), "purposes must not share a key");
  const other = deriveNodeKeys(sodium, new Uint8Array(32).fill(6));
  assert(hex(a.channel.publicKey) !== hex(other.channel.publicKey), "different masters, different keys");
  // The master itself is never a signing key — only a derivation input.
  assert(hex(a.channel.privateKey) !== hex(master), "the master seed must not be used as a key");
});

await test("NETWORK KEY: two networks are structurally unable to reach each other", async () => {
  // The isolation boundary. A staging fleet and a production one can share addresses,
  // configs and operators and still never cross: the network key seeds the transcript,
  // so every derived key and every signature preimage differs and the handshake dies at
  // the first message. Not access control — a boundary.
  const [ca, cb] = channelPair();
  const A = link(ca, identity(), { weDialed: true, networkKey: new Uint8Array(32).fill(1) });
  const B = link(cb, identity(), { networkKey: new Uint8Array(32).fill(2) });
  await tick();
  assert(!A.authed && !B.authed, "nodes on different networks must never link");
  assert(cb.sent.length === 0, `the wrong network drew ${cb.sent.length} message(s)`);

  // Same key on both sides, everything else equal: fine.
  const [cc, cd] = channelPair();
  const net = new Uint8Array(32).fill(1);
  const C = link(cc, identity(), { weDialed: true, networkKey: net });
  const D = link(cd, identity(), { networkKey: net });
  await tick();
  assert(C.authed && D.authed, "one network must still link normally");
});

await test("CONTACT SECRET: absent means OPEN — the node still conceals identities", async () => {
  // An open node answers anyone, which is a DoS and caller-privacy posture, NOT an
  // identity leak. The four-message ordering does the concealing, so even wide open
  // neither public key crosses the wire.
  const [ca, cb] = channelPair();
  const idA = identity(), idB = identity();
  const A = link(ca, idA, { weDialed: true, contactSecret: undefined });
  const B = link(cb, idB, { contactSecret: undefined });
  await tick();
  assert(A.authed && B.authed, "an open node must still complete a handshake");
  const wire = [...ca.sent, ...cb.sent].join("");
  for (const [name, id] of [["caller", idA], ["receiver", idB]]) {
    assert(!wire.includes(Buffer.from(id.publicKey).toString("hex")),
      `${name} identity in cleartext on an open node`);
  }
});

await test("CONTACT SECRET: it is the RECEIVER's, and only the receiver's", async () => {
  // Per node, not per deployment and not per pair. A caller must present the secret of
  // the node it is dialing; holding some other node's is worth nothing. This is what
  // bounds a leak to one node's inbound side instead of the whole network.
  const secretB = new Uint8Array(32).fill(11);
  const secretC = new Uint8Array(32).fill(22);
  const [ca, cb] = channelPair();
  const A = link(ca, identity(), { weDialed: true, contactSecret: secretB });
  const B = link(cb, identity(), { contactSecret: secretB });
  await tick();
  assert(A.authed && B.authed, "the right secret must open the door");

  const [cc, cd] = channelPair();
  const C = link(cc, identity(), { weDialed: true, contactSecret: secretC });
  const D = link(cd, identity(), { contactSecret: secretB });
  await tick();
  assert(cd.sent.length === 0, `another node's secret drew ${cd.sent.length} message(s)`);
  assert(!C.authed && !D.authed, "another node's secret must not authenticate");
});

await test("CONTACT SECRET: it never appears on the wire", async () => {
  // It is mixed into the key schedule, never transmitted — which is also what makes it
  // a quantum hedge: an adversary who records today and breaks X25519 later still needs
  // a value that was never sent.
  const [ca, cb] = channelPair();
  const { A, B } = pair([ca, cb]);
  await tick();
  assert(A.authed && B.authed, "handshake must complete");
  const wire = [...ca.sent, ...cb.sent].join("");
  assert(!wire.includes(Buffer.from(CONTACT).toString("hex")), "contact secret leaked onto the wire");
});

await test("LEAK FIX: a self-closing link still fires onClose", async () => {
  // The reflection guard closes the link from inside onHello. Before the fix,
  // ch.close() set `dead` without firing onCls, so onClose never ran and the
  // transport kept the link in its pre-auth bookkeeping forever.
  const id = identity();
  const [ca, cb] = channelPair();
  const A = link(ca, id, { weDialed: true });
  const B = link(cb, id); // same identity → B sees its own key in A's msg3
  await tick();
  assert(!A.authed && !B.authed, "a node must not link to itself");
  A.link.close(); await tick();
  assert(A.closed, "close MUST reach onClose (this is the leak)");
});

await test("LEAK FIX: an explicit close() fires onClose exactly once", async () => {
  const [ca, cb] = channelPair();
  let n = 0;
  const idB = identity();
  const A = new PeerLink({
    channel: ca, identity: identity(), sodium, weDialed: true, contactSecret: CONTACT,
    onAuth: () => {}, onFrame: () => {}, onClose: () => { n++; },
  });
  link(cb, identity());
  await tick();
  A.close(); A.close(); await tick();
  assert(n === 1, `onClose fired ${n} times, want exactly 1`);
});

await test("handshake deadline closes a link that never speaks", async () => {
  const [ca] = channelPair(); // no peer link constructed: nothing ever replies
  const A = link(ca, identity(), { weDialed: true, handshakeTimeoutMs: 40 });
  await sleep(120);
  assert(!A.authed, "must not authenticate");
  assert(A.closed, "must close on the deadline and notify");
});

await test("rekey: the ratchet keeps frames flowing across an epoch boundary", async () => {
  const [ca, cb] = channelPair();
  const opt = { rekeyAfterFrames: 4 };
  const idB = identity();
  const A = link(ca, identity(), { weDialed: true, ...opt }), B = link(cb, idB, opt);
  await tick();
  assert(A.authed && B.authed, "handshake must complete");
  for (let i = 0; i < 14; i++) { A.link.send(Buffer.from(`f${i}`)); await tick(4); }
  assert(B.frames.length === 14, `want 14 frames across 3 ratchets, got ${B.frames.length}`);
  assert(B.frames[13] === "f13", `ordering broken: ${B.frames[13]}`);
  assert(!A.closed && !B.closed, "link must survive rekeying");
});

await test("rekey: mismatched intervals desync (the must-match warning is real)", async () => {
  const [ca, cb] = channelPair();
  const idB = identity();
  const A = link(ca, identity(), { weDialed: true, rekeyAfterFrames: 4 });
  const B = link(cb, idB, { rekeyAfterFrames: 8 });
  await tick();
  for (let i = 0; i < 8; i++) { A.link.send(Buffer.from(`f${i}`)); await tick(4); }
  assert(B.frames.length === 4, `want 4 frames before the boundary, got ${B.frames.length}`);
  assert(B.closed, "a desync must tear the link down, not silently corrupt");
});

await test("goodbye: a clean close is distinguishable from a truncation", async () => {
  const [ca, cb] = channelPair();
  const A = link(ca, identity(), { weDialed: true }), B = link(cb, identity());
  await tick();
  A.link.close();
  await tick();
  assert(B.link.peerSaidGoodbye, "B must see the authenticated end-of-stream");
  assert(!B.link.wasTruncated(), "a clean close is not a truncation");
});

await test("goodbye: a cut connection reads as truncated", async () => {
  const [ca, cb] = channelPair();
  const A = link(ca, identity(), { weDialed: true }), B = link(cb, identity());
  await tick();
  ca.kill(); // the socket dies with no goodbye
  await tick();
  assert(!B.link.peerSaidGoodbye, "no goodbye was sent");
  assert(B.link.wasTruncated(), "B must report a truncation");
});

await test("goodbye is not delivered to the application as a frame", async () => {
  const [ca, cb] = channelPair();
  const A = link(ca, identity(), { weDialed: true }), B = link(cb, identity());
  await tick();
  A.link.send(Buffer.from("real")); await tick();
  A.link.close(); await tick();
  assert(B.frames.length === 1 && B.frames[0] === "real", `goodbye leaked into onFrame: ${JSON.stringify(B.frames)}`);
});

await test("goodbye: the CLOSER reports a local shutdown, not a truncation", async () => {
  // The regression this pins: wasTruncated() used to be `authed && !peerSaidGoodbye`,
  // which is true on our own side of every deliberate close — we send the farewell and
  // do not get one back. The double-connect tie-break closes a link on any parallel
  // dial, so that flagged a routine event as a cut stream.
  const [ca, cb] = channelPair();
  const A = link(ca, identity(), { weDialed: true }), B = link(cb, identity());
  await tick();
  A.link.close();
  await tick();
  assert(A.link.closeReason === "local", `closer should read local, got ${A.link.closeReason}`);
  assert(!A.link.wasTruncated(), "a shutdown we initiated is not a truncation");
  assert(B.link.closeReason === "clean", `peer should read clean, got ${B.link.closeReason}`);
});

await test("goodbye: an injected junk record must NOT produce a farewell", async () => {
  // The attack the close/abort split exists to stop. An in-path attacker corrupts one
  // record A->B. B cannot decrypt it and tears the link down — but if that teardown
  // emitted an end-of-stream record, B would hand A a genuine, correctly-keyed
  // farewell, and A would read an attacker-chosen moment as a clean shutdown. The
  // attacker never forges anything; they induce the victim to say goodbye.
  let corrupted = false;
  const [ca, cb] = channelPair({
    tamper: (bytes, from) => {
      if (from !== "A" || corrupted || bytes[0] !== 3) return bytes; // FRAME only
      corrupted = true;
      const out = Uint8Array.from(bytes);
      out[out.length - 1] ^= 0xff; // break the Poly1305 tag
      return out;
    },
  });
  const A = link(ca, identity(), { weDialed: true }), B = link(cb, identity());
  await tick();
  assert(A.authed && B.authed, "both ends should authenticate first");
  A.link.send(Buffer.from("payload"));
  await tick();
  assert(corrupted, "the test did not actually corrupt a record");
  assert(B.link.closeReason === "aborted", `victim should read aborted, got ${B.link.closeReason}`);
  assert(!A.link.peerSaidGoodbye, "the victim must not emit a farewell on a failure path");
  assert(A.link.closeReason === "truncated", `far end should read truncated, got ${A.link.closeReason}`);
});

await test("a graceful close asks the transport to flush; an abort does not", async () => {
  const [ca, cb] = channelPair();
  const A = link(ca, identity(), { weDialed: true }), B = link(cb, identity());
  await tick();
  A.link.close();
  await tick();
  assert(ca.closeArgs[0] === true, `close() after a farewell must request a flush, got ${ca.closeArgs[0]}`);

  const [cc, cd] = channelPair();
  const C = link(cc, identity(), { weDialed: true }), D = link(cd, identity());
  await tick();
  C.link.abort();
  await tick();
  assert(cc.closeArgs[0] === false, `abort() must not request a flush, got ${cc.closeArgs[0]}`);
  assert(D.link.closeReason === "truncated", `an abort must read as a cut, got ${D.link.closeReason}`);
});

await test("the farewell survives a transport that discards unflushed writes", async () => {
  // A TCP socket destroyed rather than ended drops the record it was just handed, so
  // the whole mechanism silently no-ops on the transport most likely to carry it. This
  // fails unless close() both writes the record AND asks for a graceful teardown.
  const [ca, cb] = channelPair({ destructive: true });
  const A = link(ca, identity(), { weDialed: true }), B = link(cb, identity());
  await tick();
  A.link.send(Buffer.from("last"));
  A.link.close();
  await tick();
  assert(B.frames[0] === "last", `the final frame was lost: ${JSON.stringify(B.frames)}`);
  assert(B.link.peerSaidGoodbye, "the farewell was discarded by the transport");
  assert(B.link.closeReason === "clean", `expected clean, got ${B.link.closeReason}`);
});

await test("limiter: a full budget EVICTS THE OLDEST rather than refusing the newest", async () => {
  // The policy the load test forced. Refusing the newest turns the budget into the
  // attacker's weapon: saturate it once and every member arriving afterwards is turned
  // away at the door, before it can send the message that would prove it belongs.
  // Evicting the oldest inverts that — a member displaces the stalest stranger, proves
  // itself in one round trip, and leaves the budget again.
  const limiter = new HalfOpenLimiter(2, 8);
  const made = [];
  for (let i = 0; i < 4; i++) {
    const [ca] = channelPair();
    made.push(link(ca, identity(), { limiter }));
  }
  await tick();
  assert(limiter.outstanding === 2, `want 2 slots held, got ${limiter.outstanding}`);
  assert(made[0].closed && made[1].closed, "the OLDEST unproven links must be evicted");
  assert(!made[2].closed && !made[3].closed, "the newest arrivals must get in");
});

await test("limiter: the per-source cap refuses outright, and costs no key material", async () => {
  // Per-source is deliberately NOT evictable: one address at its own limit must be
  // refused, never allowed to push a different address out. And a refusal must stay
  // cheap — no keypair, which is the whole reason the slot is taken before any crypto.
  let keygens = 0;
  const counting = { ...sodium, crypto_box_keypair: () => { keygens++; return sodium.crypto_box_keypair(); } };
  const limiter = new HalfOpenLimiter(64, 2);
  const made = [];
  for (let i = 0; i < 4; i++) {
    const [ca] = channelPair({ remoteAddrA: "10.0.0.1" });
    made.push(new PeerLink({
      channel: ca, identity: identity(), sodium: counting, weDialed: false,
      contactSecret: CONTACT, limiter,
      onAuth: () => {}, onFrame: () => {}, onClose: () => { made[i].closed = true; },
    }));
    made[i].closed = made[i].closed ?? false;
  }
  await tick();
  assert(limiter.outstanding === 2, `per-source cap leaked: ${limiter.outstanding} held, want 2`);
  assert(keygens === 0, `an accepting link generated ${keygens} keypairs before proof, want 0`);
});

await test("limiter: per-source cap buckets by remoteAddr", async () => {
  const limiter = new HalfOpenLimiter(100, 2);
  const mk = (addr) => { const [ca] = channelPair({ remoteAddrA: addr }); return link(ca, identity(), { limiter }); };
  const noisy = [mk("10.0.0.1"), mk("10.0.0.1"), mk("10.0.0.1")];
  const quiet = mk("10.0.0.2");
  await tick();
  assert(noisy[2].closed, "third link from one source must be refused");
  assert(!quiet.closed, "a different source must be unaffected");
});

await test("limiter: the slot is released on authentication", async () => {
  const limiter = new HalfOpenLimiter(2, 8);
  const [ca, cb] = channelPair();
  const idB = identity();
  const A = link(ca, identity(), { weDialed: true, limiter }), B = link(cb, idB, { limiter });
  await tick();
  assert(A.authed && B.authed, "handshake must complete");
  assert(limiter.outstanding === 0, `slots must be freed on auth, ${limiter.outstanding} held`);
});

await test("limiter: the slot is released when a half-open link dies", async () => {
  const limiter = new HalfOpenLimiter(2, 8);
  const [ca] = channelPair();
  const A = link(ca, identity(), { limiter });
  await tick();
  assert(limiter.outstanding === 1, "slot held while half-open");
  A.link.close(); await tick();
  assert(limiter.outstanding === 0, `slot must be freed on close, ${limiter.outstanding} held`);
});

await test("WHITELIST: absent by default, and an absent hook admits everyone", async () => {
  // The hook is a seam, not a requirement: a deployment that sets nothing gets a network
  // that links to anyone who holds the contact secret, which is the sane default.
  const [ca, cb] = channelPair();
  const { A, B } = pair([ca, cb]);
  await tick();
  assert(A.authed && B.authed, "no whitelist configured must mean admit-all");
});

await test("GUARD: a refused caller learns NOTHING about the receiver", async () => {
  // What the second round trip bought. The caller names itself at msg3, before the
  // receiver has said anything about itself, so a caller off the whitelist is turned
  // away without learning whether the identity it dialed is even here. Under the old
  // 1-RTT ordering the receiver signed and sent its identity at msg2 — before it knew
  // who was calling — so any roster member could confirm who lived at any address.
  const idB = identity();
  const run = async (extraB) => {
    const [ca, cb] = channelPair();
    const A = link(ca, identity(), { weDialed: true });
    const B = link(cb, idB, extraB);
    await tick(20);
    return { sent: cb.sent, A, B };
  };
  const good = await run({});
  const refused = await run({ admitPeer: () => false });

  assert(good.A.authed && good.B.authed, "an admitted caller must authenticate");
  assert(!refused.A.authed && !refused.B.authed, "a refused caller must not authenticate");
  // One message back (msg2, an ephemeral and a roster proof), then silence. The
  // receiver's identity and signature never went out.
  assert(refused.sent.length === 1, `refused caller drew ${refused.sent.length} messages, want 1`);
  assert(!refused.sent.join("").includes(Buffer.from(idB.publicKey).toString("hex")),
    "the receiver revealed its identity to a caller it then refused");
  assert(!refused.B.closed, "a refusal must be silent, not a visible teardown");
});

await test("a decrypt failure does not advance the receive counter", async () => {
  // Flip a byte in the first post-auth record. The link must die rather than
  // desync — the flynn/noise bug this layer already avoided, pinned so it stays that way.
  let flipped = false;
  const [ca, cb] = channelPair({
    tamper: (b, from) => {
      if (from === "A" && b[0] === 3 && !flipped) { flipped = true; const c = Buffer.from(b); c[c.length - 1] ^= 1; return c; }
      return b;
    },
  });
  const A = link(ca, identity(), { weDialed: true }), B = link(cb, identity());
  await tick();
  A.link.send(Buffer.from("tampered")); await tick();
  assert(B.frames.length === 0, "a forged record must not be delivered");
  assert(B.closed, "a forged record must close the link");
});

await test("default caps are sane", () => {
  assert(MAX_HALF_OPEN_UNVERIFIED > 0 && MAX_HALF_OPEN_UNVERIFIED <= 8192, "unverified cap should be a real bound");
  assert(MAX_HALF_OPEN_VERIFIED > 0 && MAX_HALF_OPEN_VERIFIED <= 4096, "verified cap should be a real bound");
  const l = new HalfOpenLimiter();
  assert(l.outstanding === 0 && l.unverified === 0 && l.verified === 0, "a fresh limiter holds nothing");
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
