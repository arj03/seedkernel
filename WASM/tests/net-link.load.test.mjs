// Load behaviour of the half-open budgets (§12.6.2 §6.5, §11.4).
//
// The concealed handshake refuses strangers by SILENCE — a caller that cannot produce a
// msg1 opening under the contact secret is not closed on, it is simply left to time out — so
// a connection that would once have been dropped on sight now occupies a socket for as
// long as the deadline allows. That is deliberate (an immediate close is an oracle:
// "I am a seedkernel node and that is not the key"), but it means the budgets stop being
// defence in depth and become the thing standing between a stranger and the node.
//
// This file is the measurement that was owed. Three questions:
//
//   1. What does an unproven connection actually COST us?
//   2. Can a flood from outside the contact secret stop members from getting in?
//   3. Do the budgets and deadlines behave as the constants claim?
//
// It runs entirely over in-memory channels, so the numbers are about cryptographic and
// allocation cost per connection, not about kernel socket limits. Deliberately: the
// socket ceiling is an operator's `ulimit` question, while what the protocol controls is
// how much work a stranger can buy from us per connection.

import crypto from "node:crypto";
import {
  PeerLink, HalfOpenLimiter,
  MAX_HALF_OPEN_UNVERIFIED, MAX_HALF_OPEN_VERIFIED, MAX_HALF_OPEN_PER_SOURCE,
  UNVERIFIED_TIMEOUT_MS, HANDSHAKE_TIMEOUT_MS,
} from "../build/host/net-link.js";

// ── crypto shim (same construction as net-link.test.mjs) ─────────────────────
const ED_PUB_DER = Buffer.from("302a300506032b6570032100", "hex");
const ED_PRV_DER = Buffer.from("302e020100300506032b657004220420", "hex");
const X_PUB_DER = Buffer.from("302a300506032b656e032100", "hex");
const X_PRV_DER = Buffer.from("302e020100300506032b656e04220420", "hex");
const edPub = (r) => crypto.createPublicKey({ key: Buffer.concat([ED_PUB_DER, Buffer.from(r)]), format: "der", type: "spki" });
const edPrv = (r) => crypto.createPrivateKey({ key: Buffer.concat([ED_PRV_DER, Buffer.from(r)]), format: "der", type: "pkcs8" });
const xPub = (r) => crypto.createPublicKey({ key: Buffer.concat([X_PUB_DER, Buffer.from(r)]), format: "der", type: "spki" });
const xPrv = (r) => crypto.createPrivateKey({ key: Buffer.concat([X_PRV_DER, Buffer.from(r)]), format: "der", type: "pkcs8" });
const rawOf = (k, priv) => new Uint8Array(
  priv ? k.export({ format: "der", type: "pkcs8" }).subarray(-32)
       : k.export({ format: "der", type: "spki" }).subarray(-32),
);

// Every asymmetric operation is counted. These counters are the whole point of the
// file: they turn "is a stranger expensive?" into a number.
const ops = { keygen: 0, scalarmult: 0, sign: 0, verify: 0, aead: 0 };
const resetOps = () => { for (const k of Object.keys(ops)) ops[k] = 0; };

const sodium = {
  crypto_sign_detached: (m, sk) => { ops.sign++; return new Uint8Array(crypto.sign(null, Buffer.from(m), edPrv(sk))); },
  crypto_sign_verify_detached: (sig, m, pk) => { ops.verify++; return crypto.verify(null, Buffer.from(m), edPub(pk), Buffer.from(sig)); },
  crypto_box_keypair: () => {
    ops.keygen++;
    const { publicKey, privateKey } = crypto.generateKeyPairSync("x25519");
    return { publicKey: rawOf(publicKey, false), privateKey: rawOf(privateKey, true) };
  },
  crypto_scalarmult: (sk, pk) => { ops.scalarmult++; return new Uint8Array(crypto.diffieHellman({ privateKey: xPrv(sk), publicKey: xPub(pk) })); },
  crypto_generichash: (len, m) => new Uint8Array(crypto.createHash("blake2b512").update(Buffer.from(m)).digest().subarray(0, len)),
  crypto_aead_chacha20poly1305_ietf_encrypt: (m, _ad, _ns, npub, key) => {
    ops.aead++;
    const c = crypto.createCipheriv("chacha20-poly1305", Buffer.from(key), Buffer.from(npub), { authTagLength: 16 });
    return new Uint8Array(Buffer.concat([c.update(Buffer.from(m)), c.final(), c.getAuthTag()]));
  },
  crypto_aead_chacha20poly1305_ietf_decrypt: (_ns, ct, _ad, npub, key) => {
    ops.aead++;
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

const identity = () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  return { publicKey: rawOf(publicKey, false), privateKey: rawOf(privateKey, true) };
};

const CONTACT = new Uint8Array(32).fill(3);
const OUTSIDER = new Uint8Array(32).fill(9);

// ── channels ─────────────────────────────────────────────────────────────────
function channelPair(addrA, addrB, opts = {}) {
  // `stallAfter` drops everything a side sends past the Nth message — how an attacker
  // that produces a valid msg1 and then goes quiet is modelled.
  const mk = (addr, name) => ({
    remoteAddr: addr, onMsg: null, onCls: null, dead: false, sent: 0,
    send(b) {
      if (this.dead) return;
      this.sent++;
      if (name === "a" && opts.stallAfter !== undefined && this.sent > opts.stallAfter) return;
      queueMicrotask(() => { if (!this.peer.dead) this.peer.onMsg?.(b); });
    },
    onMessage(cb) { this.onMsg = cb; },
    onClose(cb) { this.onCls = cb; },
    close() { if (this.dead) return; this.dead = true; queueMicrotask(() => this.peer.kill()); },
    kill() { if (this.dead) return; this.dead = true; this.onCls?.(); },
  });
  const a = mk(addrA, "a"), b = mk(addrB, "b");
  a.peer = b; b.peer = a;
  return [a, b];
}

/** A connection that opens a socket and then says nothing at all — the cheapest
 *  possible flood, and the one the deadline exists for. */
function silentChannel(addr) {
  return {
    remoteAddr: addr, onMsg: null, onCls: null, dead: false, sent: 0,
    send() { this.sent++; }, onMessage(cb) { this.onMsg = cb; }, onClose(cb) { this.onCls = cb; },
    close() { this.dead = true; }, kill() { if (!this.dead) { this.dead = true; this.onCls?.(); } },
  };
}

const tick = (n = 6) => new Promise((r) => { let i = 0; const s = () => (++i >= n ? r() : queueMicrotask(s)); queueMicrotask(s); });
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

let pass = 0, fail = 0;
const notes = [];
function assert(c, m) { if (!c) throw new Error(m); }
async function test(name, fn) {
  try { await fn(); pass++; console.log(`  OK   ${name}`); }
  catch (e) { fail++; console.log(`  FAIL ${name}\n       ${e.message}`); }
}
const note = (s) => { notes.push(s); console.log(`       · ${s}`); };

console.log("\nPeerLink load behaviour (§12.6.2 §6.5)\n");

// ─────────────────────────────────────────────────────────────────────────────
await test("a silent stranger costs NO asymmetric crypto", async () => {
  // The regression that matters most. The accepting side used to generate an X25519
  // keypair in its constructor, so every inbound TCP connection bought a keygen from us
  // before the peer had proved anything — the cheapest flood there is. Key material is
  // now deferred until a msg1 opens.
  const N = 2000;
  resetOps();
  const limiter = new HalfOpenLimiter(N + 1, N + 1);
  const id = identity();
  const t0 = process.hrtime.bigint();
  const links = [];
  for (let i = 0; i < N; i++) {
    const ch = silentChannel(`10.0.${(i >> 8) & 255}.${i & 255}`);
    links.push(new PeerLink({
      channel: ch, identity: id, sodium, weDialed: false, contactSecret: CONTACT, limiter,
      handshakeTimeoutMs: 60_000, onAuth: () => {}, onFrame: () => {}, onClose: () => {},
    }));
  }
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  note(`${N} silent connections accepted in ${ms.toFixed(0)}ms (${(ms * 1000 / N).toFixed(1)}µs each)`);
  note(`asymmetric ops charged: keygen=${ops.keygen} scalarmult=${ops.scalarmult} sign=${ops.sign} verify=${ops.verify}`);
  assert(ops.keygen === 0, `a silent stranger cost ${ops.keygen} keypairs, want 0`);
  assert(ops.scalarmult === 0, `a silent stranger cost ${ops.scalarmult} scalarmults, want 0`);
  assert(ops.sign === 0 && ops.verify === 0, "a silent stranger must cost no signature work");
  assert(limiter.unverified === N, `expected ${N} unverified slots held, got ${limiter.unverified}`);
  assert(limiter.verified === 0, "nothing may reach the verified budget unproven");
});

await test("a stranger who TRIES costs one AEAD open and nothing more", async () => {
  // A flood that bothers to send plausible bytes should not cost meaningfully more than
  // one that sends none. Verification of msg1 is a hash and a Poly1305 check; everything
  // expensive is behind it.
  const N = 500;
  const id = identity();
  const limiter = new HalfOpenLimiter(N + 1, N + 1);
  const links = [];
  for (let i = 0; i < N; i++) {
    const ch = silentChannel(`10.1.${(i >> 8) & 255}.${i & 255}`);
    links.push(new PeerLink({
      channel: ch, identity: id, sodium, weDialed: false, contactSecret: CONTACT, limiter,
      handshakeTimeoutMs: 60_000, onAuth: () => {}, onFrame: () => {}, onClose: () => {},
    }));
    ch.onMsg(Buffer.concat([Buffer.from([1]), crypto.randomBytes(81)])); // garbage msg1
  }
  resetOps();
  for (let i = 0; i < N; i++) links[i]; // links already fed above
  note(`${N} garbage msg1 rejected; keygen=${ops.keygen} scalarmult=${ops.scalarmult}`);
  assert(limiter.verified === 0, "garbage must not promote to the verified budget");
  assert(limiter.unverified === N, "a rejected caller keeps its unverified slot until the deadline");
});

await test("an outside flood CANNOT keep members out", async () => {
  // The property the whole budget design exists for. Separating the tiers was not
  // enough on its own: a saturating flood refused the member AT THE DOOR, before it
  // could send the one message that would have promoted it. Eviction fixes the order —
  // a new arrival displaces the stalest stranger, proves itself in one round trip, and
  // leaves the contended budget.
  const UNVER = 64;
  const limiter = new HalfOpenLimiter(UNVER, UNVER, 8);
  const server = identity();

  const evicted = [];
  for (let i = 0; i < UNVER; i++) {
    new PeerLink({
      channel: silentChannel(`10.2.${i}.1`), identity: server, sodium, weDialed: false,
      contactSecret: CONTACT, limiter, handshakeTimeoutMs: 60_000,
      onAuth: () => {}, onFrame: () => {}, onClose: () => evicted.push(i),
    });
  }
  assert(limiter.unverified === UNVER, "the unverified budget should be saturated");

  const [ca, cb] = channelPair("10.9.9.9", "10.9.9.9");
  let memberAuthed = false;
  new PeerLink({
    channel: cb, identity: server, sodium, weDialed: false, contactSecret: CONTACT, limiter,
    handshakeTimeoutMs: 60_000, onAuth: () => { memberAuthed = true; }, onFrame: () => {}, onClose: () => {},
  });
  new PeerLink({
    channel: ca, identity: identity(), sodium, weDialed: true, contactSecret: CONTACT,
    handshakeTimeoutMs: 60_000, onAuth: () => {}, onFrame: () => {}, onClose: () => {},
  });
  await tick(20);
  note(`under a saturating flood: member authenticated = ${memberAuthed}; ` +
       `${evicted.length} stranger(s) evicted; unverified=${limiter.unverified} verified=${limiter.verified}`);
  assert(memberAuthed, "A MEMBER WAS DENIED SERVICE BY AN OUTSIDE FLOOD — the budgets are not separated");
  assert(evicted.length === 1, `expected exactly 1 eviction, got ${evicted.length}`);
  assert(evicted[0] === 0, `eviction must take the OLDEST stranger, took #${evicted[0]}`);
  // The member took a slot, promoted out of it, and finished — so it leaves nothing
  // behind. The one evicted stranger does not come back, which is the cost the flood
  // pays for each member that arrives: one of its own connections, not one of ours.
  assert(limiter.verified === 0, "a completed handshake must leave the verified budget clean");
  assert(limiter.unverified === UNVER - 1,
    `expected ${UNVER - 1} strangers left (one evicted), got ${limiter.unverified}`);
});

await test("members keep getting in under a SUSTAINED flood", async () => {
  // Not one member against a static flood, but many arriving while the attacker keeps
  // pushing. Every one must complete.
  const UNVER = 32;
  const limiter = new HalfOpenLimiter(UNVER, UNVER, 16);
  const server = identity();
  const flood = () => new PeerLink({
    channel: silentChannel(`10.5.${Math.floor(Math.random() * 250)}.1`), identity: server,
    sodium, weDialed: false, contactSecret: CONTACT, limiter, handshakeTimeoutMs: 60_000,
    onAuth: () => {}, onFrame: () => {}, onClose: () => {},
  });
  for (let i = 0; i < UNVER; i++) flood();

  let authed = 0;
  const ROUNDS = 25;
  for (let i = 0; i < ROUNDS; i++) {
    for (let j = 0; j < 4; j++) flood(); // attacker keeps pushing
    const [ca, cb] = channelPair(`10.8.${i}.1`, `10.8.${i}.1`);
    new PeerLink({
      channel: cb, identity: server, sodium, weDialed: false, contactSecret: CONTACT, limiter,
      handshakeTimeoutMs: 60_000, onAuth: () => { authed++; }, onFrame: () => {}, onClose: () => {},
    });
    new PeerLink({
      channel: ca, identity: identity(), sodium, weDialed: true, contactSecret: CONTACT,
      handshakeTimeoutMs: 60_000, onAuth: () => {}, onFrame: () => {}, onClose: () => {},
    });
    await tick(12);
  }
  note(`${authed}/${ROUNDS} members authenticated while ${ROUNDS * 4 + UNVER} flood connections churned`);
  assert(authed === ROUNDS, `${ROUNDS - authed} member(s) denied service under sustained flood`);
});

await test("a leaked contact secret cannot lock members out of the verified budget", async () => {
  // The same failure the unverified budget had, one tier up. If the address leaks, an
  // attacker can produce a valid msg1, promote, then stall — and if promote() merely
  // REFUSED when full, a few hundred of those would shut every real member out of the
  // handshake. The verified tier evicts too.
  const VER = 8;
  const limiter = new HalfOpenLimiter(1024, 1024, VER);
  const server = identity();

  // Attacker holds the secret: each connection reaches msg1 and promotes.
  const attack = () => {
    // Sends msg1 (which promotes the responder) and nothing after it.
    const [ca, cb] = channelPair("10.6.6.6", "10.6.6.6", { stallAfter: 1 });
    new PeerLink({
      channel: cb, identity: server, sodium, weDialed: false, contactSecret: CONTACT,
      limiter, handshakeTimeoutMs: 60_000, onAuth: () => {}, onFrame: () => {}, onClose: () => {},
    });
    // A dialer that sends msg1 and then goes silent — never msg3.
    new PeerLink({
      channel: ca, identity: identity(), sodium, weDialed: true, contactSecret: CONTACT,
      handshakeTimeoutMs: 60_000, onAuth: () => {}, onFrame: () => {}, onClose: () => {},
    });
  };
  for (let i = 0; i < VER * 3; i++) attack();
  await tick(20);
  note(`verified budget under a credentialled flood: ${limiter.verified}/${VER}`);
  assert(limiter.verified <= VER, `verified budget overflowed: ${limiter.verified}`);

  // A real member must still complete.
  const [ca, cb] = channelPair("10.7.7.7", "10.7.7.7");
  let authed = false;
  new PeerLink({
    channel: cb, identity: server, sodium, weDialed: false, contactSecret: CONTACT, limiter,
    handshakeTimeoutMs: 60_000, onAuth: () => { authed = true; }, onFrame: () => {}, onClose: () => {},
  });
  new PeerLink({
    channel: ca, identity: identity(), sodium, weDialed: true, contactSecret: CONTACT,
    handshakeTimeoutMs: 60_000, onAuth: () => {}, onFrame: () => {}, onClose: () => {},
  });
  await tick(20);
  assert(authed, "A MEMBER WAS LOCKED OUT by a saturated verified budget");
});

await test("the per-source cap still bites under flood", async () => {
  const limiter = new HalfOpenLimiter(1024, MAX_HALF_OPEN_PER_SOURCE);
  const id = identity();
  const closed = [];
  for (let i = 0; i < MAX_HALF_OPEN_PER_SOURCE + 5; i++) {
    new PeerLink({
      channel: silentChannel("10.3.3.3"), identity: id, sodium, weDialed: false,
      contactSecret: CONTACT, limiter, handshakeTimeoutMs: 60_000,
      onAuth: () => {}, onFrame: () => {}, onClose: () => closed.push(i),
    });
  }
  await tick(4);
  note(`one source opened ${MAX_HALF_OPEN_PER_SOURCE + 5}; ${closed.length} refused, ` +
       `${limiter.unverified} held`);
  assert(limiter.unverified === MAX_HALF_OPEN_PER_SOURCE,
    `per-source cap leaked: ${limiter.unverified} held, want ${MAX_HALF_OPEN_PER_SOURCE}`);
  assert(closed.length === 5, `expected 5 refusals, got ${closed.length}`);
});

await test("an unverified connection is dropped on the SHORT deadline", async () => {
  // A stranger holds a slot for UNVERIFIED_TIMEOUT_MS, not the full handshake deadline.
  // Scaled down here so the test is fast; the ratio is what matters.
  const limiter = new HalfOpenLimiter(8, 8);
  let closed = false;
  new PeerLink({
    channel: silentChannel("10.4.4.4"), identity: identity(), sodium, weDialed: false,
    contactSecret: CONTACT, limiter, handshakeTimeoutMs: 40,
    onAuth: () => {}, onFrame: () => {}, onClose: () => { closed = true; },
  });
  assert(limiter.unverified === 1, "slot held while unproven");
  await sleep(120);
  assert(closed, "an unproven connection must be dropped on its deadline");
  assert(limiter.outstanding === 0, `slot must be freed, ${limiter.outstanding} held`);
  const ratio = HANDSHAKE_TIMEOUT_MS / UNVERIFIED_TIMEOUT_MS;
  note(`unverified deadline ${UNVERIFIED_TIMEOUT_MS}ms vs handshake ${HANDSHAKE_TIMEOUT_MS}ms (${ratio}x shorter)`);
  assert(ratio >= 2, "the unverified deadline should be materially shorter than the full one");
});

await test("sustained-rate headroom", async () => {
  // What the constants actually buy, stated as a rate rather than a count: a flood must
  // exceed this to keep the unverified budget saturated, and even then §3 above says
  // members are unaffected.
  const rate = MAX_HALF_OPEN_UNVERIFIED / (UNVERIFIED_TIMEOUT_MS / 1000);
  note(`unverified budget ${MAX_HALF_OPEN_UNVERIFIED} / ${UNVERIFIED_TIMEOUT_MS}ms ` +
       `= ${rate.toFixed(0)} conn/s to saturate`);
  note(`verified budget ${MAX_HALF_OPEN_VERIFIED}, reachable only with the contact secret`);
  assert(rate >= 100, `saturation rate ${rate}/s is too easy to reach`);
  assert(MAX_HALF_OPEN_VERIFIED >= 64, "the members' budget should not be tight");
});

console.log(`\n${pass} passed, ${fail} failed\n`);
process.exit(fail === 0 ? 0 : 1);
