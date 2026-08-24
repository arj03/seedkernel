// Load behaviour of the half-open budgets (§12.6.2 §6.5, §11.4). The concealed handshake
// refuses strangers by SILENCE (an immediate close is an oracle), so an unproven connection
// occupies a socket for the whole deadline, and these budgets are what stand between a
// stranger and the node. Three questions: what an unproven connection costs us, whether a
// flood from outside the contact secret can stop members getting in, and whether the
// budgets behave as the constants claim. Entirely over the in-process fabric, so the
// numbers cover crypto/alloc cost per connection, not kernel socket limits. The limiter
// lives inside the transport guest, so every assertion is on OBSERVABLE behaviour — is a
// socket evicted or refused, does a member still complete its handshake — never a counter.

import {
  makeTransportHost, sodium as realSodium, LoopbackChannels, until,
} from "./transport-harness.mjs";
import { testkit } from "./testkit.mjs";

const CONTACT = new Uint8Array(32).fill(3);

/** The node's sodium, wrapped to charge the asymmetric operations to a counter. The guest
 *  reaches ML-KEM through its private module and the remaining transforms through the host seam, so this is the real bill for a
 *  connection — including the ephemeral keypair, which is `RANDOM(32)` + an x25519/dh
 *  against the base point and so shows up as a scalarmult. */
function countingSodium(base) {
  const ops = { scalarmult: 0, sign: 0, verify: 0, aead: 0 };
  const charge = {
    crypto_scalarmult: "scalarmult",
    crypto_sign_detached: "sign",
    crypto_sign_verify_detached: "verify",
    crypto_aead_chacha20poly1305_ietf_encrypt: "aead",
    crypto_aead_chacha20poly1305_ietf_decrypt: "aead",
  };
  const sodium = new Proxy(base, {
    get(t, p, r) {
      const v = Reflect.get(t, p, r);
      if (typeof v !== "function") return v;
      const key = charge[p];
      if (key) return (...a) => { ops[key]++; return v.apply(t, a); };
      return v.bind(t);
    },
  });
  return { sodium, ops, reset() { for (const k of Object.keys(ops)) ops[k] = 0; } };
}

/** A listening node, with its half-open budgets set for the test. */
async function server(fabric, halfOpen, opts = {}) {
  const n = await makeTransportHost({
    channels: fabric.view(), listen: { host: "loopback", port: 0 },
    contactSecret: CONTACT, transportHalfOpen: halfOpen, ...opts,
  });
  await n.driver.start();
  return n;
}

/** A raw dial that opens a socket and then says nothing at all — the cheapest
 *  possible flood, and the one the deadline exists for. Resolves what the server did
 *  to it: `closed` flips when our socket is evicted or refused. */
function silentDial(fabric, port, host) {
  const ch = fabric.connect({ host, port, transport: "tcp" });
  const st = { ch, closed: false };
  ch.onData(() => {});
  ch.onClose(() => { st.closed = true; });
  return st;
}

/** A real member node that dials the server and must complete its handshake. */
async function member(fabric, serverNode, host) {
  const m = await makeTransportHost({ channels: fabric.view(), contactSecret: CONTACT });
  m.driver.addPeerAddr(serverNode.driver.peerId, {
    host, port: serverNode.driver.port, transport: "tcp", contactSecret: CONTACT,
  });
  return m;
}

const { test, assert, keep, note, sleep, summary } = testkit();

console.log("\nTransport load behaviour (§12.6.2 §6.5)\n");

// ─────────────────────────────────────────────────────────────────────────────
await test("a silent stranger costs NO asymmetric crypto", async () => {
  // Key material is deferred until a msg1 opens (guest `ensureKeys`). Generating an X25519
  // keypair when the socket lands would let every inbound TCP connection buy a keygen
  // before the peer had proved anything — the cheapest flood there is.
  const N = 200;
  const fabric = new LoopbackChannels();
  const c = countingSodium(realSodium);
  const s = keep(await server(fabric, { unverified: N + 1, perSource: N + 1, verified: N + 1 }, { sodium: c.sodium }));
  c.reset(); // boot (manifest verify, hashing) is not what we are measuring
  const t0 = process.hrtime.bigint();
  const dials = [];
  for (let i = 0; i < N; i++) dials.push(silentDial(fabric, s.driver.port, `10.0.${(i >> 8) & 255}.${i & 255}`));
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  await sleep(300); // let every accept reach the guest before reading the bill
  note(`${N} silent connections accepted in ${ms.toFixed(0)}ms (${(ms * 1000 / N).toFixed(1)}µs each)`);
  note(`asymmetric ops charged: scalarmult=${c.ops.scalarmult} sign=${c.ops.sign} verify=${c.ops.verify}`);
  assert(c.ops.scalarmult === 0, `a silent stranger cost ${c.ops.scalarmult} scalarmults (keygen or DH), want 0`);
  assert(c.ops.sign === 0 && c.ops.verify === 0, "a silent stranger must cost no signature work");
  assert(dials.every((d) => !d.closed), "a silent stranger inside budget must be held, not refused");
});

await test("a stranger who TRIES costs one AEAD open and nothing more", async () => {
  // A flood that bothers to send plausible bytes should not cost meaningfully more than
  // one that sends none. Verification of msg1 is a hash and a Poly1305 check; everything
  // expensive is behind it.
  const N = 100;
  const fabric = new LoopbackChannels();
  const c = countingSodium(realSodium);
  const s = keep(await server(fabric, { unverified: N + 1, perSource: N + 1, verified: N + 1 }, { sodium: c.sodium }));
  c.reset();
  const dials = [];
  for (let i = 0; i < N; i++) {
    const d = silentDial(fabric, s.driver.port, `10.1.${(i >> 8) & 255}.${i & 255}`);
    // A well-formed-looking msg1 — right suite byte, right length, wrong everything
    // else. The suite byte matters: get it wrong and the guest refuses on the byte
    // alone, and this measures a cheaper path than a real attacker gets.
    const junk = new Uint8Array(1265);
    junk[0] = 0x03; // SUITE_CHANNEL_CONCEALED
    for (let j = 1; j < junk.length; j++) junk[j] = (i * 31 + j) & 255;
    d.ch.send(junk);
    dials.push(d);
  }
  await sleep(400);
  note(`${N} garbage msg1 rejected; scalarmult=${c.ops.scalarmult} aead=${c.ops.aead} ` +
       `(${(c.ops.aead / N).toFixed(2)} AEAD opens per connection)`);
  assert(c.ops.scalarmult === 0, `garbage msg1 cost ${c.ops.scalarmult} scalarmults, want 0`);
  assert(c.ops.sign === 0, "garbage must not reach the signing path");
  assert(c.ops.aead === N, `a plausible rejected msg1 must cost exactly one AEAD open, got ${c.ops.aead / N} each`);
  assert(dials.every((d) => !d.closed), "a refusal is SILENCE, not a close — the deadline does that");
});

await test("an outside flood CANNOT keep members out", async () => {
  // The property the whole budget design exists for. Separate tiers are not enough on
  // their own: a saturating flood would refuse the member AT THE DOOR, before it could
  // send the one message that promotes it. Eviction fixes the order — a new arrival
  // displaces the stalest stranger, proves itself in one round trip, and leaves the
  // contended budget.
  const UNVER = 24;
  const fabric = new LoopbackChannels();
  const s = keep(await server(fabric, { unverified: UNVER, perSource: UNVER, verified: 8 }));
  const flood = [];
  for (let i = 0; i < UNVER; i++) flood.push(silentDial(fabric, s.driver.port, `10.2.${i}.1`));
  await sleep(300);
  assert(flood.every((d) => !d.closed), "the unverified budget should be saturated, not shedding");

  const m = keep(await member(fabric, s, "10.9.9.9"));
  await m.driver.ready(4000);
  const evicted = flood.filter((d) => d.closed).length;
  note(`under a saturating flood: member authenticated = ${(await m.driver.linkedPeers()).length === 1}; ` +
       `${evicted} stranger(s) evicted`);
  assert((await m.driver.linkedPeers()).includes(s.driver.peerId),
    "A MEMBER WAS DENIED SERVICE BY AN OUTSIDE FLOOD — the budgets are not separated");
  assert(evicted >= 1, "a saturated budget must EVICT to make room, not refuse the newcomer");
  assert(flood[0].closed, "eviction must take the OLDEST stranger first");
});

await test("members keep getting in under a SUSTAINED flood", async () => {
  // Not one member against a static flood, but many arriving while the attacker keeps
  // pushing. Every one must complete.
  const UNVER = 16;
  const ROUNDS = 8;
  const fabric = new LoopbackChannels();
  const s = keep(await server(fabric, { unverified: UNVER, perSource: UNVER, verified: 16 }));
  let n = 0;
  const flood = () => silentDial(fabric, s.driver.port, `10.5.${(n++) % 250}.1`);
  for (let i = 0; i < UNVER; i++) flood();

  let authed = 0;
  for (let i = 0; i < ROUNDS; i++) {
    for (let j = 0; j < 4; j++) flood(); // attacker keeps pushing
    const m = keep(await member(fabric, s, `10.8.${i}.1`));
    try { await m.driver.ready(4000); } catch { /* counted as a failure below */ }
    if ((await m.driver.linkedPeers()).includes(s.driver.peerId)) authed++;
  }
  note(`${authed}/${ROUNDS} members authenticated while ${ROUNDS * 4 + UNVER} flood connections churned`);
  assert(authed === ROUNDS, `${ROUNDS - authed} member(s) denied service under sustained flood`);
});

await test("a leaked contact secret cannot lock members out of the verified budget", async () => {
  // The same failure one tier up: an attacker holding the leaked address can promote into
  // the verified tier and stall, so a promote() that merely REFUSED when full would let a
  // few hundred shut every real member out — the verified tier evicts too. The attacker is
  // a real node holding the secret whose socket drops everything after msg1.
  const VER = 6;
  const fabric = new LoopbackChannels();
  const s = keep(await server(fabric, { unverified: 1024, perSource: 1024, verified: VER }));
  for (let i = 0; i < VER * 3; i++) {
    const d = silentDial(fabric, s.driver.port, `10.6.6.${i}`);
    // A dialer that opens under the real secret and then stalls needs a real msg1, which
    // only a real node can build — so borrow one and cut its socket after the first write.
    const a = keep(await makeTransportHost({ channels: fabric.view(), contactSecret: CONTACT }));
    let wrote = 0;
    const raw = fabric.connect({ host: `10.6.7.${i}`, port: s.driver.port, transport: "tcp" });
    const gated = {
      remoteAddr: raw.remoteAddr,
      send: (b) => { if (++wrote <= 1) raw.send(b); },
      framing: raw.framing,
      onData: (cb) => raw.onData(cb),
      onClose: (cb) => raw.onClose(cb),
      close: (g) => raw.close(g),
    };
    a.driver.openLink({ channel: gated, weDialed: true, expectPeerId: s.driver.peerId, contactSecret: CONTACT });
    d.ch.onClose(() => {});
  }
  await sleep(500);

  // A real member must still complete.
  const m = keep(await member(fabric, s, "10.7.7.7"));
  await m.driver.ready(4000);
  note(`after ${VER * 3} credentialled stalls against a ${VER}-slot verified budget, member got in`);
  assert((await m.driver.linkedPeers()).includes(s.driver.peerId),
    "A MEMBER WAS LOCKED OUT by a saturated verified budget");
});

await test("the budget bounds links PAST the handshake, not just into it", async () => {
  // The tiers above bound who is getting IN. Releasing the slot at authentication would
  // let anyone who can complete a handshake hold links without limit, each with its own
  // framer, session keys, timers and buffers. The slot is held for the link's life, in a
  // third tier that evicts its stalest occupant like the other two.
  const AUTHED = 3;
  const fabric = new LoopbackChannels();
  const s = keep(await server(fabric, { unverified: 1024, perSource: 1024, verified: 256, authed: AUTHED }));
  let everSaw = 0;
  for (let i = 0; i < AUTHED * 3; i++) {
    const m = keep(await member(fabric, s, `10.10.${i}.1`));
    try { await m.driver.ready(4000); } catch { /* counted below */ }
    if ((await m.driver.linkedPeers()).includes(s.driver.peerId)) everSaw++;
    await sleep(30);
  }
  const held = (await s.driver.linkedPeers()).length;
  note(`${AUTHED * 3} members authenticated against a ${AUTHED}-slot authed budget; ${held} link(s) held, ${everSaw} got in`);
  assert(everSaw === AUTHED * 3, `${AUTHED * 3 - everSaw} member(s) refused at the door — the authed tier must evict, not refuse`);
  assert(held <= AUTHED, `${held} authenticated links held against a budget of ${AUTHED}`);
});

await test("the per-source cap still bites under flood", async () => {
  // Per-source is deliberately NOT evictable: one address at its own limit must be
  // refused outright, never allowed to push a different address out.
  const PER = 8;
  const fabric = new LoopbackChannels();
  const s = keep(await server(fabric, { unverified: 1024, perSource: PER, verified: 256 }));
  const noisy = [];
  for (let i = 0; i < PER + 5; i++) noisy.push(silentDial(fabric, s.driver.port, "10.3.3.3"));
  const quiet = silentDial(fabric, s.driver.port, "10.3.3.4");
  await sleep(400);
  const refused = noisy.filter((d) => d.closed).length;
  note(`one source opened ${PER + 5}; ${refused} refused, ${PER + 5 - refused} held`);
  assert(refused === 5, `per-source cap leaked: ${refused} refused, want 5`);
  assert(!quiet.closed, "a different source must be unaffected by a noisy one");
});

await test("the HOST's own link table is bounded, under every tier the guest enforces", async () => {
  // The tiers above are content policy living in the transport guest, because only it can
  // see "half-open" and "authenticated". But a socket costs the HOST a descriptor and a
  // table entry the moment it is accepted — before the guest forms an opinion — so a
  // wedged or hostile occupant that never refuses would spend host memory the tiers cannot
  // reach. `maxRawLinks` is the ceiling underneath them, set here far BELOW the budgets so
  // what bites is unambiguously the driver's ceiling and not a tier.
  const RAW = 6;
  const fabric = new LoopbackChannels();
  const s = keep(await server(fabric, { unverified: 1024, perSource: 1024, verified: 256 }, { maxRawLinks: RAW }));
  const dials = [];
  for (let i = 0; i < RAW * 3; i++) dials.push(silentDial(fabric, s.driver.port, `10.11.${i}.1`));
  await sleep(300);
  const held = dials.filter((d) => !d.closed).length;
  note(`${RAW * 3} connections against a ${RAW}-link driver ceiling; ${held} held`);
  // The driver REFUSES rather than evicts: eviction is a policy about which link is worth
  // keeping, and picking one is exactly the judgement this layer does not have. A budget
  // this far above the guest's own tiers is never the thing rationing a healthy node.
  assert(held <= RAW, `the driver held ${held} raw links against a ceiling of ${RAW}`);
  assert(dials.slice(0, RAW).every((d) => !d.closed), "the links inside the ceiling must be kept");
  assert(dials.slice(RAW).every((d) => d.closed), "a connection past the ceiling must be closed, not stranded open");

  // …and the ceiling is not a one-way door: a link going away frees its entry, or the
  // first burst would blackhole the node permanently.
  for (const d of dials.slice(0, RAW)) d.ch.close(false);
  await sleep(200);
  const after = silentDial(fabric, s.driver.port, "10.12.0.1");
  await sleep(200);
  assert(!after.closed, "a released raw link must free its slot for the next connection");
});

await test("an unverified connection is dropped on the SHORT deadline", async () => {
  // A stranger holds a slot for the unverified deadline, not the full handshake one —
  // measured rather than restated, since the constants live in the transport bundle and a
  // number copied out of it here would be drift waiting to happen.
  const fabric = new LoopbackChannels();
  const s = keep(await server(fabric, { unverified: 8, perSource: 8, verified: 8 }));
  const d = silentDial(fabric, s.driver.port, "10.4.4.4");
  const t0 = Date.now();
  await until(() => d.closed, 15000, "an unproven connection to be dropped on its deadline");
  const unverifiedMs = Date.now() - t0;
  note(`unverified deadline measured at ~${unverifiedMs}ms`);
  assert(unverifiedMs >= 200, "the deadline must not be so short that a slow member cannot finish");
  assert(unverifiedMs <= 6000, `an unproven connection held its slot for ${unverifiedMs}ms — too long`);
  globalThis.__unverifiedMs = unverifiedMs;
});

await test("sustained-rate headroom", async () => {
  // What the constants actually buy, stated as a rate rather than a count: a flood must
  // exceed this to keep the unverified budget saturated, and even then eviction (above)
  // says members are unaffected.
  const { DEFAULT_MAX_HALF_OPEN_UNVERIFIED, DEFAULT_MAX_HALF_OPEN_VERIFIED }
    = await import("../build/host/transport-host.js");
  const deadlineMs = globalThis.__unverifiedMs ?? 2000;
  const rate = DEFAULT_MAX_HALF_OPEN_UNVERIFIED / (deadlineMs / 1000);
  note(`unverified budget ${DEFAULT_MAX_HALF_OPEN_UNVERIFIED} / ~${deadlineMs}ms ` +
       `= ${rate.toFixed(0)} conn/s to saturate`);
  note(`verified budget ${DEFAULT_MAX_HALF_OPEN_VERIFIED}, reachable only with the contact secret`);
  assert(rate >= 100, `saturation rate ${rate}/s is too easy to reach`);
  assert(DEFAULT_MAX_HALF_OPEN_VERIFIED >= 64, "the members' budget should not be tight");
});

summary("transport load behaviour");
