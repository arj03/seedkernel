// transport-link.test.mjs — regression tests for the §12.6.1 link hardening and the
// §12.6.2 concealed handshake.
//
// The AKE, the record layer, the half-open limiter and the link router live in the signed
// transport bundle (`transport/src`), where no test can reach in and hold an object. So
// each property is pinned where it ships — through the real host stack, shell → driver
// (TransportHost) → guest realm — with an instrumented in-process channel standing in for
// the socket. What these tests observe is the wire and the host-visible edges of the
// shipped artifact, never a parallel reimplementation.
//
// `TransportHost.openLink()` is the seam that makes it possible: the host half of one
// link, taking what a link needs to be stood up and handing back a handle. The half-open
// budgets are the exception — a host-managed link spends no budget by design — so those
// tests use real listeners and raw dials, in transport-load.test.mjs.
//
// Each test names the property it pins, so a failure says which guarantee broke.

import {
  makeTransportHost, generateKeyPair, sodium, LoopbackChannels, CLOSE_REASON, until, PROTO,
} from "./transport-harness.mjs";
import { testkit } from "./testkit.mjs";

// ── an instrumented channel pair ─────────────────────────────────────────────
// The RawLink shape (core/socket-seam.ts) with the hooks these tests need: every byte
// written is recorded, `tamper` may corrupt or drop a message in flight, `destructive`
// models a transport that discards unflushed writes on a hard close, and `closeArgs`
// records what the guest asked the transport to do. `framing` picks the codec the guest
// runs over the pair — 0 leaves it alone, 1 length-prefixes, as a real TCP link gets.
// Delivery is deferred a microtask so nothing re-enters a live guest frame, the same
// discipline a real socket imposes.
function wirePair({ addrA = "10.0.0.1", addrB = "10.0.0.2", tamper, destructive, framing = 0 } = {}) {
  const mk = (name, remoteAddr) => ({
    name, remoteAddr,
    sent: [], closeArgs: [], dead: false, inFlight: 0,
    msg: null, cls: null, peer: null,
    // The stall clock's progress signal (core/socket-seam.ts `RawLink.buffered`):
    // bytes written but not yet on the wire. A test drives it directly to model a
    // backpressured socket — draining, or stuck.
    backlog: 0,
    buffered() { return this.backlog; },
    send(bytes) {
      if (this.dead) return;
      this.sent.push(Buffer.from(bytes).toString("hex"));
      const out = tamper ? tamper(bytes, this.name) : bytes;
      if (out === null) return; // dropped in flight
      const seq = ++this.inFlight;
      queueMicrotask(() => {
        // A destructive close zeroes inFlight; anything still queued never made it.
        if (destructive && seq > this.inFlight) return;
        if (!this.peer.dead) this.peer.msg?.(out);
      });
    },
    framing,
    onData(cb) { this.msg = cb; },
    onClose(cb) { this.cls = cb; },
    close(graceful = false) {
      this.closeArgs.push(graceful);
      if (this.dead) return;
      this.dead = true;
      if (destructive && !graceful) this.inFlight = 0;
      queueMicrotask(() => this.peer.kill());
    },
    // The far end going away: fires onClose, the way a real channel's fail() does.
    kill() {
      if (this.dead) return;
      this.dead = true;
      this.cls?.();
      queueMicrotask(() => this.peer.kill());
    },
  });
  const a = mk("A", addrA), b = mk("B", addrB);
  a.peer = b; b.peer = a;
  return [a, b];
}

/** A node's contact secret. Per node in production; one value here is enough, since
 *  every test pairs a dialer holding it with the node that owns it. */
const CONTACT = new Uint8Array(32).fill(7);

/** Long enough for a handshake that is going to fail to have failed, and for a
 *  responder that is going to stay silent to have stayed silent. Every negative
 *  assertion in this file is "after things have settled", never "immediately". */
const settle = (ms = 250) => new Promise((r) => setTimeout(r, ms));

/** Two nodes and one link between them, opened from both ends over `chans`.
 *
 *  `aOpts`/`bOpts` go to the shells (identity, contactSecret, networkKey, admitPeer).
 *  `linkOpts` goes to both openLink calls, with three extras of its own:
 *  `dialSecret` overrides what the DIALER presents (so a test can hold the wrong
 *  secret), and `a`/`b` carry per-side options for the cases where the two ends must
 *  deliberately disagree. */
async function linked(chans, aOpts = {}, bOpts = {}, linkOpts = {}) {
  const { dialSecret, a: aLink = {}, b: bLink = {}, ...both } = linkOpts;
  const A = await makeTransportHost({ channels: new LoopbackChannels(), contactSecret: CONTACT, ...aOpts });
  const B = await makeTransportHost({ channels: new LoopbackChannels(), contactSecret: CONTACT, ...bOpts });
  const st = {
    A, B,
    a: { authed: false, closed: false, reason: null, peer: null },
    b: { authed: false, closed: false, reason: null, peer: null },
    close() { try { A.shell.close(); } catch { /* already down */ } try { B.shell.close(); } catch { /* already down */ } },
  };
  const side = (s) => ({
    onAuth: (pid) => { s.authed = true; s.peer = pid; },
    onClose: (_id, reason) => { s.closed = true; s.reason = reason; },
  });
  // The dialer presents THE PEER's contact secret (what an address carries); the
  // acceptor gates on its own, which came from its shell at init.
  st.aLink = A.driver.openLink({
    channel: chans[0], weDialed: true, expectPeerId: B.driver.peerId,
    contactSecret: dialSecret !== undefined ? dialSecret
      : ("contactSecret" in bOpts ? bOpts.contactSecret : CONTACT),
    source: chans[0].remoteAddr, ...both, ...aLink, ...side(st.a),
  });
  st.bLink = B.driver.openLink({
    channel: chans[1], weDialed: false,
    source: chans[1].remoteAddr, ...both, ...bLink, ...side(st.b),
  });
  return st;
}

/** The pair above, already authenticated — the starting point for every test whose
 *  subject is what happens *after* the handshake. */
async function upPair(chanOpts, aOpts, bOpts, linkOpts) {
  const chans = wirePair(chanOpts);
  const st = await linked(chans, aOpts, bOpts, linkOpts);
  st.chans = chans;
  await until(() => st.a.authed && st.b.authed, 4000, "handshake");
  return st;
}

// ── harness ──────────────────────────────────────────────────────────────────
const { test, assert, summary } = testkit();

const hexOf = (u) => Buffer.from(u).toString("hex");

console.log("\nTransport link hardening (§12.6.1) + concealed handshake (§12.6.2)\n");

await test("baseline: two ends authenticate and exchange frames", async (keep) => {
  const st = keep(await upPair());
  const proto = PROTO;
  const resp = await st.A.request(st.B.driver.peerId, proto, Uint8Array.from([1, 2, 3]));
  assert(resp.length === 3 && resp[2] === 3, `frames not delivered: ${resp.length}`);
  assert(st.a.peer === st.B.driver.peerId, "the dialer must attribute the link to the peer it dialed");
  assert(st.b.peer === st.A.driver.peerId, "the acceptor must attribute the link to the caller");
});

await test("a request's deadline is the CALLER's, not a node-wide clock", async (keep) => {
  // Two requests to the same peer, over the same live link, with different deadlines: the
  // short one must settle on its own schedule. A node-wide silence clock cannot do that —
  // it re-arms on ANY frame from the peer, so a request's lifetime depends on unrelated
  // traffic and every request on the node shares one window.
  const st = keep(await upPair(undefined, undefined, { mode: "hang" }));
  const proto = PROTO;
  // A holder that never answers: the deadline is the only thing that can settle these.
  const t0 = Date.now();
  const short = st.A.request(st.B.driver.peerId, proto, Uint8Array.from([1]), 150)
    .then(() => "resolved", () => Date.now() - t0);
  const long = st.A.request(st.B.driver.peerId, proto, Uint8Array.from([2]), 5000)
    .then(() => "resolved", () => Date.now() - t0);

  const shortMs = await short;
  assert(typeof shortMs === "number", "an unanswered request must reject, not resolve");
  assert(shortMs < 1200, `the 150ms deadline must settle on its own schedule (took ${shortMs}ms)`);

  // ...and it must not have taken the other request down with it: the 5s one is still
  // pending, so per-request means per request, not per peer.
  let longSettled = false;
  long.then(() => { longSettled = true; });
  await new Promise((r) => setTimeout(r, 50));
  assert(!longSettled, "a peer's short-deadline request must not settle its long-deadline one");
});

await test("the deadline is a STALL clock: a request still draining out is not late", async (keep) => {
  // A clock armed when the request is QUEUED times our own upload and blames the holder
  // for our backlog: a 50 MB PUT queued ~42 MB behind its sockets cancels every request
  // in the window at its 5 s deadline while the wire moves perfectly.
  const chans = wirePair();
  const st = keep(await linked(chans, {}, { mode: "hang" }));
  const proto = PROTO;
  // A backpressured socket holding 40 KB of this request, draining 4 KB at a time —
  // slower than the 100 ms deadline, so a queue-time clock would fire ~9 times over.
  chans[0].backlog = 40_000;
  const drain = setInterval(() => { chans[0].backlog = Math.max(0, chans[0].backlog - 4_000); }, 40);

  const t0 = Date.now();
  const settled = st.A.request(st.B.driver.peerId, proto, Uint8Array.from([1]), 100)
    .then(() => "resolved", () => Date.now() - t0);

  // While it drains, the request must survive well past its own deadline.
  await new Promise((r) => setTimeout(r, 300));
  let done = false;
  settled.then(() => { done = true; });
  await new Promise((r) => setTimeout(r, 0));
  assert(!done, `a request whose bytes are still going out must not be timed out (backlog ${chans[0].backlog})`);

  // Once drained the peer genuinely owes an answer, so the clock becomes a plain
  // silence window and settles — a stall clock is not a licence to hang.
  const ms = await settled;
  clearInterval(drain);
  assert(typeof ms === "number", "an unanswered request must still reject once its bytes are out");
  assert(ms > 300, `it must have outlived the queueing phase (settled after ${ms}ms)`);
  assert(ms < 3000, `it must settle soon after draining, not hang (took ${ms}ms)`);
});

await test("a stalled link still settles on the deadline", async (keep) => {
  // The other half: a backlog that never moves is a stuck wire, and no amount of
  // "bytes are queued" may excuse it. Same 100 ms, same never-answering peer, but
  // nothing drains.
  const chans = wirePair();
  const st = keep(await linked(chans, {}, { mode: "hang" }));
  const proto = PROTO;
  chans[0].backlog = 40_000;                            // frozen: no drain interval
  const t0 = Date.now();
  const ms = await st.A.request(st.B.driver.peerId, proto, Uint8Array.from([1]), 100)
    .then(() => "resolved", () => Date.now() - t0);
  assert(typeof ms === "number", "a stalled request must reject");
  assert(ms < 1500, `a frozen backlog must settle on the deadline, not wait forever (took ${ms}ms)`);
});

await test("handshake messages are exact-length: a trailing byte is refused", async (keep) => {
  // Trailing bytes would ride outside the transcript hash, and so outside what both
  // signatures cover. Exact, not minimum, for every message in the flight.
  // A's two handshake messages, by the width each is accepted at: msg1 and msg3.
  for (const len of [81, 112]) {
    const chans = wirePair({
      tamper: (b, from) => (from === "A" && b.length === len ? Buffer.concat([Buffer.from(b), Buffer.from([0])]) : b),
    });
    const st = keep(await linked(chans));
    await settle();
    // The responder is the end that reads a tampered message from A, so it is the end
    // that must refuse. (For msg3 the initiator has legitimately authenticated by then:
    // it verified msg2 at 1 RTT, a round trip before the responder authenticates it.)
    assert(!st.b.authed, `responder must refuse an over-long ${len}-byte message`);
    if (len === 81) assert(!st.a.authed, "a rejected msg1 must leave the initiator unauthenticated");
    st.close();
  }
});

await test("CONCEALMENT: a responder says NOTHING to a caller without the contact secret", async (keep) => {
  // A node that speaks first is a directory service: one connect reads its identity
  // straight off the wire. A caller without the contact secret must get silence — nothing
  // that distinguishes this node from a port that is not listening.
  const chans = wirePair();
  // The caller holds a secret that is not the receiver's.
  const st = keep(await linked(chans, {}, {}, { dialSecret: new Uint8Array(32).fill(9) }));
  await settle();
  assert(chans[1].sent.length === 0, `responder emitted ${chans[1].sent.length} message(s); must emit none`);
  assert(!st.a.authed && !st.b.authed, "neither end may authenticate");
  assert(!st.b.closed, "a refusal must not even close — the deadline does that later");
});

await test("CONCEALMENT: neither identity appears in cleartext on the wire", async (keep) => {
  const st = keep(await upPair());
  const proto = PROTO;
  await st.A.request(st.B.driver.peerId, proto, Uint8Array.from([9]));
  const wire = [...st.chans[0].sent, ...st.chans[1].sent].join("");
  for (const [name, id] of [["initiator", st.A.driver.peerId], ["responder", st.B.driver.peerId]]) {
    assert(!wire.includes(id), `${name} identity key found in cleartext on the wire`);
  }
});

await test("CONCEALMENT: msg1 carries no identity, so a seized static key reveals none", async (keep) => {
  // Why identities are deferred past the ephemeral-ephemeral DH rather than sealed to the
  // responder's static key as Noise IK does: anything msg1 carries is readable by whoever
  // holds that static key, including an attacker who seizes the node years later and
  // replays a recording.
  const chans = wirePair();
  const st = keep(await linked(chans));
  await until(() => chans[0].sent.length > 0, 4000, "msg1");
  const msg1 = Buffer.from(chans[0].sent[0], "hex");
  assert(msg1.length === 81, `msg1 should be 81 bytes, got ${msg1.length}`);
  assert(!msg1.includes(Buffer.from(st.A.driver.peerId, "hex")), "msg1 must not carry the initiator identity");
});

await test("CONTACT SECRET: the address book alone does not grant a probe", async (keep) => {
  // Every peer holding this node's ADDRESS also holds its static key, so without a contact
  // secret an address book leak is a probe capability: elicit msg2, confirm which identity
  // lives at that host, and keep doing it after being removed from the member set. With
  // one, an address leak costs the address and nothing more.
  const chans = wirePair();
  // The caller knows B's address (and so its static key) but not B's contact secret.
  const st = keep(await linked(chans, {}, {}, { dialSecret: new Uint8Array(32).fill(9) }));
  await settle();
  assert(chans[1].sent.length === 0, `outsider drew ${chans[1].sent.length} message(s); must draw none`);
  assert(!st.a.authed && !st.b.authed, "a wrong contact secret must not authenticate");
});

await test("FRAME CAP: an unauthenticated peer cannot declare a large frame", async (keep) => {
  // A stranger who knows only host:port must not be able to reserve memory by declaring
  // a big frame and dribbling the body. On a length-framed link the declaration is the
  // 4-byte prefix, and one over the pre-auth cap is fatal on sight — the body never
  // arrives and nothing is allocated for it.
  const chans = wirePair({ framing: 1 });
  const st = keep(await linked(chans));
  chans[1].msg(new Uint8Array([0x00, 0x01, 0x00, 0x00])); // declares 64 KiB, cap is 8 KiB
  await settle();
  assert(st.b.closed, "an over-cap pre-auth declaration must tear the link down");
  assert(!st.b.authed, "and it must never have authenticated");
});

await test("FRAME CAP: authentication raises it, before anything can arrive under it", async (keep) => {
  // The raise happens inside becomeAuthed(), ahead of the queued-frame flush, because a
  // responder authenticates at msg3 and may put application data on the wire alongside
  // msg4 — which arrives in the same delivery. A link that raised its cap afterwards
  // would measure that first frame against the handshake bound and kill every
  // connection on its first sizeable exchange.
  const chans = wirePair({ framing: 1 });
  const st = keep(await linked(chans));
  st.aLink.send(new Uint8Array(64 * 1024).fill(7)); // queued pre-auth, far over the cap
  await until(() => st.a.authed && st.b.authed, 4000, "handshake");
  await settle();
  assert(!st.a.closed && !st.b.closed, "a full-size frame after auth must cross, not close the link");
});

await test("REASSEMBLY: a frame dribbled one byte at a time is still one message", async (keep) => {
  // The behaviour the framer's merge rule has to preserve (framing.js): arbitrary slice
  // boundaries in, exactly one message out. A dribbled full-size frame is the case both
  // naive assemblers get wrong — quadratic copying if every slice is joined onto one
  // buffer, ~50× the cap in pinned chunks if none are.
  let armed = false;
  const chans = wirePair({ framing: 1, tamper: (b, from) => (from === "A" && armed ? null : b) });
  const st = keep(await linked(chans));
  await until(() => st.a.authed && st.b.authed, 4000, "handshake");
  const proto = PROTO;
  // Above the pre-auth cap, so the dribble must be measured against the RAISED
  // cap (the FRAME CAP tests pin the raise itself).
  const payload = new Uint8Array(48 * 1024).fill(0x5a);
  armed = true; // from here on, drop A's real delivery — it is re-fed manually below
  const before = chans[0].sent.length;
  const respP = st.A.request(st.B.driver.peerId, proto, payload, 8000);
  await until(() => chans[0].sent.length > before, 3000, "A's wire message");
  const wire = Uint8Array.from(Buffer.from(chans[0].sent[chans[0].sent.length - 1], "hex"));
  // Re-feed the exact bytes one at a time, yielding between pushes so each slice
  // is a separate visit to the framer.
  for (const byte of wire) {
    chans[1].msg(new Uint8Array([byte]));
    await Promise.resolve();
  }
  const resp = await respP;
  assert(resp.length === payload.length && resp[0] === 0x5a && resp[resp.length - 1] === 0x5a,
    `a byte-dribbled frame must deliver intact (got ${resp.length} bytes)`);
});

await test("REASSEMBLY: slices that straddle the merge threshold reassemble too", async (keep) => {
  // The merge rule has four paths — a small slice into a fresh accumulator, into one with
  // room, into one that has to grow, and a large slice kept as it arrived — and a dribble
  // exercises one. Feeding sizes that cross the threshold in both directions turns a
  // boundary error into a message that never completes or completes wrong.
  let armed = false;
  const chans = wirePair({ framing: 1, tamper: (b, from) => (from === "A" && armed ? null : b) });
  const st = keep(await linked(chans));
  await until(() => st.a.authed && st.b.authed, 4000, "handshake");
  const payload = new Uint8Array(96 * 1024);
  for (let i = 0; i < payload.length; i++) payload[i] = (i * 7) & 255;
  armed = true;
  const before = chans[0].sent.length;
  const respP = st.A.request(st.B.driver.peerId, PROTO, payload, 8000);
  await until(() => chans[0].sent.length > before, 3000, "A's wire message");
  const wire = Uint8Array.from(Buffer.from(chans[0].sent[chans[0].sent.length - 1], "hex"));
  const sizes = [1, 3, 8191, 1, 8192, 2, 40_000, 1, 5000];
  for (let off = 0, i = 0; off < wire.length; i++) {
    const n = Math.min(sizes[i % sizes.length], wire.length - off);
    chans[1].msg(wire.subarray(off, off + n));
    off += n;
    await Promise.resolve();
  }
  const resp = await respP;
  let same = resp.length === payload.length;
  for (let i = 0; same && i < resp.length; i++) same = resp[i] === payload[i];
  assert(same, `mixed-size slices must reassemble byte for byte (got ${resp.length} bytes)`);
});

await test("SEND CAP: an app's over-cap request is refused BEFORE it is copied", async (keep) => {
  // The refusal is the first thing `send` does, and it is LOUD — the app's own `_net` call
  // rejects by name. Measuring after the copies would let a co-resident app naming a
  // 50 MiB payload take the transport realm down before the frame it would have been
  // refused for existed.
  const st = keep(await upPair());
  let refused = "";
  try { await st.A.request(st.B.driver.peerId, PROTO, new Uint8Array(3 * 1024 * 1024)); }
  catch (e) { refused = String(e); }
  assert(refused.includes("over the frame cap"), `an over-cap send must be refused, got ${refused || "no error"}`);
  // ...and a malformed destination, which is what the hex conversion would have run on.
  let badTo = "";
  const args = new Uint8Array(1 + 4 + 4 + 4 + 4 + 4); // noReply, deadline, to(0), proto(0), payload(0)
  try { await st.A.op("send", args); } catch (e) { badTo = String(e); }
  assert(badTo.includes("32-byte peer id"), `a malformed peer id must be refused, got ${badTo || "no error"}`);
  assert(!st.a.closed && !st.b.closed, "a refused send must not disturb the link");
});

await test("IDLE: an authenticated link carrying no traffic is retired", async (keep) => {
  // The handshake deadlines stop applying the moment a link authenticates, so without an
  // idle clock a link that went quiet is held forever with its framer, session keys,
  // timers and buffers. Retired with the authenticated goodbye, since it is our own
  // deliberate shutdown: the far end reads a clean close, not a truncation.
  const st = keep(await upPair(undefined, { linkIdleTimeoutMs: 60 }, { linkIdleTimeoutMs: 60 }));
  await until(() => st.a.closed, 4000, "the idle clock to retire a silent link");
  assert(st.a.reason === CLOSE_REASON.LOCAL || st.a.reason === CLOSE_REASON.CLEAN,
    `an idle retirement is a deliberate close, got reason ${st.a.reason}`);
});

await test("IDLE: traffic keeps a link alive across the clock", async (keep) => {
  // The other half: the clock must measure silence, not age. A link exchanging frames
  // across several windows must survive them all — an idle timeout that retired a busy
  // link would be worse than none.
  const st = keep(await upPair(undefined, { linkIdleTimeoutMs: 80 }, { linkIdleTimeoutMs: 80 }));
  for (let i = 0; i < 8; i++) {
    const r = await st.A.request(st.B.driver.peerId, PROTO, Uint8Array.from([i]));
    assert(r[0] === i, `frame ${i} did not come back — the link died under its idle clock`);
    await settle(40);
  }
  assert(!st.a.closed && !st.b.closed, "a link with traffic on it must not be retired");
});

await test("READY: a second ready() does not strand the first", async (keep) => {
  // A single waiter slot would let the second call overwrite the first, leaving the first
  // caller's promise to the second's timer — or to nothing. It is a LIST, in the transport
  // guest, and each caller holds its own deferred (the `ready` op's return value).
  const st = keep(await upPair());
  const [r1, r2] = await Promise.all([
    st.A.driver.ready(50).then(() => "ok", () => "failed"),
    st.A.driver.ready(50).then(() => "ok", () => "failed"),
  ]);
  assert(r1 === "ok" && r2 === "ok", `both ready() calls must settle (got ${r1}/${r2})`);
});

await test("SUBKEYS: one master seed, one derived identity, deterministic", async () => {
  const { deriveNodeKeys } = await import("../build/core/subkeys.js");
  const master = new Uint8Array(32).fill(5);
  const a = deriveNodeKeys(sodium, master), b = deriveNodeKeys(sodium, master);
  // Deterministic: a node rebuilds its key at boot from the one secret it stores.
  assert(hexOf(a.channel.publicKey) === hexOf(b.channel.publicKey), "derivation must be deterministic");
  const other = deriveNodeKeys(sodium, new Uint8Array(32).fill(6));
  assert(hexOf(a.channel.publicKey) !== hexOf(other.channel.publicKey), "different masters, different keys");
  // The master itself is never a signing key — only a derivation input.
  assert(hexOf(a.channel.privateKey) !== hexOf(master), "the master seed must not be used as a key");
  // ONE key, deliberately: purposes are kept apart by the domain and scope the host binds
  // into every preimage, not by a second keypair (core/subkeys.ts).
  assert(Object.keys(a).length === 1, "a node derives exactly one keypair");
});

await test("NETWORK KEY: two networks are structurally unable to reach each other", async (keep) => {
  // A boundary, not access control: the network key seeds the transcript, so every derived
  // key and every signature preimage differs and the handshake dies at the first message.
  // A staging fleet and a production one can share addresses, configs and operators and
  // still never cross.
  const chans = wirePair();
  const st = keep(await linked(chans,
    { networkKey: new Uint8Array(32).fill(1) },
    { networkKey: new Uint8Array(32).fill(2) }));
  await settle();
  assert(!st.a.authed && !st.b.authed, "nodes on different networks must never link");
  assert(chans[1].sent.length === 0, `the wrong network drew ${chans[1].sent.length} message(s)`);
  st.close();

  // Same key on both sides, everything else equal: fine.
  const net = new Uint8Array(32).fill(1);
  const st2 = keep(await upPair(undefined, { networkKey: net }, { networkKey: net }));
  assert(st2.a.authed && st2.b.authed, "one network must still link normally");
});

await test("CONTACT SECRET: absent means OPEN — the node still conceals identities", async (keep) => {
  // An open node answers anyone, which is a DoS and caller-privacy posture, NOT an
  // identity leak. The four-message ordering does the concealing, so even wide open
  // neither public key crosses the wire.
  const st = keep(await upPair(undefined, { contactSecret: undefined }, { contactSecret: undefined }));
  const wire = [...st.chans[0].sent, ...st.chans[1].sent].join("");
  for (const [name, id] of [["caller", st.A.driver.peerId], ["receiver", st.B.driver.peerId]]) {
    assert(!wire.includes(id), `${name} identity in cleartext on an open node`);
  }
});

await test("CONTACT SECRET: it is the RECEIVER's, and only the receiver's", async (keep) => {
  // Per node, not per deployment and not per pair: a caller must present the secret of the
  // node it is dialing, so a leak costs one node's inbound side and not the network.
  const secretB = new Uint8Array(32).fill(11);
  const secretC = new Uint8Array(32).fill(22);
  const st = keep(await upPair(undefined, { contactSecret: secretB }, { contactSecret: secretB }));
  assert(st.a.authed && st.b.authed, "the right secret must open the door");
  st.close();

  // The caller presents node C's secret to node B.
  const chans = wirePair();
  const st2 = keep(await linked(chans, { contactSecret: secretC }, { contactSecret: secretB },
    { dialSecret: secretC }));
  await settle();
  assert(chans[1].sent.length === 0, `another node's secret drew ${chans[1].sent.length} message(s)`);
  assert(!st2.a.authed && !st2.b.authed, "another node's secret must not authenticate");
});

await test("CONTACT SECRET: it never appears on the wire", async (keep) => {
  // It is mixed into the key schedule, never transmitted — which is also what makes it
  // a quantum hedge: an adversary who records today and breaks X25519 later still needs
  // a value that was never sent.
  const st = keep(await upPair());
  const wire = [...st.chans[0].sent, ...st.chans[1].sent].join("");
  assert(!wire.includes(hexOf(CONTACT)), "contact secret leaked onto the wire");
});

await test("LEAK FIX: a self-closing link still fires onClose", async (keep) => {
  // The reflection guard closes the link from inside the handshake, and a channel whose
  // close() set `dead` without firing onClose would leave the link in the transport's
  // pre-auth bookkeeping forever. Two nodes share one identity, so B sees its own key in
  // A's msg3.
  const id = generateKeyPair();
  const chans = wirePair();
  const st = keep(await linked(chans, { identity: id }, { identity: id }));
  await settle();
  assert(!st.a.authed && !st.b.authed, "a node must not link to itself");
  st.aLink.close();
  await until(() => st.a.closed, 3000, "close MUST reach onClose (this is the leak)");
});

await test("LEAK FIX: an explicit close() fires onClose exactly once", async (keep) => {
  const st = keep(await upPair());
  let n = 0;
  const chans = wirePair();
  const extra = st.A.driver.openLink({
    channel: chans[0], weDialed: true, expectPeerId: st.B.driver.peerId,
    contactSecret: CONTACT, onClose: () => { n++; },
  });
  extra.close(); extra.close();
  await settle();
  assert(n === 1, `onClose fired ${n} times, want exactly 1`);
});

await test("handshake deadline closes a link that never speaks", async (keep) => {
  const chans = wirePair(); // no peer link opened: nothing ever replies
  const A = await makeTransportHost({ channels: new LoopbackChannels(), contactSecret: CONTACT });
  keep({ close() { try { A.shell.close(); } catch { /* down */ } } });
  let authed = false, closed = false;
  A.driver.openLink({
    channel: chans[0], weDialed: true, expectPeerId: A.driver.peerId, contactSecret: CONTACT,
    handshakeTimeoutMs: 60,
    onAuth: () => { authed = true; }, onClose: () => { closed = true; },
  });
  await until(() => closed, 3000, "the deadline to close the link and notify");
  assert(!authed, "must not authenticate");
});

await test("rekey: the ratchet keeps frames flowing across an epoch boundary", async (keep) => {
  const st = keep(await upPair(undefined, {}, {}, { rekeyAfterFrames: 4 }));
  const proto = PROTO;
  for (let i = 0; i < 14; i++) {
    const r = await st.A.request(st.B.driver.peerId, proto, Uint8Array.from([i]));
    assert(r[0] === i, `frame ${i} came back as ${r[0]} — ordering broke across a ratchet`);
  }
  assert(!st.a.closed && !st.b.closed, "link must survive rekeying");
});

await test("rekey: mismatched intervals desync (the must-match warning is real)", async (keep) => {
  const chans = wirePair();
  const st = keep(await linked(chans, {}, {}, { a: { rekeyAfterFrames: 4 }, b: { rekeyAfterFrames: 8 } }));
  await until(() => st.a.authed && st.b.authed, 4000, "handshake");
  for (let i = 0; i < 8; i++) { st.aLink.send(Uint8Array.from([i])); await settle(20); }
  await until(() => st.b.closed, 3000, "a desync must tear the link down, not silently corrupt");
});

await test("goodbye: a clean close is distinguishable from a truncation", async (keep) => {
  const st = keep(await upPair());
  st.aLink.close();
  await until(() => st.b.closed, 3000, "B to see the authenticated end-of-stream");
  assert(st.b.reason === CLOSE_REASON.CLEAN, `a clean close must read CLEAN, got ${st.b.reason}`);
});

await test("goodbye: a cut connection reads as truncated", async (keep) => {
  const st = keep(await upPair());
  st.chans[0].kill(); // the socket dies with no goodbye
  await until(() => st.b.closed, 3000, "B to notice the cut");
  assert(st.b.reason === CLOSE_REASON.TRUNCATED, `B must report a truncation, got ${st.b.reason}`);
});

await test("goodbye is not delivered to the application as a frame", async (keep) => {
  const st = keep(await upPair());
  const proto = PROTO;
  await st.A.request(st.B.driver.peerId, proto, new TextEncoder().encode("real"));
  st.aLink.close();
  await until(() => st.b.closed, 3000, "the close to land");
  await settle(100);
  // What the far APP was handed, asked of the app itself — there is no host-side sink
  // to record it in any more.
  const seen = (await st.B.seen()).map((b) => Buffer.from(b).toString());
  assert(seen.length === 1 && seen[0] === "real", `goodbye leaked into the app: ${JSON.stringify(seen)}`);
});

await test("goodbye: the CLOSER reports a local shutdown, not a truncation", async (keep) => {
  // The trap this pins: defining wasTruncated() as `authed && !peerSaidGoodbye` is true
  // on our own side of every deliberate close — we send the farewell and do not get one
  // back. The double-connect tie-break closes a link on any parallel dial, so that
  // definition flags a routine event as a cut stream.
  const st = keep(await upPair());
  st.aLink.close();
  await until(() => st.a.closed && st.b.closed, 3000, "both ends to close");
  assert(st.a.reason === CLOSE_REASON.LOCAL, `closer should read LOCAL, got ${st.a.reason}`);
  assert(st.b.reason === CLOSE_REASON.CLEAN, `peer should read CLEAN, got ${st.b.reason}`);
});

await test("goodbye: an injected junk record must NOT produce a farewell", async (keep) => {
  // The attack the close/abort split exists to stop. An in-path attacker corrupts one
  // record A->B. B cannot decrypt it and tears the link down — but if that teardown
  // emitted an end-of-stream record, B would hand A a genuine, correctly-keyed
  // farewell, and A would read an attacker-chosen moment as a clean shutdown. The
  // attacker never forges anything; they induce the victim to say goodbye.
  let corrupted = false, armed = false;
  const st = keep(await upPair({
    tamper: (bytes, from) => {
      // Records only: upPair returns with both ends authenticated, and after that
      // every message A sends is one.
      if (from !== "A" || !armed || corrupted) return bytes;
      corrupted = true;
      const out = Uint8Array.from(bytes);
      out[out.length - 1] ^= 0xff; // break the Poly1305 tag
      return out;
    },
  }));
  armed = true;
  st.aLink.send(new TextEncoder().encode("payload"));
  await until(() => st.a.closed && st.b.closed, 3000, "both ends to tear down");
  assert(corrupted, "the test did not actually corrupt a record");
  assert(st.b.reason === CLOSE_REASON.ABORTED, `victim should read ABORTED, got ${st.b.reason}`);
  assert(st.a.reason === CLOSE_REASON.TRUNCATED, `far end should read TRUNCATED, got ${st.a.reason}`);
});

await test("a graceful close asks the transport to flush; an abort does not", async (keep) => {
  const st = keep(await upPair());
  st.aLink.close();
  await until(() => st.chans[0].closeArgs.length > 0, 3000, "the channel close");
  assert(st.chans[0].closeArgs[0] === true, `close() after a farewell must request a flush, got ${st.chans[0].closeArgs[0]}`);
  st.close();

  // A failure path closes the CHANNEL instead, which must read as a cut on the far end.
  const st2 = keep(await upPair());
  st2.chans[0].close(false);
  await until(() => st2.b.closed, 3000, "the far end to notice");
  assert(st2.b.reason === CLOSE_REASON.TRUNCATED, `an abort must read as a cut, got ${st2.b.reason}`);
});

await test("the farewell survives a transport that discards unflushed writes", async (keep) => {
  // A TCP socket destroyed rather than ended drops the record it was just handed, so
  // the whole mechanism silently no-ops on the transport most likely to carry it. This
  // fails unless close() both writes the record AND asks for a graceful teardown.
  const st = keep(await upPair({ destructive: true }));
  st.aLink.close();
  await until(() => st.b.closed, 3000, "the farewell to arrive");
  assert(st.b.reason === CLOSE_REASON.CLEAN, `expected CLEAN, got ${st.b.reason} (the farewell was discarded)`);
});

await test("WHITELIST: absent by default, and an absent hook admits everyone", async (keep) => {
  // The hook is a seam, not a requirement: a deployment that sets nothing gets a network
  // that links to anyone who holds the contact secret, which is the sane default.
  const st = keep(await upPair());
  assert(st.a.authed && st.b.authed, "no whitelist configured must mean admit-all");
});

await test("GUARD: a refused caller learns NOTHING about the receiver", async (keep) => {
  // What the second round trip bought. The caller names itself at msg3, before the
  // receiver has said anything about itself, so a caller off the whitelist is turned
  // away without learning whether the identity it dialed is even here. Under the old
  // 1-RTT ordering the receiver signed and sent its identity at msg2 — before it knew
  // who was calling — so any whitelist member could confirm who lived at any address.
  //
  // This one caught a real regression when the suite was ported. Moving the whitelist to
  // the host is right — a predicate the guest applies to itself gates nothing against a
  // hostile occupant — but the first version of that move asked the gate from
  // becomeAuthed(), which the accepting end reaches only AFTER msg4 has already put its
  // identity and signature on the wire. The gate now runs in the guest's onMsg3, before
  // msg4 is built, and a concealed refusal is silence rather than a close.
  const chans = wirePair();
  // An empty-but-present list: the receiver admits nobody. The lint is the transport's own
  // now (transport/src `admits`), shipped as config at init rather than asked of the
  // host per link — see the note there for why the host was never gating this anyway.
  const st = keep(await linked(chans, {}, { admitPeers: [new Uint8Array(32).fill(1)] }));
  await settle();
  assert(!st.b.authed, "a refused caller must not be authenticated by the receiver");
  // One message back (msg2, an ephemeral and a contact proof), then silence. The
  // receiver's identity and signature must never go out.
  assert(chans[1].sent.length === 1, `refused caller drew ${chans[1].sent.length} messages, want 1 (msg4 leaked)`);
  assert(!chans[1].sent.join("").includes(st.B.driver.peerId),
    "the receiver revealed its identity to a caller it then refused");
  assert(!st.a.authed, "a refused caller must not authenticate");
});

await test("a decrypt failure does not advance the receive counter", async (keep) => {
  // Flip a byte in the first post-auth record. The link must die rather than
  // desync — the flynn/noise bug this layer already avoided, pinned so it stays that way.
  let flipped = false, armed = false;
  const st = keep(await upPair({
    tamper: (b, from) => {
      // Post-auth, so every message from A is a record (upPair waits for both ends).
      if (from === "A" && armed && !flipped) {
        flipped = true;
        const c = Buffer.from(b); c[c.length - 1] ^= 1; return c;
      }
      return b;
    },
  }));
  armed = true;
  st.aLink.send(new TextEncoder().encode("tampered"));
  await until(() => st.b.closed, 3000, "a forged record must close the link");
  assert((await st.B.seen()).length === 0, "a forged record must not be delivered");
});

// ── §12.10: the shell answers protocols of its own, ahead of the routing table ────
//
// An inbound frame reaches the shell as the transport's `_host` deliver op and goes straight
// to the routing table, so a host that serves an id of its own — seedchat's `_offer`,
// which carries a bundle between two browsers before either has an app that could
// receive it — needs an explicit seam. `createShell({ answer })` is it. These pin both
// halves of the contract: the hook wins the ids it claims, and `null` from it is
// genuinely a fall-through rather than an empty answer.

await test("ANSWER HOOK: the shell answers its own protocol ahead of dispatch", async (keep) => {
  const seen = [];
  const st = keep(await upPair(undefined, undefined, {
    answer: (from, proto, payload) => {
      if (proto !== "_offer") return null;
      seen.push({ from, payload });
      return Promise.resolve(Uint8Array.from([0xaa, payload.length]));
    },
  }));
  const resp = await st.A.request(st.B.driver.peerId, "_offer", Uint8Array.from([1, 2, 3]));
  assert(resp.length === 2 && resp[0] === 0xaa && resp[1] === 3,
    `the shell's own answer must reach the caller, got ${[...resp]}`);
  assert(seen.length === 1, "the hook must be consulted exactly once per inbound frame");
  assert(seen[0].from === st.A.driver.peerId,
    "the hook must be handed the AUTHENTICATED sender, as dispatch is");
  // The app never saw it: an id the shell claims is answered by the shell, not routed.
  const inbound = await st.B.seen();
  assert(inbound.length === 0, "a frame the shell answered must not also reach the app");
});

await test("ANSWER HOOK: null falls through to the routing table", async (keep) => {
  let asked = 0;
  const st = keep(await upPair(undefined, undefined, {
    answer: (_from, proto) => { asked++; return proto === "_offer" ? Promise.resolve(new Uint8Array(0)) : null; },
  }));
  // The harness app claims PROTO, and the hook declines it — so the app answers, exactly
  // as it would on a shell with no hook at all. A hook is first refusal, not a shadow.
  const resp = await st.A.request(st.B.driver.peerId, PROTO, Uint8Array.from([7, 8]));
  assert(resp.length === 2 && resp[1] === 8, `the app must still answer its own id, got ${[...resp]}`);
  assert(asked === 1, "the hook is consulted for every inbound frame, including ones it declines");
  assert((await st.B.seen()).length === 1, "…and the declined frame reached the app");
});

// ── the transport guest's caller boundary ────────────────────────────────────
// The platform events (`init`, `linkBytes`, …) are the host's alone; `send` and `peers`
// are an app's to name, because both are questions about the app's own traffic. An app
// that could spell `init` could re-key the node, so the line matters in both directions.

await test("CALLER BOUNDARY: an app may name `peers`, but not a platform event", async (keep) => {
  const st = keep(await upPair());
  await until(async () => (await st.B.peers()).length > 0, 4000, "B's link to A");
  // `peers` through the APP's seam — a cross-realm call carrying the app's key, not the
  // host's 32 zero bytes. This is the path seedstore's guest takes to place replicas.
  const raw = await st.B.op("peers");
  assert(raw.length === 32 && hexOf(raw) === st.A.driver.peerId,
    "an app asking `peers` must get the authenticated set back");
  // `init` through the same seam must be refused by NAME, not silently ignored.
  let refused = "";
  try { await st.B.op("init", new Uint8Array(64)); }
  catch (e) { refused = String(e); }
  assert(refused.includes("the host's, not an app's"),
    `an app naming a platform event must be refused, got ${refused || "no error"}`);
});

await test("default caps are sane", async () => {
  const {
    DEFAULT_MAX_HALF_OPEN_UNVERIFIED, DEFAULT_MAX_HALF_OPEN_PER_SOURCE, DEFAULT_MAX_HALF_OPEN_VERIFIED,
    DEFAULT_MAX_AUTHED_LINKS, DEFAULT_LINK_IDLE_TIMEOUT_MS,
  } = await import("../build/host/transport-host.js");
  assert(DEFAULT_MAX_AUTHED_LINKS > 0 && DEFAULT_MAX_AUTHED_LINKS <= 4096,
    "the authenticated-link budget should be a real bound");
  assert(DEFAULT_LINK_IDLE_TIMEOUT_MS >= 60_000,
    "the idle clock must be generous enough that a quiet-but-live link is not churned");
  assert(DEFAULT_MAX_HALF_OPEN_UNVERIFIED > 0 && DEFAULT_MAX_HALF_OPEN_UNVERIFIED <= 8192,
    "unverified cap should be a real bound");
  assert(DEFAULT_MAX_HALF_OPEN_VERIFIED > 0 && DEFAULT_MAX_HALF_OPEN_VERIFIED <= 4096,
    "verified cap should be a real bound");
  assert(DEFAULT_MAX_HALF_OPEN_PER_SOURCE > 0 && DEFAULT_MAX_HALF_OPEN_PER_SOURCE < DEFAULT_MAX_HALF_OPEN_UNVERIFIED,
    "the per-source cap must bound one source well below the whole budget");
});

summary("transport link hardening");
