// transport-link.test.mjs — regression tests for the §12.6.1 link hardening and the
// §12.6.2 concealed handshake. The link logic lives in the SIGNED transport bundle, where
// no test can reach in and hold an object, so each property is pinned where it ships —
// through the real host stack (shell → TransportHost → guest realm) with an instrumented
// in-process channel for the socket. The half-open budgets are the exception (a
// host-managed link spends none), so those tests live in transport-load.test.mjs.

import {
  makeTransportHost, generateKeyPair, sodium, InjectedChannels, CLOSE_REASON, until, PROTO,
  authorBundle, bootShell, TransportHost, ModuleTable, FreshnessMarks, createSafeRealm,
  transportBlob, transportAuthor, transportPolicy, verifyBundle, linkedTo, ready, contact,
} from "./transport-harness.mjs";
import { testkit } from "./testkit.mjs";
import { bytesEqual } from "./bytes.mjs";

// ── an instrumented channel pair ─────────────────────────────────────────────
// The RawLink shape (core/socket-seam.ts) plus the hooks these tests need: every byte
// written is recorded, `tamper` may corrupt or drop a message in flight, `destructive`
// models a transport discarding unflushed writes on a hard close, `closeArgs` records
// what the guest asked. Delivery is deferred a microtask (like a real socket); `hold`/
// `flush` model a byte stream's several whole messages arriving in ONE read — the held
// writes are handed to the far end as a single `onData`.
function wirePair({ addrA = "10.0.0.1", addrB = "10.0.0.2", tamper, destructive, stream = false } = {}) {
  const mk = (name, remoteAddr) => ({
    name, remoteAddr,
    sent: [], closeArgs: [], dead: false, inFlight: 0,
    msg: null, cls: null, peer: null,
    holding: false, held: [],
    /** Queue writes rather than delivering them, until `flush`. */
    hold() { this.holding = true; this.held = []; },
    /** Deliver everything held as ONE read at the far end; answers how many writes
     *  were coalesced, so a test can assert it really got more than one. */
    flush() {
      this.holding = false;
      const parts = this.held.splice(0);
      if (parts.length === 0) return 0;
      let n = 0;
      for (const b of parts) n += b.length;
      const one = new Uint8Array(n);
      let off = 0;
      for (const b of parts) { one.set(b, off); off += b.length; }
      queueMicrotask(() => { if (!this.peer.dead) this.peer.msg?.(one); });
      return parts.length;
    },
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
      if (this.holding) { this.held.push(Uint8Array.from(out)); return; }
      const seq = ++this.inFlight;
      queueMicrotask(() => {
        // A destructive close zeroes inFlight; anything still queued never made it.
        if (destructive && seq > this.inFlight) return;
        if (!this.peer.dead) this.peer.msg?.(out);
      });
    },
    stream,
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

/** Stand two transport bundles over injected raw links and arrival metadata. */
async function linked(chans, aOpts = {}, bOpts = {}) {
  const aFactory = new InjectedChannels();
  const bFactory = new InjectedChannels();
  const st = {
    a: { closed: false, reason: null },
    b: { closed: false, reason: null },
    close() { try { A.shell.close(); } catch { /* already down */ } try { B.shell.close(); } catch { /* already down */ } },
  };
  const A = await makeTransportHost({
    channels: aFactory, contactSecret: CONTACT,
    onLinkClosed: (_id, reason) => { st.a.closed = true; st.a.reason = reason; },
    ...aOpts,
  });
  const B = await makeTransportHost({
    channels: bFactory, contactSecret: CONTACT,
    onLinkClosed: (_id, reason) => { st.b.closed = true; st.b.reason = reason; },
    ...bOpts,
  });
  // Attached for tests that open a SECOND pair on the same nodes later (`openPair`) —
  // not part of the harness's own node shape, just this file's bookkeeping.
  A.factory = aFactory;
  B.factory = bFactory;
  st.A = A;
  st.B = B;
  await A.driver.start();
  await B.driver.start();
  // A presents its OWN contact secret (aOpts.contactSecret, default CONTACT) on the dial;
  // B's factory hands over a plain accept.
  aFactory.give(chans[0], { weDialed: true, expectPeerId: B.peerId });
  bFactory.give(chans[1]);
  return st;
}

/** Whether A currently holds an authenticated link to B, and the reverse. A question
 *  asked of the guest's live peer set, because that is the only place the answer lives. */
const aUp = (st) => linkedTo(st.A, st.B.peerId);
const bUp = (st) => linkedTo(st.B, st.A.peerId);

/** The pair above, already authenticated — the starting point for every test whose
 *  subject is what happens *after* the handshake. */
async function upPair(chanOpts, aOpts, bOpts) {
  const chans = wirePair(chanOpts);
  const st = await linked(chans, aOpts, bOpts);
  st.chans = chans;
  await until(async () => (await aUp(st)) && (await bUp(st)), 4000, "handshake");
  return st;
}

/** Hand one more channel pair to two already-started nodes' factories: a dial on A's side,
 *  an accept on B's. Split out because several tests open a second link on nodes
 *  `linked()`/`upPair()` already built. */
function openPair(A, B, chans) {
  A.factory.give(chans[0], { weDialed: true, expectPeerId: B.peerId });
  B.factory.give(chans[1]);
}

// ── harness ──────────────────────────────────────────────────────────────────
const { test, assert, summary } = testkit();

const hexOf = (u) => Buffer.from(u).toString("hex");

console.log("\nTransport link hardening (§12.6.1) + concealed handshake (§12.6.2)\n");

await test("baseline: two ends authenticate and exchange frames", async (keep) => {
  const st = keep(await upPair());
  const proto = PROTO;
  const resp = await st.A.request(st.B.peerId, proto, Uint8Array.from([1, 2, 3]));
  assert(resp.length === 3 && resp[2] === 3, `frames not delivered: ${resp.length}`);
  assert(await aUp(st), "the dialer must attribute the link to the peer it dialed");
  assert(await bUp(st), "the acceptor must attribute the link to the caller");
});

await test("a request's deadline is the CALLER's, not a node-wide clock", async (keep) => {
  // Two requests to the same peer on one live link, with different deadlines: the short
  // one must settle on its own schedule. A node-wide silence clock re-arms on ANY frame
  // from the peer, so a request's lifetime would depend on unrelated traffic.
  const st = keep(await upPair(undefined, undefined, { mode: "hang" }));
  const proto = PROTO;
  // A holder that never answers: the deadline is the only thing that can settle these.
  const t0 = Date.now();
  const short = st.A.request(st.B.peerId, proto, Uint8Array.from([1]), 150)
    .then(() => "resolved", () => Date.now() - t0);
  const long = st.A.request(st.B.peerId, proto, Uint8Array.from([2]), 5000)
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
  // for our backlog: a 50 MB PUT queued ~42 MB behind its sockets would cancel every
  // request in the window at its 5 s deadline while the wire moves perfectly.
  const chans = wirePair();
  const st = keep(await linked(chans, {}, { mode: "hang" }));
  const proto = PROTO;
  // A backpressured socket holding 40 KB of this request, draining 4 KB at a time —
  // slower than the 100 ms deadline, so a queue-time clock would fire ~9 times over.
  chans[0].backlog = 40_000;
  const drain = setInterval(() => { chans[0].backlog = Math.max(0, chans[0].backlog - 4_000); }, 40);

  const t0 = Date.now();
  const settled = st.A.request(st.B.peerId, proto, Uint8Array.from([1]), 100)
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
  const ms = await st.A.request(st.B.peerId, proto, Uint8Array.from([1]), 100)
    .then(() => "resolved", () => Date.now() - t0);
  assert(typeof ms === "number", "a stalled request must reject");
  assert(ms < 1500, `a frozen backlog must settle on the deadline, not wait forever (took ${ms}ms)`);
});

await test("handshake messages are exact-length: a trailing byte is refused", async (keep) => {
  // Trailing bytes would ride outside the transcript hash, and so outside what both
  // signatures cover. Exact, not minimum, for every message in the flight.
  // A's two handshake messages, by the width each is accepted at: msg1 and msg3.
  for (const len of [1265, 112]) {
    const chans = wirePair({
      tamper: (b, from) => (from === "A" && b.length === len ? Buffer.concat([Buffer.from(b), Buffer.from([0])]) : b),
    });
    const st = keep(await linked(chans));
    await settle();
    // The responder is the end that reads a tampered message from A, so it is the end
    // that must refuse. (For msg3 the initiator has legitimately authenticated by then:
    // it verified msg2 at 1 RTT, a round trip before the responder authenticates it.)
    assert(!(await bUp(st)), `responder must refuse an over-long ${len}-byte message`);
    if (len === 81) assert(!(await aUp(st)), "a rejected msg1 must leave the initiator unauthenticated");
    st.close();
  }
});

await test("CONCEALMENT: a responder says NOTHING to a caller without the contact secret", async (keep) => {
  // A node that speaks first is a directory service: one connect reads its identity
  // straight off the wire. A caller without the contact secret must get silence — nothing
  // that distinguishes this node from a port that is not listening.
  const chans = wirePair();
  // The caller's OWN contact secret — what a host-announced dial presents — is not the
  // receiver's.
  const st = keep(await linked(chans, { contactSecret: new Uint8Array(32).fill(9) }));
  await settle();
  assert(chans[1].sent.length === 0, `responder emitted ${chans[1].sent.length} message(s); must emit none`);
  assert(!(await aUp(st)) && !(await bUp(st)), "neither end may authenticate");
  assert(!st.b.closed, "a refusal must not even close — the deadline does that later");
});

await test("CONCEALMENT: neither identity appears in cleartext on the wire", async (keep) => {
  const st = keep(await upPair());
  const proto = PROTO;
  await st.A.request(st.B.peerId, proto, Uint8Array.from([9]));
  const wire = [...st.chans[0].sent, ...st.chans[1].sent].join("");
  for (const [name, id] of [["initiator", st.A.peerId], ["responder", st.B.peerId]]) {
    assert(!wire.includes(id), `${name} identity key found in cleartext on the wire`);
  }
});

await test("CONCEALMENT: msg1 carries no identity, so a seized static key reveals none", async (keep) => {
  // Identities are deferred past the ephemeral-ephemeral DH rather than sealed to the
  // responder's static key (as Noise IK does): anything msg1 carries is readable by
  // whoever holds that static key — including an attacker who seizes the node years later
  // and replays a recording.
  const chans = wirePair();
  const st = keep(await linked(chans));
  await until(() => chans[0].sent.length > 0, 4000, "msg1");
  const msg1 = Buffer.from(chans[0].sent[0], "hex");
  assert(msg1.length === 1265, `hybrid msg1 should be 1265 bytes, got ${msg1.length}`);
  assert(!msg1.includes(Buffer.from(st.A.peerId, "hex")), "msg1 must not carry the initiator identity");
});

await test("CONTACT SECRET: the address book alone does not grant a probe", async (keep) => {
  // Every peer holding this node's ADDRESS also holds its static key, so without a contact
  // secret an address-book leak is a probe capability: elicit msg2, confirm which identity
  // lives at that host, and keep doing it after being removed from the member set. With
  // one, an address leak costs the address and nothing more.
  const chans = wirePair();
  // The caller knows B's address (and so its static key) but not B's contact secret — its
  // own presented secret does not match.
  const st = keep(await linked(chans, { contactSecret: new Uint8Array(32).fill(9) }));
  await settle();
  assert(chans[1].sent.length === 0, `outsider drew ${chans[1].sent.length} message(s); must draw none`);
  assert(!(await aUp(st)) && !(await bUp(st)), "a wrong contact secret must not authenticate");
});

await test("FRAME CAP: an unauthenticated peer cannot declare a large frame", async (keep) => {
  // A stranger who knows only host:port must not reserve memory by declaring a big frame
  // and dribbling the body. On a length-framed link the declaration is the 4-byte prefix;
  // one over the pre-auth cap is fatal on sight — the body never arrives and nothing is
  // allocated for it.
  const chans = wirePair({ stream: true });
  const st = keep(await linked(chans));
  chans[1].msg(new Uint8Array([0x00, 0x01, 0x00, 0x00])); // declares 64 KiB, cap is 8 KiB
  await settle();
  assert(st.b.closed, "an over-cap pre-auth declaration must tear the link down");
  assert(!(await bUp(st)), "and it must never have authenticated");
});

await test("FRAME CAP: authentication raises it, before anything can arrive under it", async (keep) => {
  // The raise happens inside becomeAuthed(), ahead of the queued-frame flush: a responder
  // authenticates at msg3 and may put application data on the wire alongside msg4 — which
  // arrives in the same delivery. Raising the cap afterwards would measure that first
  // frame against the handshake bound and kill every connection on its first real exchange.
  const chans = wirePair({ stream: true });
  const st = keep(await linked(chans));
  // The app path, issued before the handshake completes: the guest's own `connecting`
  // pool is keyed by `expectPeerId` on the dial, so an app send to that peer id queues
  // pre-auth rather than failing for want of a link — far over the (pre-auth) cap, but
  // maxFrameBytes is 2 MiB so it is well inside the post-auth one.
  st.A.sendNoReply(st.B.peerId, PROTO, new Uint8Array(64 * 1024).fill(7));
  await until(async () => (await aUp(st)) && (await bUp(st)), 4000, "handshake");
  await settle();
  assert(!st.a.closed && !st.b.closed, "a full-size frame after auth must cross, not close the link");
});

await test("REASSEMBLY: a frame dribbled one byte at a time is still one message", async (keep) => {
  // A dribbled full-size frame is where both naive assemblers get it wrong — quadratic
  // copying if every slice is joined onto one buffer, ~50x the cap in pinned chunks if
  // none are. The framer's merge rule (framing.js): arbitrary slice boundaries in,
  // exactly one message out.
  let armed = false;
  const chans = wirePair({ stream: true, tamper: (b, from) => (from === "A" && armed ? null : b) });
  const st = keep(await linked(chans));
  await until(async () => (await aUp(st)) && (await bUp(st)), 4000, "handshake");
  const proto = PROTO;
  // Above the pre-auth cap, so the dribble must be measured against the RAISED
  // cap (the FRAME CAP tests pin the raise itself).
  const payload = new Uint8Array(48 * 1024).fill(0x5a);
  armed = true; // from here on, drop A's real delivery — it is re-fed manually below
  const before = chans[0].sent.length;
  const respP = st.A.request(st.B.peerId, proto, payload, 8000);
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
  // The merge rule has four paths (fresh accumulator, room, grow, large slice kept as
  // arrived) and slices crossing the threshold in both directions turn a boundary error
  // into a message that never completes or completes wrong.
  let armed = false;
  const chans = wirePair({ stream: true, tamper: (b, from) => (from === "A" && armed ? null : b) });
  const st = keep(await linked(chans));
  await until(async () => (await aUp(st)) && (await bUp(st)), 4000, "handshake");
  const payload = new Uint8Array(96 * 1024);
  for (let i = 0; i < payload.length; i++) payload[i] = (i * 7) & 255;
  armed = true;
  const before = chans[0].sent.length;
  const respP = st.A.request(st.B.peerId, PROTO, payload, 8000);
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
  // The refusal is the first thing `send` does, and LOUD — the app's own `_net` call
  // rejects by name. Measuring after the copies would let a co-resident app naming a
  // 50 MiB payload take the transport realm down before the frame it would have been
  // refused for existed.
  const st = keep(await upPair());
  let refused = "";
  try { await st.A.request(st.B.peerId, PROTO, new Uint8Array(3 * 1024 * 1024)); }
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
  // idle clock a quiet link is held forever with its framer, session keys, timers and
  // buffers. Retired with the authenticated goodbye — our own deliberate shutdown, so the
  // far end reads a clean close, not a truncation.
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
    const r = await st.A.request(st.B.peerId, PROTO, Uint8Array.from([i]));
    assert(r[0] === i, `frame ${i} did not come back — the link died under its idle clock`);
    await settle(40);
  }
  assert(!st.a.closed && !st.b.closed, "a link with traffic on it must not be retired");
});

await test("READY: a second ready() does not strand the first", async (keep) => {
  // A single waiter slot would let the second call overwrite the first, leaving the first
  // caller's promise to the second's timer — or to nothing. It is a LIST, in the transport
  // guest, and each caller holds its own deferred.
  const st = keep(await upPair());
  const [r1, r2] = await Promise.all([
    ready(st.A, 50).then(() => "ok", () => "failed"),
    ready(st.A, 50).then(() => "ok", () => "failed"),
  ]);
  assert(r1 === "ok" && r2 === "ok", `both ready() calls must settle (got ${r1}/${r2})`);
});

await test("SUBKEYS: one master seed, one derived identity, deterministic", async () => {
  const { deriveNodeKey } = await import("../build/core/subkeys.js");
  const master = new Uint8Array(32).fill(5);
  const a = deriveNodeKey(sodium, master), b = deriveNodeKey(sodium, master);
  // Deterministic: a node rebuilds its key at boot from the one secret it stores.
  assert(hexOf(a.publicKey) === hexOf(b.publicKey), "derivation must be deterministic");
  const other = deriveNodeKey(sodium, new Uint8Array(32).fill(6));
  assert(hexOf(a.publicKey) !== hexOf(other.publicKey), "different masters, different keys");
  // The master itself is never a signing key — only a derivation input.
  assert(hexOf(a.privateKey) !== hexOf(master), "the master seed must not be used as a key");
  // ONE key, deliberately: purposes are kept apart by the domain and scope the host binds
  // into every preimage, not by a second keypair (core/subkeys.ts).
  assert(!("channel" in a), "derivation returns the keypair directly");
});

await test("NETWORK KEY: two networks are structurally unable to reach each other", async (keep) => {
  // A boundary, not access control: the network key seeds the transcript, so every derived
  // key and signature preimage differs and the handshake dies at the first message. A
  // staging fleet and a production one can share addresses, configs and operators and
  // still never cross.
  const chans = wirePair();
  const st = keep(await linked(chans,
    { networkKey: new Uint8Array(32).fill(1) },
    { networkKey: new Uint8Array(32).fill(2) }));
  await settle();
  assert(!(await aUp(st)) && !(await bUp(st)), "nodes on different networks must never link");
  assert(chans[1].sent.length === 0, `the wrong network drew ${chans[1].sent.length} message(s)`);
  st.close();

  // Same key on both sides, everything else equal: fine.
  const net = new Uint8Array(32).fill(1);
  const st2 = keep(await upPair(undefined, { networkKey: net }, { networkKey: net }));
  assert((await aUp(st2)) && (await bUp(st2)), "one network must still link normally");
});

await test("CONTACT SECRET: absent means OPEN — the node still conceals identities", async (keep) => {
  // An open node answers anyone, which is a DoS and caller-privacy posture, NOT an
  // identity leak. The four-message ordering does the concealing, so even wide open
  // neither public key crosses the wire.
  const st = keep(await upPair(undefined, { contactSecret: undefined }, { contactSecret: undefined }));
  const wire = [...st.chans[0].sent, ...st.chans[1].sent].join("");
  for (const [name, id] of [["caller", st.A.peerId], ["receiver", st.B.peerId]]) {
    assert(!wire.includes(id), `${name} identity in cleartext on an open node`);
  }
});

await test("CONTACT SECRET: it is the RECEIVER's, and only the receiver's", async (keep) => {
  // Per node, not per deployment and not per pair: a caller must present the secret of the
  // node it is dialing, so a leak costs one node's inbound side and not the network.
  const secretB = new Uint8Array(32).fill(11);
  const secretC = new Uint8Array(32).fill(22);
  const st = keep(await upPair(undefined, { contactSecret: secretB }, { contactSecret: secretB }));
  assert((await aUp(st)) && (await bUp(st)), "the right secret must open the door");
  st.close();

  // The caller's OWN contact secret is node C's, dialing node B.
  const chans = wirePair();
  const st2 = keep(await linked(chans, { contactSecret: secretC }, { contactSecret: secretB }));
  await settle();
  assert(chans[1].sent.length === 0, `another node's secret drew ${chans[1].sent.length} message(s)`);
  assert(!(await aUp(st2)) && !(await bUp(st2)), "another node's secret must not authenticate");
});

await test("CONTACT SECRET: an accept gates on the CURRENT secret — rotation has no re-install", async (keep) => {
  // Rotation updates transport state without reloading or dropping live links.
  const secretB = new Uint8Array(32).fill(11);
  const secretC = new Uint8Array(32).fill(22);
  const aFactory = new InjectedChannels();
  const bFactory = new InjectedChannels();
  const A = await makeTransportHost({ channels: aFactory, contactSecret: secretB });
  const B = await makeTransportHost({ channels: bFactory, contactSecret: secretB });
  A.factory = aFactory;
  B.factory = bFactory;
  keep(async () => { try { A.shell.close(); } catch { /* already down */ } try { B.shell.close(); } catch { /* already down */ } });
  await A.driver.start();
  await B.driver.start();
  // A spy for "the bundle was never re-loaded": the rotation below must not reach it.
  let loads = 0;
  const origLoad = B.shell.loadBundleBlob;
  B.shell.loadBundleBlob = async (blob, opts) => { loads++; return origLoad(blob, opts); };

  // The boot-time secret opens the door on both sides.
  const c1 = wirePair();
  openPair(A, B, c1);
  await until(async () => (await linkedTo(A, B.peerId)) && (await linkedTo(B, A.peerId)),
    4000, "boot-time secret");

  // Rotate B's gate; A still presents the OLD value. The responder says nothing at all —
  // checked on THIS pair's own wire, since the node-level peer set already reads "linked"
  // from the surviving c1 link and cannot tell a new attempt's outcome apart from it.
  await contact(B, secretC);
  const c2 = wirePair();
  openPair(A, B, c2);
  await settle();
  assert(c2[1].sent.length === 0, `the stale secret drew ${c2[1].sent.length} message(s)`);

  // A now presents the NEW value too: the door opens again — checked as wire progress on
  // c3 (both ends complete their two-message half of the handshake), for the same reason
  // the failure case above is checked on the wire rather than the aggregate peer set —
  // and the guest never re-loaded to get it.
  await contact(A, secretC);
  const c3 = wirePair();
  openPair(A, B, c3);
  await until(() => c3[0].sent.length >= 2 && c3[1].sent.length >= 2, 4000, "rotated secret handshake");
  await settle();
  assert(loads === 0, `a secret rotation must not re-load the transport (loaded ${loads} times)`);
  // The link that authenticated under the old secret is untouched by a rotation.
  assert(!c1[0].dead && !c1[1].dead, "a live link must not be torn down by a rotation");
});

await test("CONTACT SECRET: the rotation is the host's, and takes 32 bytes or none", async (keep) => {
  // Invalid lengths fail loudly; app callers cannot rotate deployment credentials.
  const A = await makeTransportHost({ channels: new InjectedChannels(), contactSecret: CONTACT });
  keep({ close() { try { A.shell.close(); } catch { /* already down */ } } });
  let refused = "";
  try { await contact(A, Uint8Array.of(1, 2, 3)); } catch (e) { refused = String(e); }
  assert(refused.includes("32 bytes"), `a short secret must be refused, got ${refused || "no error"}`);
  // Use a valid payload shape to isolate the caller check.
  const arg = new Uint8Array(36);
  arg[3] = 32;
  let appRefused = "";
  try { await A.op("contact", arg); } catch (e) { appRefused = String(e); }
  assert(appRefused.includes("not an app"),
    `an app naming the rotation must be refused, got ${appRefused || "no error"}`);
});

await test("SEVER: driver.reset() kills live links and keeps the binding owned", async (keep) => {
  // The platform's room/secret switch closes every live socket (a rotation is a rotation:
  // links authenticated under the old value go). The bundle occupant is NOT replaced — this
  // is the operation a slot handover arrives at, run directly — so afterwards a new link
  // opens and authenticates without a re-install.
  const st = keep(await upPair());
  const chans = st.chans;
  st.A.driver.reset();
  await until(() => st.b.closed, 3000, "the far end hears the links die");
  await settle();
  assert(chans[0].dead && chans[1].dead, "both sockets must be closed at the driver level");
  assert(st.A.driver.available(), "the raw-link binding must still be owned after a sever");

  const c2 = wirePair();
  openPair(st.A, st.B, c2);
  await until(async () => (await aUp(st)) && (await bUp(st)), 4000, "re-link after a sever");
  assert(st.B.driver.available(), "the acceptor's binding must also still be owned");
});

await test("CONTACT SECRET: it never appears on the wire", async (keep) => {
  // It is mixed into the key schedule, never transmitted — which is also what makes it a
  // quantum hedge: an adversary who records today and breaks X25519 later still needs a
  // value that was never sent.
  const st = keep(await upPair());
  const wire = [...st.chans[0].sent, ...st.chans[1].sent].join("");
  assert(!wire.includes(hexOf(CONTACT)), "contact secret leaked onto the wire");
});

await test("LEAK FIX: a link that closes itself mid-handshake still reports down", async (keep) => {
  // Two nodes sharing one identity, so B sees its own key in A's msg3: the reflection
  // guard (ake.js openIdentity, `bytesCompare(id, ownPk)`) refuses it — but a refusal
  // mid-handshake is concealment, so it STALLS (silently) rather than closing outright,
  // exactly like a wrong contact secret. Nobody ever completes the handshake, so what
  // actually closes each side is its own ordinary handshake deadline firing abort() — a
  // SELF-close from inside the guest, not a host-driven one (the host cannot ask a link to
  // close any more). Shortened here so the test does not wait out the real default.
  // `onLinkClosed` must still fire for a link that never authenticated, which is the leak
  // this pins: a channel whose close() merely set `dead` without ever firing onClose would
  // leave such a link stuck in the pre-auth bookkeeping forever.
  const id = generateKeyPair();
  const chans = wirePair();
  const st = keep(await linked(chans,
    { identity: id, transportConfig: { handshakeTimeoutMs: 80 } },
    { identity: id, transportConfig: { handshakeTimeoutMs: 80 } }));
  await until(() => st.a.closed, 3000, "the self-close MUST reach onLinkClosed (this is the leak)");
  assert(st.a.reason === CLOSE_REASON.HANDSHAKE, `a link that never authenticated should read HANDSHAKE, got ${st.a.reason}`);
  assert(!(await aUp(st)) && !(await bUp(st)), "a node must not link to itself");
});

await test("handshake deadline closes a link that never speaks", async (keep) => {
  const chans = wirePair(); // no peer link opened: nothing ever replies
  const factory = new InjectedChannels();
  let closed = false;
  const A = await makeTransportHost({
    channels: factory, contactSecret: CONTACT,
    transportConfig: { handshakeTimeoutMs: 60 },
    onLinkClosed: () => { closed = true; },
  });
  keep({ close() { try { A.shell.close(); } catch { /* down */ } } });
  await A.driver.start();
  factory.give(chans[0], { weDialed: true, expectPeerId: A.peerId });
  await until(() => closed, 3000, "the deadline to close the link and notify");
  assert(!(await linkedTo(A, A.peerId)), "must not authenticate");
});

await test("rekey: the ratchet keeps frames flowing across an epoch boundary", async (keep) => {
  const st = keep(await upPair(undefined,
    { transportConfig: { rekeyAfterFrames: 4 } },
    { transportConfig: { rekeyAfterFrames: 4 } }));
  const proto = PROTO;
  for (let i = 0; i < 14; i++) {
    const r = await st.A.request(st.B.peerId, proto, Uint8Array.from([i]));
    assert(r[0] === i, `frame ${i} came back as ${r[0]} — ordering broke across a ratchet`);
  }
  assert(!st.a.closed && !st.b.closed, "link must survive rekeying");
});

await test("rekey: mismatched intervals desync (the must-match warning is real)", async (keep) => {
  const chans = wirePair();
  const st = keep(await linked(chans,
    { transportConfig: { rekeyAfterFrames: 4 } },
    { transportConfig: { rekeyAfterFrames: 8 } }));
  await until(async () => (await aUp(st)) && (await bUp(st)), 4000, "handshake");
  for (let i = 0; i < 8; i++) {
    st.A.sendNoReply(st.B.peerId, PROTO, Uint8Array.from([i]));
    await settle(20);
  }
  await until(() => st.b.closed, 3000, "a desync must tear the link down, not silently corrupt");
});

await test("goodbye: a clean close is distinguishable from a truncation", async (keep) => {
  // The close is now driven by A's idle clock — the host cannot ask a link to close any
  // more, so the deliberate-close half of this pin has to arrive through the same
  // mechanism IDLE's tests use: silence for the timeout, then the authenticated goodbye.
  const st = keep(await upPair(undefined, { linkIdleTimeoutMs: 60 }));
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
  // A's idle clock retires the link once the one real request has finished — given
  // headroom so the request settles well before the timeout fires.
  const st = keep(await upPair(undefined, { linkIdleTimeoutMs: 150 }));
  const proto = PROTO;
  await st.A.request(st.B.peerId, proto, new TextEncoder().encode("real"));
  await until(() => st.b.closed, 3000, "the idle clock to retire the link");
  await settle(100);
  // What the far APP was handed, asked of the app itself — there is no host-side sink
  // to record it in any more.
  const seen = (await st.B.seen()).map((b) => Buffer.from(b).toString());
  assert(seen.length === 1 && seen[0] === "real", `goodbye leaked into the app: ${JSON.stringify(seen)}`);
});

await test("goodbye: the CLOSER reports a local shutdown, not a truncation", async (keep) => {
  // The trap this pins: defining wasTruncated() as `authed && !peerSaidGoodbye` is true on
  // our own side of every deliberate close — we send the farewell and never get one back —
  // and the double-connect tie-break closes links routinely, so that definition would flag
  // a routine event as a cut stream.
  const st = keep(await upPair(undefined, { linkIdleTimeoutMs: 60 }));
  await until(() => st.a.closed && st.b.closed, 3000, "both ends to close");
  assert(st.a.reason === CLOSE_REASON.LOCAL, `closer should read LOCAL, got ${st.a.reason}`);
  assert(st.b.reason === CLOSE_REASON.CLEAN, `peer should read CLEAN, got ${st.b.reason}`);
});

await test("goodbye: an injected junk record must NOT produce a farewell", async (keep) => {
  // The attack the close/abort split exists to stop. An in-path attacker corrupts one
  // record A->B; B cannot decrypt it and tears the link down — but if that teardown
  // emitted an end-of-stream record, B would hand A a genuine, correctly-keyed farewell
  // and A would read an attacker-chosen moment as a clean shutdown. The attacker never
  // forges anything: they induce the victim to say goodbye.
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
  st.A.sendNoReply(st.B.peerId, PROTO, new TextEncoder().encode("payload"));
  await until(() => st.a.closed && st.b.closed, 3000, "both ends to tear down");
  assert(corrupted, "the test did not actually corrupt a record");
  assert(st.b.reason === CLOSE_REASON.ABORTED, `victim should read ABORTED, got ${st.b.reason}`);
  assert(st.a.reason === CLOSE_REASON.TRUNCATED, `far end should read TRUNCATED, got ${st.a.reason}`);
});

await test("a graceful close asks the transport to flush; an abort does not", async (keep) => {
  // The graceful half is now the idle clock's own close, not an explicit call.
  const st = keep(await upPair(undefined, { linkIdleTimeoutMs: 60 }));
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
  // A TCP socket destroyed rather than ended drops the record it was just handed, so the
  // whole mechanism silently no-ops on the transport most likely to carry it. This fails
  // unless close() both writes the record AND asks for a graceful teardown. The close
  // itself is the idle clock's now.
  const st = keep(await upPair({ destructive: true }, { linkIdleTimeoutMs: 60 }));
  await until(() => st.b.closed, 3000, "the farewell to arrive");
  assert(st.b.reason === CLOSE_REASON.CLEAN, `expected CLEAN, got ${st.b.reason} (the farewell was discarded)`);
});

await test("WHITELIST: absent by default, and an absent hook admits everyone", async (keep) => {
  // The hook is a seam, not a requirement: a deployment that sets nothing gets a network
  // that links to anyone who holds the contact secret, which is the sane default.
  const st = keep(await upPair());
  assert((await aUp(st)) && (await bUp(st)), "no whitelist configured must mean admit-all");
});

await test("GUARD: a refused caller learns NOTHING about the receiver", async (keep) => {
  // What the second round trip bought: the caller names itself at msg3, before the receiver
  // has said anything about itself, so a caller off the whitelist is turned away without
  // learning whether the identity it dialed is even here. Under the OLD 1-RTT ordering the
  // receiver signed its identity at msg2 — before it knew who was calling — so any
  // whitelist member could confirm who lived at any address.
  //
  // This caught a real regression when the suite was ported: the gate was first asked from
  // becomeAuthed(), which the accepting end reaches only AFTER msg4 already put its
  // identity and signature on the wire. The gate now runs in the guest's onMsg3, before
  // msg4 is built, and a concealed refusal is silence rather than a close.
  const chans = wirePair();
  // An empty-but-present list: the receiver admits nobody. The lint is the transport's own
  // now (transport/src `admits`), read from its capability rather than asked of the
  // host per link — see the note there for why the host was never gating this anyway.
  const st = keep(await linked(chans, {}, { admitPeers: [new Uint8Array(32).fill(1)] }));
  await settle();
  assert(!(await bUp(st)), "a refused caller must not be authenticated by the receiver");
  // One message back (msg2, an ephemeral and a contact proof), then silence. The
  // receiver's identity and signature must never go out.
  assert(chans[1].sent.length === 1, `refused caller drew ${chans[1].sent.length} messages, want 1 (msg4 leaked)`);
  assert(!chans[1].sent.join("").includes(st.B.peerId),
    "the receiver revealed its identity to a caller it then refused");
  assert(!(await aUp(st)), "a refused caller must not authenticate");
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
  st.A.sendNoReply(st.B.peerId, PROTO, new TextEncoder().encode("tampered"));
  await until(() => st.b.closed, 3000, "a forged record must close the link");
  assert((await st.B.seen()).length === 0, "a forged record must not be delivered");
});

// ── §12.10: a slot's own answer reaches its loader through onInbound ────────────
// Dispatch is one claim → slot map, with no second table an embedder's own name could
// occupy — but the one thing a table never gave an embedder is a view of what its own app
// just answered: a peer-inbound frame's reply is consumed by the wire on the way back out.
// `LoadBundleOptions.onInbound` is that one seam — scoped to the load that named it, not
// the shell, so there is no table, no owner and no name to contest.
await test("a peer-inbound answer reaches the loader through onInbound", async (keep) => {
  const st = keep(await upPair());
  // A second, tiny app on B: it claims its own protocol and answers by flipping every
  // byte, so the response is trivially distinct from the request that produced it.
  const guestSource = `
    function handle(arg) {
      const payload = arg.subarray(32);
      const out = new Uint8Array(payload.length);
      for (let i = 0; i < payload.length; i++) out[i] = payload[i] ^ 0xff;
      return out;
    }
  `;
  const { blob } = authorBundle(sodium, st.B.appAuthor, {
    app: "watcher", version: 1, protocols: ["watch/v1"],
    modules: [], guestSource, guestRequires: [],
  });
  const seen = [];
  const watcher = await st.B.shell.loadBundleBlob(blob, {
    onInbound: (claim, from, answer) => seen.push({ claim, from: Buffer.from(from).toString("hex"), answer }),
  });

  const resp = await st.A.request(st.B.peerId, "watch/v1", Uint8Array.from([1, 2, 3]));
  assert(resp.length === 3 && resp[0] === 0xfe && resp[1] === 0xfd && resp[2] === 0xfc,
    `the caller must still get the app's own answer untouched, got ${[...resp]}`);
  assert(seen.length === 1, "onInbound must fire exactly once per peer-inbound answer");
  assert(seen[0].claim === "watch/v1", "…named the claim the frame arrived on");
  assert(seen[0].from === st.A.peerId,
    "…and the AUTHENTICATED sender, exactly as dispatch attributes it");
  assert(bytesEqual(seen[0].answer, resp), "…carrying exactly the bytes the caller received");

  // The host loopback path already holds its own return value directly — onInbound is
  // wired for the peer path alone, so invoking the SAME slot as the host must not fire it.
  await watcher.invoke(Uint8Array.from([9, 9]));
  assert(seen.length === 1, "a host loopback invoke of the same slot must not fire onInbound");
});

// A peer names the id the TRANSPORT ITSELF claims. Nothing about the delivery return reads
// the protocol bytes — the transport merely returns what it decoded — so the refusal has to
// be the routing's: the transport declares `_net` under `services`, never `protocols`, and
// inbound delivery answers only what is in the latter (§12.10). Were it reachable, this
// frame would land in the transport realm's own `handle` with the sender's key as caller
// id, which `APP_OPS` admits — `peers` would enumerate the node's links.
await test("a peer cannot reach a bundle's local service claim, the transport's included", async (keep) => {
  const st = keep(await upPair());
  const opEnvelope = (op) => {
    const n = Buffer.from(op, "utf8");
    return Uint8Array.from([n.length, ...n]);
  };
  const peers = await st.A.request(st.B.peerId, "_net", opEnvelope("peers"));
  assert(peers.length === 0,
    `the transport's own claim must not answer a peer, got ${peers.length} bytes: ${hexOf(peers)}`);
  // Not merely unanswered — never delivered: the ordinary claim still works on the same
  // link, so this is a routing rule and not a link that stopped carrying frames.
  const ordinary = await st.A.request(st.B.peerId, PROTO, Uint8Array.from([4, 5]));
  assert(ordinary.length === 2 && ordinary[1] === 5, "the app's own id still answers over the same link");
});

// ── delivery, when one read carries several requests ─────────────────────────
// The link occupant hands each request it decodes to the shell's claim table as its own
// `link/deliver` call (§12.10), and that is where attribution is decided: the occupant
// names the authenticated sender, because it is the one that saw the plaintext. Several
// requests per socket read is the ORDINARY case on a byte stream, and one call each is
// what keeps them separate — nothing packs them into a shared buffer whose framing a
// peer's own payload bytes could be read as.
await test("DELIVERY: two pipelined requests in ONE read are two correctly attributed deliveries", async (keep) => {
  // Stream framing permits one read to contain multiple messages.
  const st = keep(await upPair({ stream: true }));
  const first = Uint8Array.from([0x11, 0x22, 0x33]);
  // The second request's payload names another claim and another sender in the shape the
  // retired batch codec framed a record in. It is now just bytes — which is the property
  // under test: a payload is never anything the delivery path parses.
  const forgedAttribution = new Uint8Array(32).fill(0xfe);
  const forgedClaim = Buffer.from("admin/grant", "utf8");
  const second = Uint8Array.from([
    1, 0, 0, 0, 0, forgedClaim.length, ...forgedClaim,
    0, 0, 0, 32, ...forgedAttribution,
    0, 0, 0, 5, 0x41, 0x41, 0x41, 0x41, 0x41,
  ]);

  // Hold A's writes, issue both requests, then deliver them as one read.
  st.chans[0].hold();
  const sends = [
    st.A.sendNoReply(st.B.peerId, PROTO, first),
    st.A.sendNoReply(st.B.peerId, PROTO, second),
  ];
  await until(() => st.chans[0].held.length >= 2, 4000, "both requests written");
  const coalesced = st.chans[0].flush();
  assert(coalesced === 2, `the test must coalesce two writes into one read, got ${coalesced}`);
  await Promise.all(sends);

  // `until` does not await its predicate, and `seen` is an invoke — so poll it directly.
  let seen = [], from = [];
  for (const started = Date.now(); Date.now() - started < 4000;) {
    seen = await st.B.seen();
    if (seen.length >= 2) break;
    await settle(10);
  }
  from = await st.B.from();
  assert(seen.length === 2, `exactly two deliveries, got ${seen.length}`);
  // Each payload is its own, whole: neither swallowed the record behind it.
  assert(hexOf(seen[0]) === hexOf(first), `first payload intact, got ${hexOf(seen[0])}`);
  assert(hexOf(seen[1]) === hexOf(second), `second payload intact, got ${hexOf(seen[1])}`);
  // And both are attributed to the peer that actually sent them — never to the key the
  // second payload names, which is the whole point of the crafted bytes above.
  assert(from.length === 2 && from.every((f) => f === st.A.peerId),
    `both deliveries must be attributed to the sending peer, got ${from.join(", ")}`);
  assert(!from.includes(hexOf(forgedAttribution)),
    "a payload's own bytes must never become another delivery's attribution");
});

// ── the transport guest's caller boundary ────────────────────────────────────
// The platform events (`linkBytes`, `linkClosed`, …) are the host's alone; `send` and
// `peers` are an app's to name, because both are questions about the app's own traffic. An
// app that could inject link bytes could forge traffic from a peer, so the line matters in
// both directions.

await test("CALLER BOUNDARY: an app may name `peers`, but not a platform event", async (keep) => {
  const st = keep(await upPair());
  await until(async () => (await st.B.peers()).length > 0, 4000, "B's link to A");
  // `peers` through the APP's seam — a cross-realm call carrying the app's key, not the
  // host's 32 zero bytes. This is the path seedstore's guest takes to place replicas.
  const raw = await st.B.op("peers");
  assert(raw.length === 32 && hexOf(raw) === st.A.peerId,
    "an app asking `peers` must get the authenticated set back");
  // `linkBytes` through the same seam must be refused by NAME, not silently ignored.
  let refused = "";
  try { await st.B.op("linkBytes", new Uint8Array(8)); }
  catch (e) { refused = String(e); }
  assert(refused.includes("the host's, not an app's"),
    `an app naming a platform event must be refused, got ${refused || "no error"}`);
});

// A reply applies only to the captured channel (§12.10).
await test("DRIVER BOUNDARY: the down report names its own socket, once", async (keep) => {
  class ManualChannel {
    data = null;
    closed = null;
    send() {}
    onData(cb) { this.data = cb; }
    onClose(cb) { this.closed = cb; }
    // Deliberately does not fire `onClose`: this is native's local-close behavior. The
    // driver must synthesize its own later event and still notify exactly once.
    close() {}
    emit(bytes = Uint8Array.of(1)) { this.data?.(bytes); }
    fail() { this.closed?.(); }
  }
  class ThrowingChannel extends ManualChannel {
    stops = 0;
    send() { throw new Error("partial backend write"); }
    close() { this.stops++; }
  }

  // The driver's own `[opLen u8][op]` head, plus the one field every event below carries:
  // a u32 link id. `linkOpen`'s payload has more behind it, but the id is always first.
  const readU32 = (b, off) => ((b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3]) >>> 0;
  const events = [];
  const downs = [];
  const factory = new InjectedChannels();
  const driver = keep(new TransportHost(
    { channels: factory, onLinkClosed: (linkId, reason) => downs.push({ linkId, reason }) },
    {},
  ));
  driver.activate(async (payload) => {
    const n = payload[0];
    const op = new TextDecoder().decode(payload.subarray(1, 1 + n));
    const rest = payload.subarray(1 + n);
    if (op === "linkBytes" || op === "linkOpen") events.push({ op, linkId: readU32(rest, 0) });
    if (op === "linkClosed") { events.push({ op, linkId: readU32(rest, 0) }); return Uint8Array.of(CLOSE_REASON.LOCAL); }
    return new Uint8Array();
  });
  await driver.start();

  // Two accepted channels: give() runs register()+announce() synchronously, so the
  // linkOpen event (and this test's link id) is already in `events` when it returns.
  const aChannel = new ManualChannel();
  factory.give(aChannel);
  const aLinkId = events.find((e) => e.op === "linkOpen").linkId;
  events.length = 0;
  const bChannel = new ManualChannel();
  factory.give(bChannel);
  const bLinkId = events.find((e) => e.op === "linkOpen").linkId;
  events.length = 0;

  // 1) Bytes on one channel produce exactly one linkBytes, naming THAT channel's link id.
  aChannel.emit();
  await settle(0);
  assert(events.length === 1 && events[0].op === "linkBytes" && events[0].linkId === aLinkId,
    `A's bytes must produce exactly one linkBytes for A's own link id, got ${JSON.stringify(events)}`);
  assert(!events.some((e) => e.linkId === bLinkId), "B's channel must not have produced an event");
  events.length = 0;

  // 2) A host-driven close reports down exactly once with the occupant's reason, even
  // though ManualChannel.close() deliberately fires no callback of its own — the driver
  // must synthesize the event. A later backend callback racing it (channel.fail(), the
  // way a real socket's own close would arrive) must not report a second time: this is the
  // idempotence the deleted "explicit close() fires onClose exactly once" test covered,
  // now at the driver's own close/backend-callback boundary instead of a per-link handle.
  driver.rawNet().close(aLinkId, false);
  await until(() => downs.length === 1, 1000, "A's close to report down");
  assert(downs[0].linkId === aLinkId && downs[0].reason === CLOSE_REASON.LOCAL,
    `A's close must report down once with LOCAL, got ${JSON.stringify(downs)}`);
  aChannel.fail();
  await settle();
  assert(downs.length === 1, "a backend callback racing a host-driven close must not report down twice");

  // 3) Not every RawLink is a BufferedChannel. The driver is the final containment
  // boundary: a backend send that throws after emitting bytes must be failed and removed,
  // never left available for another write that would follow a truncated LENGTH frame.
  const cChannel = new ThrowingChannel();
  factory.give(cChannel);
  const cLinkId = events.find((e) => e.op === "linkOpen").linkId;
  events.length = 0;
  driver.rawNet().send(cLinkId, Uint8Array.of(1, 2, 3));
  await until(() => downs.some((d) => d.linkId === cLinkId), 1000, "the throwing channel's close to report down");
  assert(cChannel.stops === 1, `a throwing raw send must close the backend once, got ${cChannel.stops}`);
  const cDowns = downs.filter((d) => d.linkId === cLinkId);
  assert(cDowns.length === 1 && cDowns[0].reason === CLOSE_REASON.LOCAL,
    `the throwing channel's link must be failed exactly once with LOCAL, got ${JSON.stringify(cDowns)}`);
});

await test("default caps are sane", async () => {
  const defaults = verifyBundle(sodium, transportBlob).manifest.guest.config;
  assert(defaults.maxAuthedLinks > 0 && defaults.maxAuthedLinks <= 4096,
    "the authenticated-link budget should be a real bound");
  assert(defaults.linkIdleTimeoutMs >= 60_000,
    "the idle clock must be generous enough that a quiet-but-live link is not churned");
  assert(defaults.maxHalfOpenUnverified > 0 && defaults.maxHalfOpenUnverified <= 8192,
    "unverified cap should be a real bound");
  assert(defaults.maxHalfOpenVerified > 0 && defaults.maxHalfOpenVerified <= 4096,
    "verified cap should be a real bound");
  assert(defaults.maxHalfOpenPerSource > 0 && defaults.maxHalfOpenPerSource < defaults.maxHalfOpenUnverified,
    "the per-source cap must bound one source well below the whole budget");
  // The three signed numbers this rework moved out of per-link options and into the
  // node-level, signed transport config.
  assert(defaults.handshakeTimeoutMs > 0, "the dialer's whole-handshake deadline must be a real bound");
  assert(defaults.unverifiedTimeoutMs > 0 && defaults.unverifiedTimeoutMs <= defaults.handshakeTimeoutMs,
    "an accept's clock must be the tighter one — it starts believing nothing at all");
  assert(defaults.rekeyAfterFrames > 0 && defaults.rekeyAfterFrames >= (1 << 16),
    "the rekey interval should be comfortably large, not a per-connection tripwire");
});

summary("transport link hardening");
