// transport-link.test.mjs — regression tests for the §12.6.1 link hardening and the
// §12.6.2 concealed handshake. The link logic lives in the SIGNED transport bundle, where
// no test can reach in and hold an object, so each property is pinned where it ships —
// through the real host stack (shell → TransportHost → guest realm) with an instrumented
// in-process channel for the socket. The half-open budgets are the exception (a
// host-managed link spends none), so those tests live in transport-load.test.mjs.

import {
  makeTransportHost, generateKeyPair, sodium, LoopbackChannels, CLOSE_REASON, until, PROTO,
  authorBundle, bootShell, TransportHost, ModuleTable, FreshnessMarks, createSafeRealm,
  transportBlob, transportAuthor, transportPolicy,
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
function wirePair({ addrA = "10.0.0.1", addrB = "10.0.0.2", tamper, destructive, framing = 0 } = {}) {
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
 *  `aOpts`/`bOpts` go to the shells (identity, contactSecret, networkKey, admitPeer);
 *  `linkOpts` go to both openLink calls, with three extras of its own: `dialSecret`
 *  overrides what the DIALER presents (a test can hold the wrong secret), and `a`/`b`
 *  carry per-side options for cases where the two ends deliberately disagree. */
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
  // acceptor gates on its own, which came from its shell configuration.
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
  // Two requests to the same peer on one live link, with different deadlines: the short
  // one must settle on its own schedule. A node-wide silence clock re-arms on ANY frame
  // from the peer, so a request's lifetime would depend on unrelated traffic.
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
  // Identities are deferred past the ephemeral-ephemeral DH rather than sealed to the
  // responder's static key (as Noise IK does): anything msg1 carries is readable by
  // whoever holds that static key — including an attacker who seizes the node years later
  // and replays a recording.
  const chans = wirePair();
  const st = keep(await linked(chans));
  await until(() => chans[0].sent.length > 0, 4000, "msg1");
  const msg1 = Buffer.from(chans[0].sent[0], "hex");
  assert(msg1.length === 81, `msg1 should be 81 bytes, got ${msg1.length}`);
  assert(!msg1.includes(Buffer.from(st.A.driver.peerId, "hex")), "msg1 must not carry the initiator identity");
});

await test("CONTACT SECRET: the address book alone does not grant a probe", async (keep) => {
  // Every peer holding this node's ADDRESS also holds its static key, so without a contact
  // secret an address-book leak is a probe capability: elicit msg2, confirm which identity
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
  // A stranger who knows only host:port must not reserve memory by declaring a big frame
  // and dribbling the body. On a length-framed link the declaration is the 4-byte prefix;
  // one over the pre-auth cap is fatal on sight — the body never arrives and nothing is
  // allocated for it.
  const chans = wirePair({ framing: 1 });
  const st = keep(await linked(chans));
  chans[1].msg(new Uint8Array([0x00, 0x01, 0x00, 0x00])); // declares 64 KiB, cap is 8 KiB
  await settle();
  assert(st.b.closed, "an over-cap pre-auth declaration must tear the link down");
  assert(!st.b.authed, "and it must never have authenticated");
});

await test("FRAME CAP: authentication raises it, before anything can arrive under it", async (keep) => {
  // The raise happens inside becomeAuthed(), ahead of the queued-frame flush: a responder
  // authenticates at msg3 and may put application data on the wire alongside msg4 — which
  // arrives in the same delivery. Raising the cap afterwards would measure that first
  // frame against the handshake bound and kill every connection on its first real exchange.
  const chans = wirePair({ framing: 1 });
  const st = keep(await linked(chans));
  st.aLink.send(new Uint8Array(64 * 1024).fill(7)); // queued pre-auth, far over the cap
  await until(() => st.a.authed && st.b.authed, 4000, "handshake");
  await settle();
  assert(!st.a.closed && !st.b.closed, "a full-size frame after auth must cross, not close the link");
});

await test("REASSEMBLY: a frame dribbled one byte at a time is still one message", async (keep) => {
  // A dribbled full-size frame is where both naive assemblers get it wrong — quadratic
  // copying if every slice is joined onto one buffer, ~50x the cap in pinned chunks if
  // none are. The framer's merge rule (framing.js): arbitrary slice boundaries in,
  // exactly one message out.
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
  // The merge rule has four paths (fresh accumulator, room, grow, large slice kept as
  // arrived) and slices crossing the threshold in both directions turn a boundary error
  // into a message that never completes or completes wrong.
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
  // The refusal is the first thing `send` does, and LOUD — the app's own `_net` call
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
    const r = await st.A.request(st.B.driver.peerId, PROTO, Uint8Array.from([i]));
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
  // key and signature preimage differs and the handshake dies at the first message. A
  // staging fleet and a production one can share addresses, configs and operators and
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

/** One transport host whose contact secret is a LIVE getter — the shape a platform with a
 *  rotating gate has (§12.6.3). Deliberately parallels makeTransportHost in the pieces a
 *  test needs: an options object's value would be copied at construction, and the point is
 *  that the driver RE-READS the secret when it opens a link. */
async function makeTransportHostWithGetter(getSecret) {
  const identity = generateKeyPair();
  const driver = new TransportHost({
    identity,
    channels: new LoopbackChannels(),
    get contactSecret() { return getSecret(); },
  });
  const { shell } = await bootShell({
    sodium, identity, modules: new ModuleTable(), freshnessStore: new FreshnessMarks(),
    fs: false, transport: driver, transportBundle: transportBlob,
    createRealm: async (o) => createSafeRealm(o), admit: transportPolicy(transportAuthor()),
  });
  await shell.loadBundleBlob(transportBlob);
  return { shell, driver, identity };
}

/** One host-managed link opened from both ends, with the dialer's presented secret.
 *  Takes the NODES (harness shape) so the pair sits symmetric with `linked()`. */
function openPair(A, B, chans, dialSecret) {
  const st = { a: { authed: false, closed: false, reason: null }, b: { authed: false, closed: false, reason: null } };
  A.driver.openLink({
    channel: chans[0], weDialed: true, expectPeerId: B.driver.peerId,
    contactSecret: dialSecret, source: chans[0].remoteAddr,
    onAuth: () => { st.a.authed = true; },
    onClose: (_id, reason) => { st.a.closed = true; st.a.reason = reason; },
  });
  B.driver.openLink({
    channel: chans[1], weDialed: false, source: chans[1].remoteAddr,
    onAuth: () => { st.b.authed = true; },
    onClose: (_id, reason) => { st.b.closed = true; st.b.reason = reason; },
  });
  return st;
}

await test("CONTACT SECRET: an accept gates on the CURRENT secret — rotation has no re-install", async (keep) => {
  // The driver re-reads its contact secret when it opens a link and delivers it per link in
  // `linkOpen`, so rotating the GETTER rotates the accept gate instantly; the guest's
  // boot-time init facts are only the fallback. Before this, the gate was the boot-time
  // snapshot and a rotation cost a transport re-load, killing every live link for a
  // credential change.
  const secretB = new Uint8Array(32).fill(11);
  const secretC = new Uint8Array(32).fill(22);
  let current = secretB;
  const A = await makeTransportHost({ channels: new LoopbackChannels(), contactSecret: CONTACT });
  const B = await makeTransportHostWithGetter(() => current);
  keep(async () => { try { A.shell.close(); } catch { /* already down */ } try { B.shell.close(); } catch { /* already down */ } });
  // A spy for "the bundle was never re-loaded": the rotation below must not reach it.
  let loads = 0;
  const origLoad = B.shell.loadBundleBlob;
  B.shell.loadBundleBlob = async (blob, opts) => { loads++; return origLoad(blob, opts); };

  // The boot-time secret opens the door.
  const c1 = wirePair();
  const s1 = openPair(A, B, c1, secretB);
  await until(() => s1.a.authed && s1.b.authed, 4000, "boot-time secret");

  // Rotate. The OLD secret is now a wrong secret: the responder says nothing at all.
  current = secretC;
  const c2 = wirePair();
  const s2 = openPair(A, B, c2, secretB);
  await settle();
  assert(c2[1].sent.length === 0, `the stale secret drew ${c2[1].sent.length} message(s)`);
  assert(!s2.a.authed && !s2.b.authed, "the stale secret must not authenticate");

  // The NEW secret opens — and the guest never re-loaded to get it.
  const c3 = wirePair();
  const s3 = openPair(A, B, c3, secretC);
  await until(() => s3.a.authed && s3.b.authed, 4000, "rotated secret");
  assert(loads === 0, `a secret rotation must not re-load the transport (loaded ${loads} times)`);
  // The link that authenticated under the old secret is untouched by a rotation.
  assert(s1.a.authed && s1.b.authed, "a live link must not be torn down by a rotation");
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
  const s2 = openPair(st.A, st.B, c2, CONTACT);
  await until(() => s2.a.authed && s2.b.authed, 4000, "re-link after a sever");
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

await test("LEAK FIX: a self-closing link still fires onClose", async (keep) => {
  // The reflection guard closes the link from inside the handshake, and a channel whose
  // close() set `dead` without firing onClose would leave the link in the pre-auth
  // bookkeeping forever. Two nodes share one identity, so B sees its own key in A's msg3.
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
  // The trap this pins: defining wasTruncated() as `authed && !peerSaidGoodbye` is true on
  // our own side of every deliberate close — we send the farewell and never get one back —
  // and the double-connect tie-break closes links routinely, so that definition would flag
  // a routine event as a cut stream.
  const st = keep(await upPair());
  st.aLink.close();
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
  // A TCP socket destroyed rather than ended drops the record it was just handed, so the
  // whole mechanism silently no-ops on the transport most likely to carry it. This fails
  // unless close() both writes the record AND asks for a graceful teardown.
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

  const resp = await st.A.request(st.B.driver.peerId, "watch/v1", Uint8Array.from([1, 2, 3]));
  assert(resp.length === 3 && resp[0] === 0xfe && resp[1] === 0xfd && resp[2] === 0xfc,
    `the caller must still get the app's own answer untouched, got ${[...resp]}`);
  assert(seen.length === 1, "onInbound must fire exactly once per peer-inbound answer");
  assert(seen[0].claim === "watch/v1", "…named the claim the frame arrived on");
  assert(seen[0].from === st.A.driver.peerId,
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
  const peers = await st.A.request(st.B.driver.peerId, "_net", opEnvelope("peers"));
  assert(peers.length === 0,
    `the transport's own claim must not answer a peer, got ${peers.length} bytes: ${hexOf(peers)}`);
  // Not merely unanswered — never delivered: the ordinary claim still works on the same
  // link, so this is a routing rule and not a link that stopped carrying frames.
  const ordinary = await st.A.request(st.B.driver.peerId, PROTO, Uint8Array.from([4, 5]));
  assert(ordinary.length === 2 && ordinary[1] === 5, "the app's own id still answers over the same link");
});

// ── the delivery return, when one read carries several requests ──────────────
// The link occupant answers a `linkBytes` event with an optional authenticated-peer
// transition followed by `[count u32]` and that many delivery records, and the driver
// routes each through the shell's claim table (§12.10). Several records in one return is
// the ORDINARY case on a byte stream. It is also where attribution
// is decided: the occupant writes the authenticated sender into each record, and if any
// field ran to the end of the FRAME rather than to its own length, the next record would
// be read out of this one's payload — a peer could hand the claim table a request
// attributed to any key it liked.
await test("DELIVERY: two pipelined requests in ONE read are two correctly attributed deliveries", async (keep) => {
  // framing 1: a byte-stream link, so the guest runs its own length framer and a single
  // read really can carry two whole messages. (The default fabric preserves message
  // boundaries and can never produce more than one record.)
  const st = keep(await upPair({ framing: 1 }));
  const first = Uint8Array.from([0x11, 0x22, 0x33]);
  // The second request's payload is itself a well-formed delivery record naming another
  // claim and another sender — the shape a mis-parse would promote into a real delivery.
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
    st.A.sendNoReply(st.B.driver.peerId, PROTO, first),
    st.A.sendNoReply(st.B.driver.peerId, PROTO, second),
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
  assert(from.length === 2 && from.every((f) => f === st.A.driver.peerId),
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
  assert(raw.length === 32 && hexOf(raw) === st.A.driver.peerId,
    "an app asking `peers` must get the authenticated set back");
  // `linkBytes` through the same seam must be refused by NAME, not silently ignored.
  let refused = "";
  try { await st.B.op("linkBytes", new Uint8Array(8)); }
  catch (e) { refused = String(e); }
  assert(refused.includes("the host's, not an app's"),
    `an app naming a platform event must be refused, got ${refused || "no error"}`);
});

// The event result carries no link id: the driver supplies it from the event context and
// checks the captured owner/channel again after the result settles. Exercise that boundary
// with a deliberately dishonest occupant rather than the real, pinned transport bundle.
await test("EVENT RETURNS: authentication and down cannot be redirected to another link", async (keep) => {
  class ManualChannel {
    framing = 0;
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
  const owner = {};
  const driver = keep(new TransportHost({ identity: generateKeyPair() }));
  driver.activate(owner);
  const peerA = new Uint8Array(32).fill(0xa1);
  const peerB = new Uint8Array(32).fill(0xb2);
  const authResult = (peer, trailing = []) => Uint8Array.from([1, ...peer, 0, 0, 0, 0, ...trailing]);
  let nextBytesResult = new Uint8Array();
  let pending = null;
  driver.route(async (payload) => {
    const n = payload[0];
    const op = new TextDecoder().decode(payload.subarray(1, 1 + n));
    if (op === "linkBytes") {
      if (pending) return new Promise((resolve) => { pending.resolve = resolve; });
      return nextBytesResult;
    }
    if (op === "linkClosed") return Uint8Array.of(CLOSE_REASON.LOCAL);
    return new Uint8Array();
  }, () => true);

  const aChannel = new ManualChannel(), bChannel = new ManualChannel();
  const a = { auth: [], close: [] }, b = { auth: [], close: [] };
  const aLink = driver.openLink({
    channel: aChannel, weDialed: false,
    onAuth: (peer) => a.auth.push(peer), onClose: (_id, reason) => a.close.push(reason),
  });
  const bLink = driver.openLink({
    channel: bChannel, weDialed: false,
    onAuth: (peer) => b.auth.push(peer), onClose: (_id, reason) => b.close.push(reason),
  });

  nextBytesResult = authResult(peerA);
  aChannel.emit();
  await until(() => a.auth.length === 1, 1000, "A's event-bound authentication");
  assert(a.auth[0] === hexOf(peerA) && b.auth.length === 0,
    "A's linkBytes return must authenticate A and cannot select B");

  // A second return cannot rename an authenticated link, and a malformed result has no
  // valid prefix: neither authentication nor any later delivery may partially apply.
  nextBytesResult = authResult(peerB);
  aChannel.emit();
  nextBytesResult = authResult(peerB, [0xff]);
  bChannel.emit();
  await settle();
  assert(a.auth.length === 1 && b.auth.length === 0,
    "duplicate or malformed authentication returns must have no effect");

  // Hold B's result, close B through the raw-link owner, then settle the stale result.
  // The channel intentionally emits no callback of its own, so this also pins the
  // driver's cross-backend local-close event.
  pending = {};
  bChannel.emit();
  await until(() => typeof pending.resolve === "function", 1000, "B's pending linkBytes return");
  driver.rawNet(owner).close(bLink.linkId, false);
  await until(() => b.close.length === 1, 1000, "B's event-bound close report");
  pending.resolve(authResult(peerB));
  pending = null;
  await settle();
  assert(b.auth.length === 0 && b.close[0] === CLOSE_REASON.LOCAL,
    "a stale linkBytes result cannot revive or authenticate its closed link");

  // A backend callback racing the synthesized close event is idempotent.
  driver.rawNet(owner).close(aLink.linkId, false);
  await until(() => a.close.length === 1, 1000, "A's close report");
  aChannel.fail();
  await settle();
  assert(a.close.length === 1, "a local close and backend close callback must report down once");
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
