// transport-link.test.mjs — regression tests for the §12.6.1 link hardening and the
// §12.6.2 concealed handshake.
//
// The AKE, the record layer, the half-open limiter and the link router are the signed
// transport bundle's (`transport/src`), where no test can reach in and hold an
// object. So each property is pinned where it ships — through the real host stack,
// shell → driver (TransportHost) → guest realm — with an instrumented in-process
// channel standing in for the socket.
//
// That is a strictly better place to pin them: what these tests observe is the wire and
// the host-visible edges of the shipped artifact, not a parallel reimplementation. It is
// also the only place they *can* be observed, which is the point.
//
// `TransportHost.openLink()` is the seam that makes it possible: it is the host half of
// one link, taking exactly what a link needs to be stood up (weDialed, expectPeerId,
// contactSecret, source, handshakeTimeoutMs, rekeyAfterFrames, onAuth, onClose) and
// handing back a handle. The half-open budgets are the exception: a host-managed link spends no
// budget by design, so those tests use real listeners and raw dials instead, and live in
// transport-load.test.mjs.
//
// Each test names the property it pins, so a failure says which guarantee broke.

import {
  makeTransportHost, generateKeyPair, sodium, LoopbackChannels, CLOSE_REASON, until,
} from "./transport-harness.mjs";
import { testkit } from "./testkit.mjs";

// ── an instrumented channel pair ─────────────────────────────────────────────
// The RawLink shape (core/socket-seam.ts), with the hooks these tests need:
// every byte written is recorded, `tamper` may corrupt or drop a message in flight,
// `destructive` models a transport that discards unflushed writes on a hard close,
// and `closeArgs` records what the guest asked the transport to do. `framing` picks the
// codec the guest runs over the pair: 0 leaves it alone, 1 makes it length-prefix its
// own messages, which is what a real TCP link gets.
// Delivery is deferred a microtask so nothing re-enters a live guest frame, which is
// the same discipline a real socket imposes.
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
  const proto = new TextEncoder().encode("_t");
  st.B.driver.onRequest((_from, _p, payload) => payload);
  const resp = await st.A.driver.request(st.B.driver.peerId, proto, Uint8Array.from([1, 2, 3]));
  assert(resp.length === 3 && resp[2] === 3, `frames not delivered: ${resp.length}`);
  assert(st.a.peer === st.B.driver.peerId, "the dialer must attribute the link to the peer it dialed");
  assert(st.b.peer === st.A.driver.peerId, "the acceptor must attribute the link to the caller");
});

await test("a request's deadline is the CALLER's, not a node-wide clock", async (keep) => {
  // Two requests to the same peer, over the same live link, with different deadlines —
  // and the short one must settle on its own schedule. This is what the old silence
  // clock could not do: it re-armed on ANY frame from the peer, so a request's lifetime
  // depended on unrelated traffic, and every request on a node shared one window.
  const st = keep(await upPair());
  const proto = new TextEncoder().encode("_t");
  // A holder that never answers: the deadline is the only thing that can settle these.
  st.B.driver.onRequest(() => new Promise(() => {}));

  const t0 = Date.now();
  const short = st.A.driver.request(st.B.driver.peerId, proto, Uint8Array.from([1]), 150)
    .then(() => "resolved", () => Date.now() - t0);
  const long = st.A.driver.request(st.B.driver.peerId, proto, Uint8Array.from([2]), 5000)
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
  // The failure this exists to stop: a 50 MB PUT queued ~42 MB behind its sockets and
  // every request in the window was cancelled at its 5 s deadline while the wire was
  // moving perfectly. The clock was armed when the request was QUEUED, so it timed our
  // own upload and blamed the holders for our backlog.
  const chans = wirePair();
  const st = keep(await linked(chans));
  const proto = new TextEncoder().encode("_t");
  st.B.driver.onRequest(() => new Promise(() => {}));   // never answers: only the clock can settle it

  // A backpressured socket holding 40 KB of this request, draining 4 KB at a time —
  // slower than the 100 ms deadline, so a queue-time clock would fire ~9 times over.
  chans[0].backlog = 40_000;
  const drain = setInterval(() => { chans[0].backlog = Math.max(0, chans[0].backlog - 4_000); }, 40);

  const t0 = Date.now();
  const settled = st.A.driver.request(st.B.driver.peerId, proto, Uint8Array.from([1]), 100)
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
  const st = keep(await linked(chans));
  const proto = new TextEncoder().encode("_t");
  st.B.driver.onRequest(() => new Promise(() => {}));

  chans[0].backlog = 40_000;                            // frozen: no drain interval
  const t0 = Date.now();
  const ms = await st.A.driver.request(st.B.driver.peerId, proto, Uint8Array.from([1]), 100)
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
  // The enumeration primitive. A node that speaks first is a directory service: one
  // connect reads its identity straight off the wire. A caller without the contact secret
  // must get silence — not an error, not a close, nothing that distinguishes this node
  // from a port that is not listening.
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
  const proto = new TextEncoder().encode("_t");
  st.B.driver.onRequest((_f, _p, p) => p);
  await st.A.driver.request(st.B.driver.peerId, proto, Uint8Array.from([9]));
  const wire = [...st.chans[0].sent, ...st.chans[1].sent].join("");
  for (const [name, id] of [["initiator", st.A.driver.peerId], ["responder", st.B.driver.peerId]]) {
    assert(!wire.includes(id), `${name} identity key found in cleartext on the wire`);
  }
});

await test("CONCEALMENT: msg1 carries no identity, so a seized static key reveals none", async (keep) => {
  // Why identities are deferred past the ephemeral-ephemeral DH instead of sealed to the
  // responder's static key the way Noise IK does. Anything msg1 carries is readable by
  // whoever holds that static key — including an attacker who seizes the node years
  // later and replays a recording. So msg1 carries no identity at all.
  const chans = wirePair();
  const st = keep(await linked(chans));
  await until(() => chans[0].sent.length > 0, 4000, "msg1");
  const msg1 = Buffer.from(chans[0].sent[0], "hex");
  assert(msg1.length === 81, `msg1 should be 81 bytes, got ${msg1.length}`);
  assert(!msg1.includes(Buffer.from(st.A.driver.peerId, "hex")), "msg1 must not carry the initiator identity");
});

await test("CONTACT SECRET: the address book alone does not grant a probe", async (keep) => {
  // The property the contact secret exists for. Every peer holding this node's ADDRESS also
  // holds its static key, so without a contact secret an address book leak is a probe
  // capability: elicit msg2, confirm which identity lives at that host, and keep doing
  // it after being removed from the member set. With one, probing needs a secret no address
  // contains — so an address leak costs the address and nothing more.
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
  // The framer used to join every inbound slice onto one buffer, so a peer that
  // dribbles a full-size frame one byte at a time forced a quadratic number of
  // copies — a CPU-exhaustion budget no frame-size cap controls (the cap bounds
  // the buffer, not the copying). The parser now keeps the slices it was handed
  // and copies once per complete frame. This pins the behaviour the refactor has
  // to preserve: arbitrary slice boundaries in, exactly one message out.
  let armed = false;
  const chans = wirePair({ framing: 1, tamper: (b, from) => (from === "A" && armed ? null : b) });
  const st = keep(await linked(chans));
  await until(() => st.a.authed && st.b.authed, 4000, "handshake");
  const proto = new TextEncoder().encode("_t");
  st.B.driver.onRequest((_f, _p, p) => p);
  // Above the pre-auth cap, so the dribble must be measured against the RAISED
  // cap (the FRAME CAP tests pin the raise itself).
  const payload = new Uint8Array(48 * 1024).fill(0x5a);
  armed = true; // from here on, drop A's real delivery — it is re-fed manually below
  const before = chans[0].sent.length;
  const respP = st.A.driver.request(st.B.driver.peerId, proto, payload, 8000);
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

await test("READY: a second ready() joins the first instead of stranding it", async (keep) => {
  // ready() used to overwrite the waiter on a second call: the first caller's
  // promise was resolved by the second caller's timer — or never, if the second
  // call resolved first. Both callers must settle together, whatever the order.
  const { TransportHost } = await import("../build/host/transport-host.js");
  const { generateKeyPair: mkKey } = await import("./transport-harness.mjs");
  const identity = mkKey();
  const host = new TransportHost({ identity });
  // A stub realm that answers the ready entrypoint immediately, so the test does
  // not wait out the host's timeout backstop.
  host.attach({
    call: async (entry) => { if (entry === "ready") host.sink().ready(true); return new Uint8Array(); },
    dispose() {},
  });
  const [r1, r2] = await Promise.all([
    host.ready(50).then(() => "ok", () => "failed"),
    host.ready(50).then(() => "ok", () => "failed"),
  ]);
  assert(r1 === "ok" && r2 === "ok", `both ready() calls must settle together (got ${r1}/${r2})`);
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
  // The isolation boundary. A staging fleet and a production one can share addresses,
  // configs and operators and still never cross: the network key seeds the transcript,
  // so every derived key and every signature preimage differs and the handshake dies at
  // the first message. Not access control — a boundary.
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
  // Per node, not per deployment and not per pair. A caller must present the secret of
  // the node it is dialing; holding some other node's is worth nothing. This is what
  // bounds a leak to one node's inbound side instead of the whole network.
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
  // The reflection guard closes the link from inside onHello. Before the fix,
  // ch.close() set `dead` without firing onCls, so onClose never ran and the
  // transport kept the link in its pre-auth bookkeeping forever.
  // Two nodes sharing one identity: B sees its own key in A's msg3.
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
  const proto = new TextEncoder().encode("_t");
  st.B.driver.onRequest((_f, _p, p) => p);
  for (let i = 0; i < 14; i++) {
    const r = await st.A.driver.request(st.B.driver.peerId, proto, Uint8Array.from([i]));
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
  const proto = new TextEncoder().encode("_t");
  const seen = [];
  st.B.driver.onRequest((_f, _p, p) => { seen.push(Buffer.from(p).toString()); return p; });
  await st.A.driver.request(st.B.driver.peerId, proto, new TextEncoder().encode("real"));
  st.aLink.close();
  await until(() => st.b.closed, 3000, "the close to land");
  await settle(100);
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
  const st = keep(await linked(chans, {}, { admitPeer: () => false }));
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
  const seen = [];
  st.B.driver.onRequest((_f, _p, p) => { seen.push(p); return p; });
  st.aLink.send(new TextEncoder().encode("tampered"));
  await until(() => st.b.closed, 3000, "a forged record must close the link");
  assert(seen.length === 0, "a forged record must not be delivered");
});

await test("default caps are sane", async () => {
  const {
    DEFAULT_MAX_HALF_OPEN_UNVERIFIED, DEFAULT_MAX_HALF_OPEN_PER_SOURCE, DEFAULT_MAX_HALF_OPEN_VERIFIED,
  } = await import("../build/host/transport-host.js");
  assert(DEFAULT_MAX_HALF_OPEN_UNVERIFIED > 0 && DEFAULT_MAX_HALF_OPEN_UNVERIFIED <= 8192,
    "unverified cap should be a real bound");
  assert(DEFAULT_MAX_HALF_OPEN_VERIFIED > 0 && DEFAULT_MAX_HALF_OPEN_VERIFIED <= 4096,
    "verified cap should be a real bound");
  assert(DEFAULT_MAX_HALF_OPEN_PER_SOURCE > 0 && DEFAULT_MAX_HALF_OPEN_PER_SOURCE < DEFAULT_MAX_HALF_OPEN_UNVERIFIED,
    "the per-source cap must bound one source well below the whole budget");
});

summary("transport link hardening");
