// Tests for the §12.6.1 record layer and link teardown and the §12.6 concealed handshake.
// The link logic lives in the signed transport bundle, where no test can reach in and
// hold an object, so each property is tested through the real host stack (shell,
// TransportHost, guest realm) with an instrumented in-process channel for the socket. The
// half-open budgets are tested in transport-load.test.mjs.

import {
  makeTransportHost, generateKeyPair, sodium, InjectedChannels, until, PROTO,
  authorBundle, bootShell, TransportHost, ModuleTable, FreshnessMarks, createSafeRealm,
  transportBlob, transportAuthor, transportPolicy, verifyBundle, linkedTo, ready, contact,
  LoopbackChannels, generatorRequest,
} from "./transport-harness.mjs";
import { testkit } from "./testkit.mjs";
import { bytesEqual } from "./bytes.mjs";
import { MAX_INBOUND_HOLD_BYTES, MAX_INBOUND_HOLD_SLICES } from "../build/services/net-limits.js";
import { HOST_CALLER_ID } from "../build/host/guest-seam.js";

/** Read a link event as the bound realm does. The driver passes the occupant the whole
 *  realm argument, `[caller 32][opLen u8][op][args ...]`, with the host's caller id in front
 *  (transport-host.ts `TransportCall`), so a test standing in for an occupant reads it at
 *  the same seam the signed one does. */
function opOf(input) {
  const body = input.subarray(HOST_CALLER_ID.length);
  const n = body[0];
  return { op: new TextDecoder().decode(body.subarray(1, 1 + n)), args: body.subarray(1 + n) };
}

// ── an instrumented channel pair ─────────────────────────────────────────────
// The RawLink interface (services/socket-seam.ts) plus the hooks these tests need: every
// byte written is recorded, `tamper` may corrupt or drop a message in flight,
// `destructive` models a transport discarding unflushed writes on a hard close, and
// `closeArgs` records what the guest asked. Delivery is deferred a microtask (like a real
// socket); `hold`/`flush` model several whole messages arriving in one read of a byte
// stream, handing the held writes to the far end as a single `onData`.
function wirePair({ addrA = "10.0.0.1", addrB = "10.0.0.2", tamper, destructive, stream = false, trackBacklog = false } = {}) {
  const mk = (name, remoteAddr) => ({
    name, remoteAddr,
    sent: [], closeArgs: [], dead: false, inFlight: 0,
    msg: null, rawMsg: null, cls: null, peer: null,
    paused: false, inbound: [],
    holding: false, held: [],
    /** Queue writes instead of delivering them, until `flush`. */
    hold() { this.holding = true; this.held = []; },
    /** Deliver everything held as one read at the far end; returns how many writes were
     *  combined, so a test can check it really got more than one. */
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
    // The adapter backlog the host accounts against (services/socket-seam.ts
    // `RawLink.buffered`): bytes written but not yet on the wire, set directly by a test to
    // model a socket that is backpressured, draining or stuck. `trackBacklog` instead grows
    // it by what `send` was given, since `LinkOutboundOwner` only releases what was
    // admitted, so a backlog with no real write behind it would not count.
    backlog: 0,
    buffered() { return this.backlog; },
    send(bytes) {
      if (this.dead) return;
      if (trackBacklog) this.backlog += bytes.length;
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
    onData(cb) {
      this.rawMsg = cb;
      this.msg = (bytes) => {
        if (!this.paused) { this.rawMsg?.(bytes); return; }
        this.inbound.push(Uint8Array.from(bytes));
      };
    },
    setReadable(enabled) {
      if (!enabled) { this.paused = true; return; }
      if (this.inbound.length === 0) { this.paused = false; return; }
      let next = this.inbound.shift();
      // A real paused TCP socket leaves bytes in the kernel, and the next read combines
      // them. Model that instead of turning a byte-by-byte test into tens of thousands of
      // host events.
      if (this.stream && this.inbound.length > 0) {
        const parts = [next, ...this.inbound.splice(0)];
        const size = parts.reduce((n, part) => n + part.length, 0);
        next = new Uint8Array(size);
        let off = 0;
        for (const part of parts) { next.set(part, off); off += part.length; }
      }
      // Keep the socket paused until this queued read is delivered; otherwise a newly
      // arriving slice could overtake it in the resume microtask.
      queueMicrotask(() => { this.paused = false; this.msg?.(next); });
    },
    onClose(cb) { this.cls = cb; },
    close(graceful = false) {
      this.closeArgs.push(graceful);
      if (this.dead) return;
      this.dead = true;
      this.inbound.length = 0;
      if (destructive && !graceful) this.inFlight = 0;
      queueMicrotask(() => this.peer.kill());
    },
    // The far end going away: fires onClose, as a real channel's fail() does.
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

/** Long enough for a handshake that will fail to have failed, and for a responder that
 *  will stay silent to have stayed silent. Every negative assertion in this file waits
 *  for things to settle. */
const settle = (ms = 250) => new Promise((r) => setTimeout(r, ms));

/** Two transport nodes over injected raw links: A dials B over `chans[0]`, B accepts on
 *  `chans[1]`. Both allow more links per peer than they will ever hold, so a test can open
 *  another pair on nodes already linked (`openPair`). */
async function linked(chans, aOpts = {}, bOpts = {}) {
  const aFactory = new InjectedChannels();
  const bFactory = new InjectedChannels();
  const st = {
    a: { closed: false, reason: null },
    b: { closed: false, reason: null },
    close() { try { A.shell.close(); } catch { /* already down */ } try { B.shell.close(); } catch { /* already down */ } },
  };
  const A = await makeTransportHost({
    channels: aFactory, contactSecret: CONTACT, connsPerPeer: 64,
    onLinkClosed: (_id, reason) => { st.a.closed = true; st.a.reason = reason; },
    ...aOpts,
  });
  const B = await makeTransportHost({
    channels: bFactory, contactSecret: CONTACT, connsPerPeer: 64,
    onLinkClosed: (_id, reason) => { st.b.closed = true; st.b.reason = reason; },
    ...bOpts,
  });
  // For tests that later open a second pair on the same nodes (`openPair`).
  A.factory = aFactory;
  B.factory = bFactory;
  // What each node's dial presents: its own configured secret, which in every test here is
  // the one the node it dials gates on (or is meant not to be).
  A.dialSecret = "contactSecret" in aOpts ? aOpts.contactSecret : CONTACT;
  B.dialSecret = "contactSecret" in bOpts ? bOpts.contactSecret : CONTACT;
  st.A = A;
  st.B = B;
  await openPair(A, B, chans);
  return st;
}

/** Whether A currently has an authenticated link to B, and the reverse, asked of the
 *  guest's peer set, the only place the answer lives. */
const aUp = (st) => linkedTo(st.A, st.B.peerId);
const bUp = (st) => linkedTo(st.B, st.A.peerId);

/** The pair above, already authenticated: the starting point for tests about what
 *  happens after the handshake. */
async function upPair(chanOpts, aOpts, bOpts) {
  const chans = wirePair(chanOpts);
  const st = await linked(chans, aOpts, bOpts);
  st.chans = chans;
  await until(async () => (await aUp(st)) && (await bUp(st)), 4000, "handshake");
  return st;
}

/** Give one channel pair to two already-started nodes' factories: an accept on B's side,
 *  then a dial from A presenting `secret` (A's own by default). For tests that open a
 *  second link on nodes `linked()`/`upPair()` already built. */
function openPair(A, B, chans, secret = A.dialSecret) {
  B.factory.give(chans[1]);
  return A.factory.dial(A, B.peerId, chans[0], secret);
}

// ── harness ──────────────────────────────────────────────────────────────────
const { test, assert, summary } = testkit();

const hexOf = (u) => Buffer.from(u).toString("hex");

console.log("\nTransport link hardening (§12.6.1) + concealed handshake (§12.6)\n");

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
  // one must settle on its own schedule. A node-wide silence clock would reset on any frame
  // from the peer, making a request's lifetime depend on unrelated traffic.
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

  // It must not have taken the other request with it: the 5s one is still pending, so the
  // deadline is per request, not per peer.
  let longSettled = false;
  long.then(() => { longSettled = true; });
  await new Promise((r) => setTimeout(r, 50));
  assert(!longSettled, "a peer's short-deadline request must not settle its long-deadline one");
});

await test("OUT OF TIME: an app past its deadline loses its own request, never the link", async (keep) => {
  // The transport's turns are its own (§12.3): an app's remainder bounds the app's wait,
  // not the record the transport seals and writes for it. Here the seal outlasts the app's
  // 30 ms; on the app's clock it would be refused halfway and take the link down.
  let slowSeal = false;
  const st = keep(await upPair(undefined, {
    onHostAnswer: (name, answer) => {
      if (!slowSeal || name !== "crypto/chacha20poly1305-ietf/seal") return answer;
      slowSeal = false;
      return new Promise((r) => setTimeout(() => r(answer), 100));
    },
  }));
  slowSeal = true;
  const late = await st.A.request(st.B.peerId, PROTO, Uint8Array.of(1), 30).then(() => "answered", () => "failed");
  assert(late === "failed", "the app's own deadline still bounds its wait");
  await settle(200);
  assert(!st.a.closed && !st.b.closed, "the link must outlive one app's deadline");
  const next = await st.A.request(st.B.peerId, PROTO, Uint8Array.of(2)).then((r) => r[0], () => null);
  assert(next === 2, "and carry the next request");
});

await test("a silent peer's correlation is retired on the transport's own timeout", async (keep) => {
  // Hold B's encrypted response after the request reaches its app. A's 100ms transport
  // timeout must beat the still-live 2s host deadline, and the response released later
  // must be ignored rather than poisoning the next correlation or closing the link.
  const st = keep(await upPair(undefined, { transportConfig: { requestTimeoutMs: 100 } }));
  st.chans[1].hold();
  const t0 = Date.now();
  const timedOut = await st.A.request(st.B.peerId, PROTO, Uint8Array.from([7]), 2000)
    .then(() => "resolved", () => Date.now() - t0);
  assert(typeof timedOut === "number", "the transport timeout rejects an unanswered correlation");
  assert(timedOut < 1200, `the 100ms transport timeout wins before the 2s caller deadline (${timedOut}ms)`);

  const released = st.chans[1].flush();
  assert(released > 0, "the timed-out request really had a late response waiting on the wire");
  await settle(50);
  const next = await st.A.request(st.B.peerId, PROTO, Uint8Array.from([8]), 1000);
  assert(next.length === 1 && next[0] === 8, "a late response is ignored and the next correlation still settles");
  assert(await aUp(st), "retiring one correlation does not close its healthy link");
});

await test("peer loss settles a pending request even with its retention timeout disabled", async (keep) => {
  const st = keep(await upPair(undefined, { transportConfig: { requestTimeoutMs: 0 } }));
  st.chans[1].hold();
  const pending = st.A.request(st.B.peerId, PROTO, Uint8Array.of(7), 2000)
    .then(() => "resolved", () => "failed");
  await until(() => st.chans[1].held.length > 0, 1000, "response held on the wire");
  st.chans[0].kill();
  const result = await Promise.race([pending, settle(500).then(() => "still pending")]);
  assert(result === "failed", `peer-down must settle before the caller deadline: ${result}`);
});

await test("a refused wake fails nothing, and the next event arms it again", async (keep) => {
  // The wake is a host call, so this realm's call budget can refuse it. The budget frees
  // up by itself: every deadline must stay and every link stay up until a later event
  // re-arms.
  let refusing = false, refused = 0;
  const st = keep(await upPair(undefined, {
    transportConfig: { requestTimeoutMs: 100 },
    onHostCall: (name) => { if (refusing && name === "timer/arm") { refused++; throw new Error("wake refused"); } },
  }));
  st.chans[1].hold();
  refusing = true;
  const t0 = Date.now();
  const pending = st.A.request(st.B.peerId, PROTO, Uint8Array.of(7), 3000)
    .then(() => "resolved", () => Date.now() - t0);
  await until(() => refused > 0, 2000, "the wake to be refused");
  await settle(150);
  assert(await aUp(st), "a refused wake must not close an authenticated link");
  refusing = false;
  await aUp(st); // any event asks for the wake again
  const retired = await pending;
  assert(typeof retired === "number" && retired < 2000,
    `the correlation still retires on the transport's timeout, not the caller's (${retired}ms)`);
});

await test("the handoff deadline includes time in the outbound socket queue", async (keep) => {
  // The deadline belongs to the initiating call, so the transport cannot extend it because
  // bytes are still draining. `trackBacklog` shows the timeout happens while this
  // request's bytes are still held by the adapter.
  const chans = wirePair({ trackBacklog: true });
  const st = keep(await linked(chans, {}, { mode: "hang" }));
  const proto = PROTO;
  // Draining 4 KB at a time is slower than the 100 ms owner deadline.
  const drain = setInterval(() => { chans[0].backlog = Math.max(0, chans[0].backlog - 4_000); }, 40);

  const t0 = Date.now();
  const settled = st.A.request(st.B.peerId, proto, new Uint8Array(40_000), 100)
    .then(() => "resolved", () => Date.now() - t0);

  const ms = await settled;
  clearInterval(drain);
  assert(typeof ms === "number", "an unanswered request must reject");
  assert(ms < 1000, `the host deadline must not be extended by transport progress (${ms}ms)`);
  assert(chans[0].backlog > 0, "the deadline fires while the initiating owner's bytes are still queued");
});

await test("a stalled link still settles on the deadline", async (keep) => {
  // The other half: a backlog that never moves is a stuck wire. Same 100 ms, same
  // never-answering peer, but nothing drains: `trackBacklog` grows `chans[0].backlog` from
  // the request's own 40 KB write (see the test above) and nothing here reduces it.
  const chans = wirePair({ trackBacklog: true });
  const st = keep(await linked(chans, {}, { mode: "hang" }));
  const proto = PROTO;
  const t0 = Date.now();
  const ms = await st.A.request(st.B.peerId, proto, new Uint8Array(40_000), 100)
    .then(() => "resolved", () => Date.now() - t0);
  assert(typeof ms === "number", "a stalled request must reject");
  assert(ms < 1500, `a frozen backlog must settle on the deadline, not wait forever (took ${ms}ms)`);
});

await test("NO ROUTE: a request nothing can carry fails at once, not at its timeout", async (keep) => {
  // The transport knows when it dropped a frame for lack of a link (a peer with no
  // address, a refused dial), and nothing will answer that request. It fails at once,
  // while the caller may still have time to ask someone else.
  const fabric = new LoopbackChannels();
  const A = keep(await makeTransportHost({ channels: fabric.view(), listen: [{ label: "tcp", host: "loopback", port: 0 }] }));
  const nobody = hexOf(generateKeyPair().publicKey);
  const ask = async () => {
    const t0 = Date.now();
    const r = await A.request(nobody, PROTO, Uint8Array.of(1), 4000).then(() => "answered", () => "failed");
    return `${r} after ${Date.now() - t0}ms`;
  };
  const unknown = await ask();
  assert(/^failed after \d{1,3}ms$/.test(unknown), `a peer with no address must fail at once (${unknown})`);
  await A.addr(nobody, "tcp://127.0.0.1:1"); // nothing listens there
  const refused = await ask();
  assert(/^failed after \d{1,3}ms$/.test(refused), `a refused dial must fail at once (${refused})`);
});

await test("ANSWER CAP: an answer over the frame cap comes back empty, not never", async (keep) => {
  // A claimant's answer too big for one record cannot be sent. Dropped at the link, it
  // would leave the caller waiting out its deadline; it is sent back empty instead, which
  // means "no answer" here.
  const st = keep(await upPair());
  const t0 = Date.now();
  const got = await st.A.request(st.B.peerId, PROTO, generatorRequest(3 * 1024 * 1024, 1), 4000)
    .then((r) => r, () => null);
  const ms = Date.now() - t0;
  assert(got !== null && got.length === 0,
    `the over-cap answer must come back empty (got ${got === null ? "a failure" : got.length + " bytes"} after ${ms}ms)`);
  assert(ms < 2000, `and at once, not at the deadline (${ms}ms)`);
});

await test("HUNG CLAIMANT: the caller hears empty at the responder's deadline, and the link lives", async (keep) => {
  // A claimant that never answers is settled by the responder's deadline. A delivery's
  // answer is a new turn of the transport (§12.3), so the empty reply is written with its
  // own budget; under the read's spent budget its seal would be refused and the responder
  // would tear down its own link.
  const st = keep(await upPair(undefined, {}, { mode: "hang", guestDeadlineMs: 1000 }));
  const t0 = Date.now();
  const got = await st.A.request(st.B.peerId, PROTO, Uint8Array.of(1), 4000).then((r) => r, () => null);
  const ms = Date.now() - t0;
  assert(got !== null && got.length === 0,
    `the unanswered request must come back empty (got ${got === null ? "a failure" : got.length + " bytes"} after ${ms}ms)`);
  assert(ms < 3000, `and at the responder's 1 s deadline, not the caller's 4 s (${ms}ms)`);
  assert(!st.a.closed && !st.b.closed, "and the link must survive it");
});

await test("handshake messages are exact-length: a trailing byte is refused", async (keep) => {
  // Trailing bytes would sit outside the transcript hash, and so outside what both
  // signatures cover. Every handshake message must have the exact width, not a minimum.
  // A's two handshake messages, by the width each is accepted at: msg1 and msg3.
  for (const len of [1233, 112]) {
    const chans = wirePair({
      tamper: (b, from) => (from === "A" && b.length === len ? Buffer.concat([Buffer.from(b), Buffer.from([0])]) : b),
    });
    const st = keep(await linked(chans));
    await settle();
    // The responder is the end that reads a tampered message from A, so it is the end
    // that must refuse. (For msg3 the initiator has legitimately authenticated by then:
    // it verified msg2 at 1 RTT, before the responder has msg3 to authenticate it by.)
    assert(!(await bUp(st)), `responder must refuse an over-long ${len}-byte message`);
    if (len === 81) assert(!(await aUp(st)), "a rejected msg1 must leave the initiator unauthenticated");
    st.close();
  }
});

await test("an exact-size invalid handshake latches before repeated KEM work", async (keep) => {
  // A malformed msg2 has the right public shape, so the initiator has to do its DH and
  // ML-KEM decapsulation before the concealed tag can reject it. After that rejection ends
  // the exchange, replaying the same body must be a cheap silent stall; decapsulating again
  // would let one socket turn bandwidth into repeated PQ work.
  let invalidMsg2 = null;
  let fromB = 0;
  let initiatorKemCalls = 0;
  const chans = wirePair({
    // msg2 is the first thing the responder sends; identified that way instead of by
    // width, so a suite change cannot turn this tamper into a silent no-op.
    tamper: (bytes, from) => {
      if (from !== "B" || ++fromB !== 1) return bytes;
      invalidMsg2 = Uint8Array.from(bytes);
      invalidMsg2[invalidMsg2.length - 1] ^= 0x80;
      return invalidMsg2;
    },
  });
  const st = keep(await linked(chans, {
    onHostCall: (name) => { if (name === "mlkem") initiatorKemCalls++; },
  }));
  await until(() => invalidMsg2 !== null, 4000, "the responder to answer msg1");
  await settle(750); // let the initiator finish its decapsulation
  const afterFirstFailure = initiatorKemCalls;
  assert(afterFirstFailure > 0, "the initiator must have reached ML-KEM at all");

  for (let i = 0; i < 8; i++) chans[0].msg(invalidMsg2);
  await settle(750);
  assert(initiatorKemCalls === afterFirstFailure,
    `a terminal invalid msg2 repeated ML-KEM work (${afterFirstFailure} -> ${initiatorKemCalls} calls)`);
  assert(!(await aUp(st)) && !(await bUp(st)), "a latched invalid exchange must remain unauthenticated");
});

await test("a RECORDED msg1 replayed on a fresh connection draws nothing", async (keep) => {
  // The contact-secret proof inside msg1 is not bound to the connection carrying it, so
  // anyone who records one can resend it. Accepting the copy would draw an answer from a
  // node that is otherwise silent to strangers, promote the socket off the contended
  // budget, and cost a DH and an encapsulation, as often as the recording is sent.
  let bKem = 0;
  const chans = wirePair();
  const st = keep(await linked(chans, {}, {
    onHostCall: (name) => { if (name === "mlkem") bKem++; },
  }));
  await until(async () => await bUp(st), 4000, "the genuine handshake");
  const msg1 = Uint8Array.from(Buffer.from(chans[0].sent[0], "hex"));
  assert(msg1.length === 1233, `expected msg1 first on A's wire, got ${msg1.length} bytes`);
  const spentGenuinely = bKem;

  // The recording, arriving on its own connection, an accept like any other.
  const replay = wirePair({ addrA: "10.0.9.1", addrB: "10.0.9.2" });
  st.B.factory.give(replay[1]);
  for (let i = 0; i < 4; i++) replay[0].send(msg1);
  await settle();
  assert(replay[1].sent.length === 0,
    `a replayed msg1 drew ${replay[1].sent.length} message(s); it must draw silence`);
  assert(bKem === spentGenuinely,
    `a replayed msg1 bought ${bKem - spentGenuinely} ML-KEM call(s) — the refusal must come first`);

  // The silence is specific to the replay, not a node that stopped accepting: a fresh
  // dial, with its own ephemeral, still gets its answer.
  const again = wirePair({ addrA: "10.0.9.3", addrB: "10.0.9.4" });
  await openPair(st.A, st.B, again);
  await until(() => again[1].sent.length > 0, 4000, "the responder to answer a FRESH msg1");
});

await test("a caller names itself only to the key it dialed", async (keep) => {
  // Every holder of a node's address holds its contact secret, so any of them can answer
  // msg1 as that node. msg2 is signed under the answering node's key and checked against
  // the one the dial pinned, so an impostor holding the secret draws msg1 and nothing
  // more: the caller's identity goes only to the receiver it meant.
  const st = keep(await upPair());
  const impostor = wirePair({ addrA: "10.0.7.1", addrB: "10.0.7.2" });
  // A believes it dials `nobody`; B, holding the same contact secret, answers as itself.
  const nobody = hexOf(generateKeyPair().publicKey);
  st.B.factory.give(impostor[1]);
  await st.A.factory.dial(st.A, nobody, impostor[0], CONTACT);
  await until(() => impostor[1].sent.length >= 1, 4000, "the impostor to answer with msg2");
  await until(() => impostor[0].dead, 4000, "the caller to close on the wrong signature");
  assert(impostor[0].sent.length === 1,
    `the caller answered an impostor (${impostor[0].sent.length} messages, want msg1 alone)`);
  assert(!impostor[0].sent.join("").includes(st.A.peerId), "the caller's identity reached an impostor");
  assert(!(await linkedTo(st.A, nobody)), "an impostor must not authenticate as the dialed key");
});

await test("COHORT: a node dials the peers its config spells as pk[.secret]@dest", async (keep) => {
  // The CLI passes `--peers` to the transport unread (§12.8): the peer grammar is this
  // bundle's, parsed at install, with the peer's contact secret inside the reference.
  const fabric = new LoopbackChannels();
  const B = keep(await makeTransportHost({ channels: fabric.view(), listen: [{ label: "tcp", host: "loopback", port: 0 }], contactSecret: CONTACT }));
  const A = keep(await makeTransportHost({
    channels: fabric.view(), listen: [{ label: "tcp", host: "loopback", port: 0 }],
    transportConfig: { peers: [`${B.peerId.toUpperCase()}.${hexOf(CONTACT)}@127.0.0.1:${B.driver.portOf("tcp")}`] },
  }));
  await ready(A, 4000);
  assert(await linkedTo(A, B.peerId), "the configured peer is dialed, through its contact secret");
});

await test("CONCEALMENT: a responder says NOTHING to a caller without the contact secret", async (keep) => {
  // A node that speaks first gives away its identity to anyone who connects. A caller
  // without the contact secret must get silence, like any server waiting for its client
  // to speak.
  const chans = wirePair();
  // The caller presents its own contact secret, which is not the receiver's.
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
  // Identities are sent after the ephemeral-ephemeral DH instead of sealed to the
  // responder's static key (as Noise IK does): anything msg1 carries is readable by
  // whoever holds that static key, including an attacker who seizes the node years later
  // and replays a recording.
  const chans = wirePair();
  const st = keep(await linked(chans));
  await until(() => chans[0].sent.length > 0, 4000, "msg1");
  const msg1 = Buffer.from(chans[0].sent[0], "hex");
  assert(msg1.length === 1233, `hybrid msg1 should be 1233 bytes, got ${msg1.length}`);
  assert(!msg1.includes(Buffer.from(st.A.peerId, "hex")), "msg1 must not carry the initiator identity");
});

await test("CONTACT SECRET: the address book alone does not grant a probe", async (keep) => {
  // Every peer with this node's address also has its static key, so without a contact
  // secret a leaked address book allows probing: elicit msg2, confirm which identity is at
  // that host, and keep doing it after being removed from the member set. With one, a
  // leaked address reveals nothing more.
  const chans = wirePair();
  // The caller knows B's address (and so its static key) but not B's contact secret; the
  // secret it presents does not match.
  const st = keep(await linked(chans, { contactSecret: new Uint8Array(32).fill(9) }));
  await settle();
  assert(chans[1].sent.length === 0, `outsider drew ${chans[1].sent.length} message(s); must draw none`);
  assert(!(await aUp(st)) && !(await bUp(st)), "a wrong contact secret must not authenticate");
});

await test("FRAME CAP: an over-cap pre-auth frame draws the silence every refusal draws", async (keep) => {
  // A stranger who knows only host:port must not reserve memory by declaring a big frame
  // and sending the body slowly, nor learn anything from the refusal. Almost every random
  // 4-byte prefix declares more than the 8 KiB cap, so closing at once would let four
  // random bytes tell a scanner that this is a node, which a wrong contact secret never
  // does. The frame is dropped unbuffered and the socket held to the same deadline as any
  // refusal. Both shapes: a length prefix on a stream, and a whole platform-framed message.
  for (const [stream, bytes] of [[true, Uint8Array.of(0x00, 0x01, 0x00, 0x00)], [false, new Uint8Array(9000)]]) {
    const chans = wirePair({ stream });
    const factory = new InjectedChannels();
    let reason = null;
    const B = await makeTransportHost({
      channels: factory, contactSecret: CONTACT,
      transportConfig: { unverifiedTimeoutMs: 1000 },
      onLinkClosed: (_id, r) => { reason = r; },
    });
    keep({ close() { try { B.shell.close(); } catch { /* already down */ } } });
    factory.give(chans[1]);
    await settle(50);
    chans[1].msg(bytes);
    await settle(100);
    const shape = stream ? "an over-cap length prefix" : "an over-cap message";
    assert(reason === null, `${shape} must not close the socket on sight`);
    assert(chans[1].sent.length === 0, `…nor draw a byte (drew ${chans[1].sent.length})`);
    await until(() => reason !== null, 3000, "the unverified deadline to retire it");
    // `refused`, not `timeout`: the peer sent something wrong, a different problem from a
    // caller that went quiet. The distinction is local, never on the wire.
    assert(reason === "refused", `${shape} should read REFUSED, got ${reason}`);
  }
});

await test("FRAME CAP: authentication raises it, before anything can arrive under it", async (keep) => {
  // A dialer authenticates at msg2 and may send application data right after msg3, which
  // the responder can read in the same delivery. The responder raises its cap only once
  // msg3 has been handled (becomeAuthed), so the framer must measure what follows msg3
  // after that, or it holds a full-size first record to the handshake cap and kills the
  // link on its first real exchange.
  const chans = wirePair({ stream: true });
  chans[0].hold(); // A's writes: msg1 alone, then msg3 and whatever follows it as one read
  const st = keep(await linked(chans));
  await until(() => chans[0].held.length === 1, 4000, "msg1");
  chans[0].flush();
  chans[0].hold();
  await until(() => aUp(st), 4000, "the dialer to authenticate");
  // Far over the pre-auth cap, well inside the post-auth one (maxFrameBytes is 2 MiB).
  const answer = st.A.request(st.B.peerId, PROTO, new Uint8Array(64 * 1024).fill(7), 4000)
    .then((r) => r, () => null);
  await until(() => chans[0].held.length === 2, 4000, "msg3 and a record behind it");
  assert(chans[0].flush() === 2, "msg3 and the record must arrive as ONE read");
  const got = await answer;
  assert(got !== null && got.length === 64 * 1024, "the record behind msg3 must cross under the raised cap");
  assert(!st.a.closed && !st.b.closed, "and neither end may close the link over it");
});

await test("A REFUSED SEND fails the link, never one record", async (keep) => {
  // `link/send` is awaited and counted in bytes, so the occupant's own host-call budget can
  // refuse a write the driver never sees, and `host.call` throws that synchronously.
  // Ignoring it would leave a gap in a nonce-ordered stream, and the peer would tear the
  // link down as a forgery, blaming it for this end's backpressure.
  let refuse = false;
  const chans = wirePair();
  const st = keep(await linked(chans, {
    onHostCall: (name) => {
      if (refuse && name === "link/send") throw new Error("guest: budget refused this write");
    },
  }));
  await until(async () => (await aUp(st)) && (await bUp(st)), 4000, "handshake");
  refuse = true;
  await st.A.sendNoReply(st.B.peerId, PROTO, Uint8Array.of(1));
  await until(() => st.a.closed, 4000, "the refused write must end the link");
  assert(st.a.closed, "a record that could not be issued must fail its link");
});

await test("A REFUSED CLOSE still retires the link, and the socket follows on a later tick", async (keep) => {
  // `link/close` is a host call too, so the budget pressure that tears a link down can
  // refuse the close itself. The link must still leave routing at once (a dead link left
  // routable swallows every frame sent to its peer), and the close is retried until the
  // host accepts it, or the peer keeps a link this end has forgotten.
  let refusing = false, refused = 0, forge = false;
  const chans = wirePair({
    tamper: (bytes, from) => {
      if (from !== "B" || !forge) return bytes;
      const forged = Uint8Array.from(bytes);
      forged[forged.length - 1] ^= 1;
      return forged;
    },
  });
  const st = keep(await linked(chans, {
    onHostCall: (name) => {
      if (refusing && name === "link/close") { refused++; throw new Error("guest: budget refused the close"); }
    },
  }));
  await until(async () => (await aUp(st)) && (await bUp(st)), 4000, "handshake");
  refusing = true;
  forge = true;
  await st.B.sendNoReply(st.A.peerId, PROTO, Uint8Array.of(1)); // A aborts on the forged record
  await until(() => refused > 0, 4000, "the close to be refused");
  await until(async () => !(await aUp(st)), 1000, "the refused link to leave routing");
  assert(!chans[0].dead, "the socket stays open while the host refuses to close it");
  refusing = false;
  await until(() => chans[0].dead, 2000, "the owed close, asked again on a later tick");
});

await test("PRE-AUTH QUEUE: tiny frames are bounded by count", async (keep) => {
  let msg1 = null;
  let holdHandshake = true;
  const chans = wirePair({
    tamper: (bytes, from) => {
      if (from === "A" && holdHandshake) { msg1 = Uint8Array.from(bytes); return null; }
      return bytes;
    },
  });
  const st = keep(await linked(chans, { transportConfig: { maxPreAuthQueueSlices: 8 } }));
  await until(() => msg1 !== null, 4000, "the held msg1");
  for (let i = 0; i < 12; i++) {
    await st.A.sendNoReply(st.B.peerId, PROTO, Uint8Array.of(i));
  }

  holdHandshake = false;
  chans[1].msg(msg1);
  await until(async () => (await aUp(st)) && (await bUp(st)), 4000, "handshake after queueing");
  await until(async () => (await st.B.seen()).length === 8, 4000, "the bounded queue to flush");
  const seen = await st.B.seen();
  assert(seen.every((payload, i) => payload[0] === i + 4),
    `the queue must retain only its newest 8 frames (got ${seen.map((p) => p[0]).join(",")})`);
});

await test("REASSEMBLY: a frame dribbled one byte at a time is still one message", async (keep) => {
  // A full-size frame arriving byte by byte is where both naive assemblers fail: quadratic
  // copying if every slice is joined onto one buffer, ~50x the cap in held chunks if none
  // are. The framer's merge rule (framing.js): arbitrary slice boundaries in, exactly one
  // message out.
  let armed = false;
  const chans = wirePair({ stream: true, tamper: (b, from) => (from === "A" && armed ? null : b) });
  const st = keep(await linked(chans));
  await until(async () => (await aUp(st)) && (await bUp(st)), 4000, "handshake");
  const proto = PROTO;
  // Above the pre-auth cap, so it must be measured against the raised cap (the FRAME CAP
  // tests cover the raise itself).
  const payload = new Uint8Array(48 * 1024).fill(0x5a);
  armed = true; // from here on, drop A's real delivery; it is re-fed manually below
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
  // The merge rule has four paths (new accumulator, room left, grow, large slice kept as
  // it arrived), and slices crossing the threshold in both directions turn a boundary error
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
  // The size check is the first thing `send` does, and it fails loudly: the app's own
  // `_net` call rejects by name. Checking after the copies would let a co-resident app
  // sending a 50 MiB payload take the transport realm down before the check ran.
  const st = keep(await upPair());
  let refused = "";
  try { await st.A.request(st.B.peerId, PROTO, new Uint8Array(3 * 1024 * 1024)); }
  catch (e) { refused = String(e); }
  assert(refused.includes("over the frame cap"), `an over-cap send must be refused, got ${refused || "no error"}`);
  // And a malformed destination, checked before the hex conversion.
  let badTo = "";
  // noReply, to(0), proto (the harness app's own, which it may send under), payload(0)
  const proto = new TextEncoder().encode(PROTO);
  const args = new Uint8Array(1 + 4 + 4 + proto.length + 4);
  args[8] = proto.length;
  args.set(proto, 9);
  try { await st.A.op("send", args); } catch (e) { badTo = String(e); }
  assert(badTo.includes("32-byte peer id"), `a malformed peer id must be refused, got ${badTo || "no error"}`);
  assert(!st.a.closed && !st.b.closed, "a refused send must not disturb the link");
});

await test("SEND CLAIMS: an app sends only under the protocols it claims", async (keep) => {
  // The protocol id is all that says which app a frame is for at the far end (§12.10), so a
  // send under one the app does not claim is refused, as is one that does not lie within its
  // bytes. The embedder's own door to the transport is not an app's.
  const st = keep(await upPair());
  let refused = "";
  try { await st.A.request(st.B.peerId, "someone/else", Uint8Array.of(1)); }
  catch (e) { refused = String(e); }
  assert(refused.includes('does not claim "someone/else"'), `a send under another's id must be refused by name, got ${refused || "no error"}`);
  const ok = await st.A.request(st.B.peerId, PROTO, Uint8Array.of(4, 5));
  assert(ok.length === 2 && ok[1] === 5, "and one under its own still goes through");
  const { sendProtocol, OpArgs } = await import("../build/services/op-frame.js");
  const whole = new OpArgs("send").u8(1).blob(new Uint8Array(32)).blob(Uint8Array.of(0x63, 0x68)).blob(Uint8Array.of(9)).build();
  assert(sendProtocol(whole) === "ch" && sendProtocol(new OpArgs("peers").build()) === null, "the protocol is read off a send, and off nothing else");
  for (let cut = 0; cut < whole.length - 5; cut++) {
    let threw = false;
    try { sendProtocol(whole.subarray(0, cut)); } catch { threw = true; }
    assert(threw, `a send cut at ${cut} bytes must be refused`);
  }
});

await test("OUTBOUND QUEUE: authenticated encryption work is bounded", async (keep) => {
  // Hold A's first post-auth seal below the guest realm. Every later send can return to
  // its app but stays on Link's ordered work chain, the queue a peer that refuses to read
  // could otherwise grow without hitting a socket-side limit.
  let stallSeals = false;
  let releaseSeal = null;
  const slowSodium = Object.create(sodium);
  Object.defineProperty(slowSodium, "crypto_aead_chacha20poly1305_ietf_encrypt", {
    value: (...args) => {
      const seal = () => sodium.crypto_aead_chacha20poly1305_ietf_encrypt(...args);
      if (!stallSeals) return seal();
      return new Promise((resolve) => { releaseSeal = () => resolve(seal()); });
    },
  });

  // A 512-byte frame cap makes the matching eight-frame work window 4096 bytes, small
  // enough to cross without allocating the production 16 MiB in this regression test.
  const cfg = { maxFrameBytes: 512 };
  const st = keep(await upPair(undefined,
    { sodium: slowSodium, transportConfig: cfg },
    { transportConfig: cfg }));
  stallSeals = true;
  const payload = new Uint8Array(400); // wire plaintext frame: 6 + PROTO.length + 400
  await st.A.sendNoReply(st.B.peerId, PROTO, payload);
  await until(() => releaseSeal !== null, 3000, "the first authenticated seal to stall");

  // Nine such frames fit (3744 bytes); the tenth would take the queued plaintext to
  // 4160 and must abort the link. No partial ordered record is silently discarded.
  for (let i = 1; i < 10; i++) await st.A.sendNoReply(st.B.peerId, PROTO, payload);
  // abort() tears down behind the active crypto step so it cannot zero a key that step is
  // using. Release only that first seal: if the ceiling did not set `closed`, the next
  // queued seal stalls and this assertion times out.
  const releaseFirstSeal = releaseSeal;
  releaseSeal = null;
  releaseFirstSeal();
  await until(() => st.a.closed, 3000, "the outbound encryption queue to close its link");
  assert(st.a.reason === "local",
    `an outbound queue overflow must be a local abort, got reason ${st.a.reason}`);
});

await test("IDLE: an authenticated link carrying no traffic is retired", async (keep) => {
  // The handshake deadlines stop applying once a link authenticates, so without an idle
  // clock a quiet link is held forever with its framer, session keys, timers and buffers.
  // It is closed with the authenticated goodbye, a deliberate local shutdown, so the far
  // end sees a clean close, not a truncation.
  const st = keep(await upPair(undefined, { linkIdleTimeoutMs: 60 }, { linkIdleTimeoutMs: 60 }));
  await until(() => st.a.closed, 4000, "the idle clock to retire a silent link");
  assert(st.a.reason === "local" || st.a.reason === "clean",
    `an idle retirement is a deliberate close, got reason ${st.a.reason}`);
});

await test("IDLE: traffic keeps a link alive across the clock", async (keep) => {
  // The other half: the clock must measure silence, not age. A link exchanging frames
  // across several windows must survive them all.
  const st = keep(await upPair(undefined, { linkIdleTimeoutMs: 80 }, { linkIdleTimeoutMs: 80 }));
  for (let i = 0; i < 8; i++) {
    const r = await st.A.request(st.B.peerId, PROTO, Uint8Array.from([i]));
    assert(r[0] === i, `frame ${i} did not come back — the link died under its idle clock`);
    await settle(40);
  }
  assert(!st.a.closed && !st.b.closed, "a link with traffic on it must not be retired");
});

await test("CLOSING: a request sent while its link closes redials instead of vanishing", async (keep) => {
  // A link leaves routing as soon as it closes, not once its queued teardown has run, since
  // until then it could only drop a frame routed to it. Here the idle clock closes A's link
  // and its goodbye is slow; a request sent meanwhile must go out on a new dial instead of
  // into the closing link, where it would fail when that link finally goes.
  const fabric = new LoopbackChannels();
  let slowNext = false, onGoodbye = null;
  const A = keep(await makeTransportHost({
    channels: fabric.view(), listen: [{ label: "tcp", host: "loopback", port: 0 }], linkIdleTimeoutMs: 200,
    onHostAnswer: (name, answer) => {
      if (name !== "link/send" || !slowNext) return answer;
      slowNext = false;
      onGoodbye();
      return new Promise((r) => setTimeout(() => r(answer), 500));
    },
  }));
  const B = keep(await makeTransportHost({ channels: fabric.view(), listen: [{ label: "tcp", host: "loopback", port: 0 }] }));
  await A.addr(B.peerId, `tcp://127.0.0.1:${B.driver.portOf("tcp")}`);
  await A.request(B.peerId, PROTO, Uint8Array.of(1));
  const closing = new Promise((r) => { onGoodbye = r; });
  slowNext = true; // A's next write is the idle close's goodbye record
  await closing;
  const got = await A.request(B.peerId, PROTO, Uint8Array.of(2), 4000).then((r) => r, () => null);
  assert(got !== null && got[0] === 2, "a request sent while its link closed must be answered over a fresh dial");
});

await test("READY: a second ready() does not strand the first", async (keep) => {
  // A single waiter slot would let the second call overwrite the first, leaving the first
  // caller's promise to the second's timer, or to nothing. It is a list in the transport
  // guest, and each caller has its own deferred.
  const st = keep(await upPair());
  const [r1, r2] = await Promise.all([
    ready(st.A, 50).then(() => "ok", () => "failed"),
    ready(st.A, 50).then(() => "ok", () => "failed"),
  ]);
  assert(r1 === "ok" && r2 === "ok", `both ready() calls must settle (got ${r1}/${r2})`);
});

await test("TIE-BREAK: a dial that loses hands what it queued to the link that won", async (keep) => {
  // Two nodes dialing each other at once keep one link, the one the smaller identity
  // dialed. A request queued on the larger identity's dial while it was still handshaking
  // must not die with that dial; the winning link carries it.
  let [ia, ib] = [generateKeyPair(), generateKeyPair()];
  if (Buffer.compare(Buffer.from(ia.publicKey), Buffer.from(ib.publicKey)) < 0) [ia, ib] = [ib, ia];
  const losing = wirePair();
  losing[1].hold(); // A's dial stalls before msg2, so the request queues on it
  const st = keep(await linked(losing, { identity: ia }, { identity: ib }));
  const answer = st.A.request(st.B.peerId, PROTO, Uint8Array.of(1, 2, 3), 4000).then((r) => r, () => null);
  await settle(50);
  await openPair(st.B, st.A, wirePair({ addrA: "10.0.0.3", addrB: "10.0.0.4" })); // B dials A, and wins
  await until(async () => (await aUp(st)) && (await bUp(st)), 4000, "B's dial");
  losing[1].flush(); // A's dial completes, and loses the tie-break
  const got = await answer;
  assert(got !== null && got.length === 3 && got[2] === 3, "the queued request must be answered over the winning link");
});

await test("TIE-BREAK: records a losing dial sent behind msg3 are read, not dropped", async (keep) => {
  // A dialer authenticates at msg2 and sends behind msg3, before the far end has run the
  // tie-break. In a symmetric double connect the far end has already authenticated its own
  // (winning) dial by then, so if it closed the loser on sight it would drop those records
  // unread. Only the loser's dialer may close it; the accepting end reads until its goodbye.
  let [ia, ib] = [generateKeyPair(), generateKeyPair()];
  if (Buffer.compare(Buffer.from(ia.publicKey), Buffer.from(ib.publicKey)) < 0) [ia, ib] = [ib, ia];
  // Stream pairs: a flush delivers several writes as one read, which only a framer splits.
  const losing = wirePair({ stream: true });
  losing[0].hold(); // A's msg1
  const st = keep(await linked(losing, { identity: ia }, { identity: ib }));
  await settle(50);
  const winning = wirePair({ stream: true, addrA: "10.0.0.3", addrB: "10.0.0.4" });
  winning[0].hold(); // B's msg1
  await openPair(st.B, st.A, winning); // B dials A, and wins
  await settle(50);
  winning[0].flush();
  winning[0].hold(); // B's msg3 waits, so A has not yet seen the winner
  await until(() => bUp(st), 4000, "B's dial");
  const answer = st.A.request(st.B.peerId, PROTO, Uint8Array.of(1, 2, 3), 4000).then((r) => r, () => null);
  await settle(20);
  losing[0].flush();
  losing[0].hold(); // A's msg3 and the request record behind it
  await until(() => aUp(st), 4000, "A's dial");
  await settle(50);
  assert(losing[0].held.length === 2, `msg3 and the record must both be in flight (got ${losing[0].held.length})`);
  losing[0].flush(); // B authenticates the loser only now, with its own dial already up
  await settle(50);
  winning[0].flush(); // A sees the winner and closes its losing dial
  const got = await answer;
  assert(got !== null && got.length === 3 && got[2] === 3, "the request sent on the losing link must be answered");
  await until(async () => losing[0].dead, 4000, "the losing dial closed");
  assert((await aUp(st)) && (await bUp(st)), "both ends must stay linked over the winner");
});

await test("SUBKEYS: one master seed, one derived identity, deterministic", async () => {
  const { deriveNodeKey } = await import("../build/services/subkeys.js");
  const master = new Uint8Array(32).fill(5);
  const a = deriveNodeKey(sodium, master), b = deriveNodeKey(sodium, master);
  // Deterministic: a node rebuilds its key at boot from the one secret it stores.
  assert(hexOf(a.publicKey) === hexOf(b.publicKey), "derivation must be deterministic");
  const other = deriveNodeKey(sodium, new Uint8Array(32).fill(6));
  assert(hexOf(a.publicKey) !== hexOf(other.publicKey), "different masters, different keys");
  // The master itself is never a signing key, only a derivation input.
  assert(hexOf(a.privateKey) !== hexOf(master), "the master seed must not be used as a key");
  // One key: purposes are kept apart by the domain and scope the host puts into every
  // preimage, not by a second keypair (services/subkeys.ts).
  assert(!("channel" in a), "derivation returns the keypair directly");
});

await test("NETWORK KEY: honest transports on different networks cannot link", async (keep) => {
  // Separation, not access control: the network key seeds the transcript, so every
  // derived key and signature preimage differs and the handshake fails at the first
  // message. A staging fleet and a production one can share addresses, configs and
  // operators and still never connect.
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

  const publicPair = keep(await upPair(undefined, {}, { networkKey: new Uint8Array(32) }));
  assert((await aUp(publicPair)) && (await bUp(publicPair)),
    "an absent network key selects the same public network as an explicit zero key");
});

await test("CONTACT SECRET: absent means OPEN — the node still conceals identities", async (keep) => {
  // An open node answers anyone, which affects DoS exposure and caller privacy but does
  // not leak identities. The message ordering does the concealing, so even on an open node
  // neither public key crosses the wire.
  const st = keep(await upPair(undefined, { contactSecret: undefined }, { contactSecret: undefined }));
  const wire = [...st.chans[0].sent, ...st.chans[1].sent].join("");
  for (const [name, id] of [["caller", st.A.peerId], ["receiver", st.B.peerId]]) {
    assert(!wire.includes(id), `${name} identity in cleartext on an open node`);
  }
});

await test("CONTACT SECRET: it is the RECEIVER's, and only the receiver's", async (keep) => {
  // Per node, not per deployment or pair: a caller must present the secret of the node it
  // is dialing, so a leak exposes one node's inbound side, not the network.
  const secretB = new Uint8Array(32).fill(11);
  const secretC = new Uint8Array(32).fill(22);
  const st = keep(await upPair(undefined, { contactSecret: secretB }, { contactSecret: secretB }));
  assert((await aUp(st)) && (await bUp(st)), "the right secret must open the door");
  st.close();

  // The caller presents node C's contact secret while dialing node B.
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
  const A = await makeTransportHost({ channels: aFactory, contactSecret: secretB, connsPerPeer: 64 });
  const B = await makeTransportHost({ channels: bFactory, contactSecret: secretB, connsPerPeer: 64 });
  A.factory = aFactory;
  B.factory = bFactory;
  keep(async () => { try { A.shell.close(); } catch { /* already down */ } try { B.shell.close(); } catch { /* already down */ } });
  // Counts reinstalls: the rotation below must not cause one.
  let loads = 0;
  const origLoad = B.shell.install;
  B.shell.install = async (blob, opts) => { loads++; return origLoad(blob, opts); };

  // The boot-time secret works on both sides.
  const c1 = wirePair();
  await openPair(A, B, c1, secretB);
  await until(async () => (await linkedTo(A, B.peerId)) && (await linkedTo(B, A.peerId)),
    4000, "boot-time secret");

  // Rotate B's secret; A still presents the old value. The responder says nothing at all,
  // checked on this pair's own wire, since the node-level peer set already reads "linked"
  // from the surviving c1 link.
  await contact(B, secretC);
  const c2 = wirePair();
  await openPair(A, B, c2, secretB);
  await settle();
  assert(c2[1].sent.length === 0, `the stale secret drew ${c2[1].sent.length} message(s)`);

  // A now presents the new value too, and the handshake completes again, checked as wire
  // progress on c3 (msg1 and msg3 from the dialer, msg2 from the receiver) for the same
  // reason as above, without the guest being reinstalled.
  await contact(A, secretC);
  const c3 = wirePair();
  await openPair(A, B, c3, secretC);
  await until(() => c3[0].sent.length >= 2 && c3[1].sent.length >= 1, 4000, "rotated secret handshake");
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
  // `reset()` closes every live socket (after a rotation, links authenticated under the
  // old value go). The occupant is not replaced (this is the step a slot handover runs,
  // called directly), so afterwards a new link opens and authenticates without a reinstall.
  const st = keep(await upPair());
  const chans = st.chans;
  st.A.driver.reset();
  await until(() => st.b.closed, 3000, "the far end hears the links die");
  await settle();
  assert(chans[0].dead && chans[1].dead, "both sockets must be closed at the driver level");
  assert(st.A.driver.available(), "the raw-link binding must still be owned after a sever");

  const c2 = wirePair();
  await openPair(st.A, st.B, c2);
  await until(async () => (await aUp(st)) && (await bUp(st)), 4000, "re-link after a sever");
  assert(st.B.driver.available(), "the acceptor's binding must also still be owned");
});

await test("CONTACT SECRET: it never appears on the wire", async (keep) => {
  // It is mixed into the key schedule and no handshake carries it, which also makes it a
  // quantum hedge: an adversary who records a handshake and breaks X25519 later still needs
  // a value that handshake never sent.
  const st = keep(await upPair());
  const wire = [...st.chans[0].sent, ...st.chans[1].sent].join("");
  assert(!wire.includes(hexOf(CONTACT)), "contact secret leaked onto the wire");
});

await test("LEAK FIX: a link that closes itself mid-handshake still reports down", async (keep) => {
  // A's peer lint declines the key it dialed, so A refuses the verified msg2 (ake.js
  // onMsg2, `admits`) and aborts: a close from inside the guest.
  // `onLinkClosed` must still fire for a link that never authenticated: a channel whose
  // close() only set `dead` without firing onClose would leave such a link stuck in the
  // pre-auth bookkeeping forever.
  const chans = wirePair();
  const st = keep(await linked(chans,
    { admitPeers: [generateKeyPair().publicKey], transportConfig: { handshakeTimeoutMs: 80 } },
    { transportConfig: { handshakeTimeoutMs: 80 } }));
  await until(() => st.a.closed, 3000, "the self-close MUST reach onLinkClosed (this is the leak)");
  assert(st.a.reason === "refused", `a declined peer should read REFUSED, got ${st.a.reason}`);
  assert(!(await aUp(st)) && !(await bUp(st)), "a declined peer must not link");
});

await test("handshake deadline closes a link that never speaks", async (keep) => {
  const chans = wirePair(); // no peer link opened: nothing ever replies
  const factory = new InjectedChannels();
  let reason = null;
  const A = await makeTransportHost({
    channels: factory, contactSecret: CONTACT,
    transportConfig: { handshakeTimeoutMs: 60 },
    onLinkClosed: (_id, r) => { reason = r; },
  });
  keep({ close() { try { A.shell.close(); } catch { /* down */ } } });
  const nobody = hexOf(generateKeyPair().publicKey);
  await factory.dial(A, nobody, chans[0], CONTACT);
  await until(() => reason !== null, 3000, "the deadline to close the link and notify");
  assert(reason === "timeout",
    `a peer that never speaks is a TIMEOUT — the one an operator chases an address for — got ${reason}`);
  assert(!(await linkedTo(A, nobody)), "must not authenticate");
});

await test("DIAGNOSTIC: a socket that dies mid-handshake reads DROPPED, not the catch-all", async (keep) => {
  // "The other machine is not there": a refused connect, an unreachable host, a far end
  // that hangs up before authenticating. Checked against the real native binary:
  // `--peers <id>@127.0.0.1:9` prints exactly this. It must not read as `handshake`, which
  // covers local failures (a half-open budget evicting this link), nor as `timeout`, which
  // means the socket stayed open and went quiet.
  const chans = wirePair();
  let reason = null;
  const st = keep(await linked(chans, { onLinkClosed: (_id, r) => { reason = r; } }));
  await until(() => chans[0].sent.length > 0, 4000, "msg1 on the wire");
  chans[0].kill(); // the socket goes away with the handshake unfinished
  await until(() => reason !== null, 3000, "the dead socket to report down");
  assert(reason === "dropped",
    `a socket lost mid-handshake should read DROPPED, got ${reason}`);
  assert(!(await aUp(st)), "and nothing may be linked");
});

await test("DIAGNOSTIC: the driver prints a failing link and stays quiet about a healthy one", async (keep) => {
  // Why the close reason matters in a real deployment: an embedder that wired nothing
  // (seedstore's p2p CLI boots `bootShell` itself and never uses `onLinkClosed`) still
  // learns that its links are failing, and from which address. A healthy node must print
  // nothing, or the signal is useless.
  const lines = [];
  const realError = console.error;
  console.error = (...a) => { lines.push(a.join(" ")); };
  try {
    const chans = wirePair({ stream: true });
    const st = keep(await linked(chans, { suppressLinkLog: false }, { suppressLinkLog: false }));
    await until(async () => (await aUp(st)) && (await bUp(st)), 4000, "handshake");
    assert(lines.length === 0, `a healthy handshake printed ${JSON.stringify(lines)}`);

    // Cut A's socket under a live link: `truncated` at A, which is abnormal and must print.
    chans[0].kill();
    await until(() => lines.length > 0, 3000, "the cut link to be reported");
    assert(/^\[transport\] link \d+ from 10\.0\.0\.1 down: truncated$/.test(lines[0]),
      `the line must name the link, the address and the reason, got ${JSON.stringify(lines[0])}`);
  } finally {
    console.error = realError;
  }
});

await test("DIAGNOSTIC: the driver prints a reason above severity 0 as given, and only that", async (keep) => {
  // The occupant decides the words and their severity: a replacement transport's own
  // reasons print verbatim at any severity above 0, severity 0 prints nothing, and an empty
  // answer is an empty reason at severity 0.
  class ManualChannel { send() {} onData() {} onClose() {} close() {} }
  const word = (severity, s) => Uint8Array.of(severity, ...new TextEncoder().encode(s));
  const answers = [word(1, "gone fishing"), word(0, "bye"), word(7, "on fire"), new Uint8Array()];
  const opened = [];
  const downs = [];
  const factory = new InjectedChannels();
  const driver = keep(new TransportHost(
    { channels: factory, suppressLinkLog: false, onLinkClosed: (_id, r) => downs.push(r) },
  ));
  driver.activate(async (input) => {
    const { op, args } = opOf(input);
    if (op === "linkOpen") opened.push(new DataView(args.buffer, args.byteOffset).getUint32(0));
    return op === "linkClosed" ? answers.shift() : new Uint8Array();
  });
  await driver.start();
  const lines = [];
  const realError = console.error;
  console.error = (...a) => { lines.push(a.join(" ")); };
  try {
    for (let i = 0; i < 4; i++) factory.give(new ManualChannel());
    for (const id of opened) {
      driver.rawNet().close(id, false);
      await until(() => downs.length === opened.indexOf(id) + 1, 1000, `link ${id} to report down`);
    }
  } finally {
    console.error = realError;
  }
  assert(JSON.stringify(downs) === JSON.stringify(["gone fishing", "bye", "on fire", ""]),
    `onLinkClosed must see each reason as given, got ${JSON.stringify(downs)}`);
  assert(JSON.stringify(lines) === JSON.stringify([
    `[transport] link ${opened[0]} down: gone fishing`, `[transport] link ${opened[2]} down: on fire`]),
    `only reasons above severity 0 print, verbatim, got ${JSON.stringify(lines)}`);
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
  // The deliberate close comes from A's idle clock, as in the IDLE tests: silence for the
  // timeout, then the authenticated goodbye.
  const st = keep(await upPair(undefined, { linkIdleTimeoutMs: 60 }));
  await until(() => st.b.closed, 3000, "B to see the authenticated end-of-stream");
  assert(st.b.reason === "clean", `a clean close must read CLEAN, got ${st.b.reason}`);
});

await test("goodbye: a cut connection reads as truncated", async (keep) => {
  const st = keep(await upPair());
  st.chans[0].kill(); // the socket dies with no goodbye
  await until(() => st.b.closed, 3000, "B to notice the cut");
  assert(st.b.reason === "truncated", `B must report a truncation, got ${st.b.reason}`);
});

await test("goodbye is not delivered to the application as a frame", async (keep) => {
  // A's idle clock closes the link once the one real request has finished, with enough
  // headroom that the request settles well before the timeout fires.
  const st = keep(await upPair(undefined, { linkIdleTimeoutMs: 150 }));
  const proto = PROTO;
  await st.A.request(st.B.peerId, proto, new TextEncoder().encode("real"));
  await until(() => st.b.closed, 3000, "the idle clock to retire the link");
  await settle(100);
  // What the far app received, asked of the app itself.
  const seen = (await st.B.seen()).map((b) => Buffer.from(b).toString());
  assert(seen.length === 1 && seen[0] === "real", `goodbye leaked into the app: ${JSON.stringify(seen)}`);
});

await test("goodbye: the CLOSER reports a local shutdown, not a truncation", async (keep) => {
  // The trap this covers: defining truncation as `authed && !peerSaidGoodbye` is true on
  // the closing side of every deliberate close (it sends the goodbye and never gets one
  // back), and the double-connect tie-break closes links routinely, so that definition
  // would report a routine event as a cut stream.
  const st = keep(await upPair(undefined, { linkIdleTimeoutMs: 60 }));
  await until(() => st.a.closed && st.b.closed, 3000, "both ends to close");
  assert(st.a.reason === "local", `closer should read LOCAL, got ${st.a.reason}`);
  assert(st.b.reason === "clean", `peer should read CLEAN, got ${st.b.reason}`);
});

await test("goodbye: an injected junk record must NOT produce a farewell", async (keep) => {
  // The attack the close/abort split exists to stop. An on-path attacker corrupts one
  // record A->B; B cannot decrypt it and tears the link down, but if that teardown sent an
  // end-of-stream record, B would give A a genuine, correctly keyed goodbye and A would
  // read an attacker-chosen moment as a clean shutdown. The attacker forges nothing; they
  // make the victim say goodbye.
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
  assert(st.b.reason === "aborted", `victim should read ABORTED, got ${st.b.reason}`);
  assert(st.a.reason === "truncated", `far end should read TRUNCATED, got ${st.a.reason}`);
});

await test("a graceful close asks the transport to flush; an abort does not", async (keep) => {
  // The graceful half is the idle clock's close.
  const st = keep(await upPair(undefined, { linkIdleTimeoutMs: 60 }));
  await until(() => st.chans[0].closeArgs.length > 0, 3000, "the channel close");
  assert(st.chans[0].closeArgs[0] === true, `close() after a farewell must request a flush, got ${st.chans[0].closeArgs[0]}`);
  st.close();

  // A failure path closes the channel instead, which must read as a cut on the far end.
  const st2 = keep(await upPair());
  st2.chans[0].close(false);
  await until(() => st2.b.closed, 3000, "the far end to notice");
  assert(st2.b.reason === "truncated", `an abort must read as a cut, got ${st2.b.reason}`);
});

await test("the farewell survives a transport that discards unflushed writes", async (keep) => {
  // A TCP socket destroyed instead of ended drops the record it was just given, so the
  // mechanism would silently do nothing on the most common transport. This fails unless
  // close() both writes the record and asks for a graceful teardown. The close comes from
  // the idle clock.
  const st = keep(await upPair({ destructive: true }, { linkIdleTimeoutMs: 60 }));
  await until(() => st.b.closed, 3000, "the farewell to arrive");
  assert(st.b.reason === "clean", `expected CLEAN, got ${st.b.reason} (the farewell was discarded)`);
});

await test("WHITELIST: absent by default, and an absent hook admits everyone", async (keep) => {
  // The hook is a seam, not a requirement: a deployment that sets nothing gets a network
  // that links to anyone who holds the contact secret, which is the sane default.
  const st = keep(await upPair());
  assert((await aUp(st)) && (await bUp(st)), "no whitelist configured must mean admit-all");
});

await test("GUARD: a refused caller is closed at msg3 and never sees the receiver's key", async (keep) => {
  // The receiver signs at msg2 but never sends its key: the caller checks the signature
  // against the key it dialed. The lint runs in the guest's onMsg3, on a verified identity.
  // It closes instead of stalling: the caller already verified the receiver, so silence
  // would hide nothing and only leave the caller sending into a link that never answers.
  const chans = wirePair();
  // The receiver's list names only a key nobody holds, so it admits nobody. The lint is
  // the transport's own (ake.js `admits`), read from its config.
  const st = keep(await linked(chans, {}, { admitPeers: [new Uint8Array(32).fill(1)] }));
  await until(() => st.b.closed && st.a.closed, 4000, "the refusal to close both ends");
  assert(st.b.reason === "refused", `the receiver should read REFUSED, got ${st.b.reason}`);
  assert(!(await bUp(st)), "a refused caller must not be authenticated by the receiver");
  assert(!(await aUp(st)), "a refused caller must not keep a link");
  // msg2 is all the receiver ever sends, and its key is never in it.
  assert(chans[1].sent.length === 1, `refused caller drew ${chans[1].sent.length} messages, want 1`);
  assert(!chans[1].sent.join("").includes(st.B.peerId),
    "the receiver put its key on the wire");
});

await test("a decrypt failure does not advance the receive counter", async (keep) => {
  // Flip a byte in the first post-auth record. The link must die instead of losing sync
  // (the flynn/noise bug).
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

// ── §12.10: a slot's own answer reaches its installer through onInbound ────────────
// Dispatch is one claim-to-slot map. An embedder has no other way to see what its own app
// answered, since a peer-inbound frame's reply goes straight back out on the wire.
// `InstallOptions.onInbound` provides that, scoped to the install that set it, not the
// shell, so there is no table, owner or name to contest.
await test("a peer-inbound answer reaches the installer through onInbound", async (keep) => {
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
  const watcher = await st.B.shell.install(blob, {
    onInbound: (claim, from, answer) => seen.push({ claim, from: Buffer.from(from).toString("hex"), answer }),
  });

  const resp = await st.A.requestAsHost(st.B.peerId, "watch/v1", Uint8Array.from([1, 2, 3]));
  assert(resp.length === 3 && resp[0] === 0xfe && resp[1] === 0xfd && resp[2] === 0xfc,
    `the caller must still get the app's own answer untouched, got ${[...resp]}`);
  assert(seen.length === 1, "onInbound must fire exactly once per peer-inbound answer");
  assert(seen[0].claim === "watch/v1", "…named the claim the frame arrived on");
  assert(seen[0].from === st.A.peerId,
    "…and the AUTHENTICATED sender, exactly as dispatch attributes it");
  assert(bytesEqual(seen[0].answer, resp), "…carrying exactly the bytes the caller received");

  // The host loopback path already has its return value, and onInbound is only wired for
  // the peer path, so invoking the same slot as the host must not fire it.
  await watcher.invoke(Uint8Array.from([9, 9]));
  assert(seen.length === 1, "a host loopback invoke of the same slot must not fire onInbound");
});

// A peer names the id the transport itself claims. The transport passes on what it
// decoded without reading the protocol bytes, so the routing has to refuse it: the
// transport declares `_net` under `services`, never `protocols`, and inbound delivery only
// reaches the latter (§12.10). If it were reachable, this frame would land in the
// transport realm's `handle` with the sender's key as caller id, which `APP_OPS` admits,
// and `peers` would list the node's links.
await test("a peer cannot reach a bundle's local service claim, the transport's included", async (keep) => {
  const st = keep(await upPair());
  const opEnvelope = (op) => {
    const n = Buffer.from(op, "utf8");
    return Uint8Array.from([n.length, ...n]);
  };
  const peers = await st.A.requestAsHost(st.B.peerId, "_net", opEnvelope("peers"));
  assert(peers.length === 0,
    `the transport's own claim must not answer a peer, got ${peers.length} bytes: ${hexOf(peers)}`);
  // Never delivered, not just unanswered: the ordinary claim still works on the same link,
  // so this is a routing rule, not a link that stopped carrying frames.
  const ordinary = await st.A.request(st.B.peerId, PROTO, Uint8Array.from([4, 5]));
  assert(ordinary.length === 2 && ordinary[1] === 5, "the app's own id still answers over the same link");
});

// ── delivery, when one read carries several requests ─────────────────────────
// The link occupant passes each request it decodes to the shell's claim table as its own
// `link/deliver` call (§12.10), naming the authenticated sender, since it saw the
// plaintext. Several requests per socket read is normal on a byte stream, and one call
// each keeps them separate: nothing packs them into a shared buffer whose framing a
// peer's payload bytes could imitate.
await test("DELIVERY: two pipelined requests in ONE read are two correctly attributed deliveries", async (keep) => {
  // Stream framing permits one read to contain multiple messages.
  const st = keep(await upPair({ stream: true }));
  const first = Uint8Array.from([0x11, 0x22, 0x33]);
  // The second request's payload is crafted to look like a framed record naming another
  // claim and sender. It must stay plain bytes: the delivery path never parses a payload.
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

  // Polled here instead of with `until`, so the last `seen` result is kept.
  let seen = [], from = [];
  for (const started = Date.now(); Date.now() - started < 4000;) {
    seen = await st.B.seen();
    if (seen.length >= 2) break;
    await settle(10);
  }
  from = await st.B.from();
  assert(seen.length === 2, `exactly two deliveries, got ${seen.length}`);
  // Each payload is whole and separate: neither swallowed the one behind it.
  assert(hexOf(seen[0]) === hexOf(first), `first payload intact, got ${hexOf(seen[0])}`);
  assert(hexOf(seen[1]) === hexOf(second), `second payload intact, got ${hexOf(seen[1])}`);
  // Both are attributed to the peer that actually sent them, never to the key the second
  // payload names.
  assert(from.length === 2 && from.every((f) => f === st.A.peerId),
    `both deliveries must be attributed to the sending peer, got ${from.join(", ")}`);
  assert(!from.includes(hexOf(forgedAttribution)),
    "a payload's own bytes must never become another delivery's attribution");
});

// ── the transport guest's caller boundary ────────────────────────────────────
// The platform events (`linkBytes`, `linkClosed`, ...) are for the host only; an app may
// name `send` and `peers`, since both concern its own traffic. An app that could inject
// link bytes could forge traffic from a peer.

await test("CALLER BOUNDARY: an app may name `peers`, but not a platform event", async (keep) => {
  const st = keep(await upPair());
  await until(async () => (await st.B.peers()).length > 0, 4000, "B's link to A");
  // `peers` through the app's seam: a cross-realm call carrying the app's id, not the
  // host's 32 zero bytes. seedstore's guest uses this path to place replicas.
  const raw = await st.B.op("peers");
  assert(raw.length === 32 && hexOf(raw) === st.A.peerId,
    "an app asking `peers` must get the authenticated set back");
  // `linkBytes` through the same seam must be refused by name, not silently ignored.
  let refused = "";
  try { await st.B.op("linkBytes", new Uint8Array(8)); }
  catch (e) { refused = String(e); }
  assert(refused.includes("the host's, not an app's"),
    `an app naming a platform event must be refused, got ${refused || "no error"}`);
});

// A raw read is accepted only while its channel can be held at the socket boundary.
await test("DRIVER BACKPRESSURE: one blocked read cannot fill the realm queue", async (keep) => {
  class PausableChannel {
    data = null;
    closed = null;
    paused = false;
    pauses = 0;
    resumes = 0;
    send() {}
    onData(cb) { this.data = cb; }
    onClose(cb) { this.closed = cb; }
    setReadable(enabled) {
      this.paused = !enabled;
      if (enabled) this.resumes++; else this.pauses++;
    }
    close() {}
    emit(bytes = Uint8Array.of(1)) {
      if (this.paused) return false;
      this.data?.(bytes);
      return true;
    }
  }

  let releaseRead;
  const blockedRead = new Promise((resolve) => { releaseRead = resolve; });
  let acceptedReads = 0;
  const factory = new InjectedChannels();
  const driver = keep(new TransportHost({ channels: factory }));
  driver.activate((input) => {
    if (opOf(input).op === "linkBytes") { acceptedReads++; return blockedRead; }
    return Promise.resolve(new Uint8Array());
  });
  await driver.start();
  const channel = new PausableChannel();
  factory.give(channel);
  await settle(0);

  let deliveredBySocket = 0;
  for (let i = 0; i < 1000; i++) if (channel.emit()) deliveredBySocket++;
  assert(deliveredBySocket === 1 && acceptedReads === 1,
    `a blocked realm accepted ${acceptedReads} of ${deliveredBySocket} socket reads`);
  assert(channel.pauses === 1 && channel.paused,
    `the socket must be paused for the read's lifetime (pauses ${channel.pauses})`);

  releaseRead(new Uint8Array());
  await until(() => channel.resumes === 1 && !channel.paused, 1000, "the socket read to resume");
  channel.emit(Uint8Array.of(2));
  await until(() => acceptedReads === 2, 1000, "the next read after resume");
});

/** An adapter with no platform backpressure, as in production: a browser WebSocket and an
 *  RTCDataChannel both deliver whatever arrives, so neither can implement `setReadable`,
 *  and the driver has to hold their bursts itself. */
class UnpausableChannel {
  data = null;
  closed = null;
  closes = 0;
  send() {}
  onData(cb) { this.data = cb; }
  onClose(cb) { this.closed = cb; }
  close() { this.closes++; }
  emit(bytes) { this.data?.(bytes); }
}

/** A driver whose `linkBytes` answer each test releases by hand, recording what it saw. */
function heldReadDriver(keep) {
  const factory = new InjectedChannels();
  const driver = keep(new TransportHost({ channels: factory }));
  const reads = [];
  let release = null;
  driver.activate((input) => {
    const { op, args } = opOf(input);
    if (op !== "linkBytes") return Promise.resolve(new Uint8Array());
    // `linkBytes` args are [linkId u32][blobLen u32][blob]; the blob runs to the end.
    reads.push(args.subarray(4 + 4));
    return new Promise((r) => { release = () => r(new Uint8Array()); });
  });
  return { factory, driver, reads, next: () => { const r = release; release = null; r(); } };
}

// An adapter that cannot be paused is held by the driver instead of the socket. Without
// this, a browser WebSocket or an RTCDataChannel (which splits every write it makes)
// loses its link as soon as a peer's third message arrives within one realm turn.
await test("DRIVER BACKPRESSURE: an unpausable adapter's burst is held, in order", async (keep) => {
  const h = heldReadDriver(keep);
  await h.driver.start();
  const channel = new UnpausableChannel();
  h.factory.give(channel);
  await settle(0);

  const BURST = 6;
  for (let i = 1; i <= BURST; i++) channel.emit(Uint8Array.of(i));
  await until(() => h.reads.length === 1, 1000, "the first read");
  assert(channel.closes === 0, "a burst within the hold bound must not fail the link");
  for (let i = 2; i <= BURST; i++) {
    h.next();
    await until(() => h.reads.length === i, 1000, `held read ${i}`);
  }
  const order = h.reads.map((r) => r[r.length - 1]).join(",");
  assert(order === "1,2,3,4,5,6", `held reads must arrive whole and in order, got ${order}`);
  assert(channel.closes === 0, "the link must survive the whole burst");
});

// The hold is bounded: a peer that outruns the realm loses its link instead of growing
// the driver's queue (§16.1).
await test("DRIVER BACKPRESSURE: a peer outrunning the realm loses its link", async (keep) => {
  const h = heldReadDriver(keep);
  await h.driver.start();
  const channel = new UnpausableChannel();
  h.factory.give(channel);
  await settle(0);

  const SLICE = 1 << 20; // 1 MiB, well under the per-delivery frame cap
  const over = Math.floor(MAX_INBOUND_HOLD_BYTES / SLICE) + 2; // aggregate includes the dispatched read
  for (let i = 0; i < over && channel.closes === 0; i++) channel.emit(new Uint8Array(SLICE));
  assert(channel.closes === 1, "a peer past the hold bound must have its link closed");
  assert(h.reads.length === 1, `only the dispatched read may reach the realm, got ${h.reads.length}`);
});

// The byte bound alone is not enough: one-byte messages cost far more than their bytes,
// so the hold is bounded by count too.
await test("DRIVER BACKPRESSURE: tiny messages cannot outrun the hold by count", async (keep) => {
  const h = heldReadDriver(keep);
  await h.driver.start();
  const channel = new UnpausableChannel();
  h.factory.give(channel);
  await settle(0);

  const one = Uint8Array.of(9);
  const over = MAX_INBOUND_HOLD_SLICES + 2; // aggregate includes the dispatched read
  let sent = 0;
  for (; sent < over && channel.closes === 0; sent++) channel.emit(one);
  assert(channel.closes === 1, "a peer past the slice bound must have its link closed");
  assert(sent * one.length < MAX_INBOUND_HOLD_BYTES,
    "the count bound must bite long before the byte bound it backs up");
});

await test("DRIVER BACKPRESSURE: the inbound slice budget is shared by every link", async (keep) => {
  const h = heldReadDriver(keep);
  await h.driver.start();
  const first = new UnpausableChannel();
  const second = new UnpausableChannel();
  h.factory.give(first);
  h.factory.give(second);
  await settle(0);

  // Two dispatched reads already occupy two reservations. Fill the remaining allowance
  // behind only the first link; one more slice on the otherwise empty second link must be
  // refused by the driver-wide total, not admitted under a new per-link allowance.
  first.emit(Uint8Array.of(1));
  second.emit(Uint8Array.of(2));
  for (let i = 2; i < MAX_INBOUND_HOLD_SLICES; i++) first.emit(Uint8Array.of(3));
  assert(first.closes === 0 && second.closes === 0,
    "the exact aggregate slice ceiling must remain admitted");
  second.emit(Uint8Array.of(4));
  assert(second.closes === 1 && first.closes === 0,
    "the link crossing the shared slice ceiling must fail without closing its neighbour");
  assert(h.reads.length === 2, `both dispatched reads count while stalled (got ${h.reads.length})`);
});

await test("DRIVER BACKPRESSURE: the inbound byte budget is shared by every link", async (keep) => {
  const h = heldReadDriver(keep);
  await h.driver.start();
  const first = new UnpausableChannel();
  const second = new UnpausableChannel();
  h.factory.give(first);
  h.factory.give(second);
  await settle(0);

  const frame = new Uint8Array(MAX_INBOUND_HOLD_BYTES / 8);
  first.emit(frame);
  second.emit(frame);
  for (let i = 2; i < 8; i++) first.emit(frame);
  assert(first.closes === 0 && second.closes === 0,
    "the exact aggregate byte ceiling must remain admitted");
  second.emit(Uint8Array.of(5));
  assert(second.closes === 1 && first.closes === 0,
    "the link crossing the shared byte ceiling must fail without closing its neighbour");
});

// A read that finishes synchronously (nothing bound) lets a full hold drain in one pass.
// It must drain as a loop, not with one stack frame per held slice, and the socket must
// end up readable again.
await test("DRIVER BACKPRESSURE: a hold answered synchronously drains whole", async (keep) => {
  const factory = new InjectedChannels();
  const driver = keep(new TransportHost({ channels: factory }));
  let reads = 0;
  let releaseFirst;
  driver.activate((input) => {
    if (opOf(input).op !== "linkBytes") return Promise.resolve(new Uint8Array());
    // The first read occupies the realm; every later one answers on the spot.
    if (++reads > 1) return null;
    return new Promise((r) => { releaseFirst = () => r(new Uint8Array()); });
  });
  await driver.start();
  const channel = new UnpausableChannel();
  factory.give(channel);
  await settle(0);

  const BURST = MAX_INBOUND_HOLD_SLICES;
  for (let i = 0; i < BURST; i++) channel.emit(Uint8Array.of(1));
  assert(reads === 1 && channel.closes === 0,
    `the hold must have taken the burst behind one read (reads ${reads}, closes ${channel.closes})`);

  releaseFirst();
  await settle(50);
  assert(reads === BURST, `every held slice must reach the realm, got ${reads} of ${BURST}`);
  assert(channel.closes === 0, "a fully drained hold must leave the link alive");
  channel.emit(Uint8Array.of(2));
  assert(reads === BURST + 1, "and the link must be readable again once the hold is empty");
});

// A reply applies only to the captured channel (§12.10).
await test("DRIVER BOUNDARY: the down report names its own socket, once", async (keep) => {
  class ManualChannel {
    data = null;
    closed = null;
    send() {}
    onData(cb) { this.data = cb; }
    onClose(cb) { this.closed = cb; }
    // Does not fire `onClose`, like native's local close. The driver must raise its own
    // later event and still notify exactly once.
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
  ));
  driver.activate(async (input) => {
    const { op, args } = opOf(input);
    if (op === "linkBytes" || op === "linkOpen") events.push({ op, linkId: readU32(args, 0) });
    if (op === "linkClosed") { events.push({ op, linkId: readU32(args, 0) }); return Uint8Array.of(0, ...new TextEncoder().encode("local")); }
    return new Uint8Array();
  });
  await driver.start();

  // Two accepted channels: give() runs register() and announce() synchronously, so the
  // linkOpen event (and this test's link id) is already in `events` when it returns.
  const aChannel = new ManualChannel();
  factory.give(aChannel);
  const aLinkId = events.find((e) => e.op === "linkOpen").linkId;
  events.length = 0;
  const bChannel = new ManualChannel();
  factory.give(bChannel);
  const bLinkId = events.find((e) => e.op === "linkOpen").linkId;
  events.length = 0;

  // 1) Bytes on one channel produce exactly one linkBytes, naming that channel's link id.
  aChannel.emit();
  await settle(0);
  assert(events.length === 1 && events[0].op === "linkBytes" && events[0].linkId === aLinkId,
    `A's bytes must produce exactly one linkBytes for A's own link id, got ${JSON.stringify(events)}`);
  assert(!events.some((e) => e.linkId === bLinkId), "B's channel must not have produced an event");
  events.length = 0;

  // 2) A host-driven close reports down exactly once with the occupant's reason, even
  // though ManualChannel.close() fires no callback of its own, so the driver must raise the
  // event. A later backend callback racing it (channel.fail(), as a real socket's close
  // would arrive) must not report a second time.
  driver.rawNet().close(aLinkId, false);
  await until(() => downs.length === 1, 1000, "A's close to report down");
  assert(downs[0].linkId === aLinkId && downs[0].reason === "local",
    `A's close must report down once with LOCAL, got ${JSON.stringify(downs)}`);
  aChannel.fail();
  await settle();
  assert(downs.length === 1, "a backend callback racing a host-driven close must not report down twice");

  // 3) Not every RawLink is a MessageChannel. The driver is the last line of defence: a
  // backend send that throws after writing bytes must fail the link and remove it, never
  // leave it open for another write after a truncated length frame.
  const cChannel = new ThrowingChannel();
  factory.give(cChannel);
  const cLinkId = events.find((e) => e.op === "linkOpen").linkId;
  events.length = 0;
  driver.rawNet().send(cLinkId, Uint8Array.of(1, 2, 3));
  await until(() => downs.some((d) => d.linkId === cLinkId), 1000, "the throwing channel's close to report down");
  assert(cChannel.stops === 1, `a throwing raw send must close the backend once, got ${cChannel.stops}`);
  const cDowns = downs.filter((d) => d.linkId === cLinkId);
  assert(cDowns.length === 1 && cDowns[0].reason === "local",
    `the throwing channel's link must be failed exactly once with LOCAL, got ${JSON.stringify(cDowns)}`);
});

await test("DRIVER HANDOVER: an outgoing occupant hears nothing about the links it leaves", async (keep) => {
  // The shell disposes the outgoing realm right after a handover, so a `linkClosed` queued
  // into it would never run. The binding is released first: every link still closes and
  // reports down once, with nothing bound.
  class ManualChannel {
    closes = 0;
    send() {}
    onData() {}
    onClose() {}
    close() { this.closes++; }
  }
  const heard = { old: [], new: [] };
  const downs = [];
  const occupant = (who) => (input) => {
    heard[who].push(opOf(input).op);
    return Promise.resolve(Uint8Array.of(0, ...new TextEncoder().encode("local")));
  };
  const factory = new InjectedChannels();
  const driver = keep(new TransportHost(
    { channels: factory, onLinkClosed: (_linkId, reason) => downs.push(reason) },
  ));
  driver.activate(occupant("old"));
  await driver.start();
  const channels = [new ManualChannel(), new ManualChannel()];
  for (const c of channels) factory.give(c);
  heard.old.length = 0; // their two linkOpens

  driver.activate(occupant("new"));
  await settle(0);
  assert(heard.old.length === 0, `the outgoing occupant must hear nothing, heard ${JSON.stringify(heard.old)}`);
  assert(heard.new.length === 0, `the incoming occupant must hear nothing, heard ${JSON.stringify(heard.new)}`);
  assert(channels.every((c) => c.closes === 1), "every socket the outgoing occupant held is closed");
  assert(downs.length === 2 && downs.every((r) => r === ""),
    `each link reports down once, unanswered, got ${JSON.stringify(downs)}`);
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
  assert(defaults.maxPreAuthQueueSlices > 0 && defaults.maxPreAuthQueueSlices <= 4096,
    "the pre-auth queue needs a finite object-count bound");
  // Three bounds from the signed transport config: two deadlines and the rekey interval.
  assert(defaults.handshakeTimeoutMs > 0, "the dialer's whole-handshake deadline must be a real bound");
  assert(defaults.unverifiedTimeoutMs > 0 && defaults.unverifiedTimeoutMs <= defaults.handshakeTimeoutMs,
    "an accept's clock must be the tighter one — it starts believing nothing at all");
  assert(defaults.rekeyAfterFrames > 0 && defaults.rekeyAfterFrames >= (1 << 16),
    "the rekey interval should be comfortably large, not a per-connection tripwire");
});

summary("transport link hardening");
