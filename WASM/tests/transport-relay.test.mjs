// Relays (§12.7): a node registers its key on a relay with a signature, and reaches any
// registered key through a splice the relay joins end to end, the channel handshake running
// straight through it. The move to WebRTC, and the splice's retirement, are
// net-rtc.test.mjs's. The relay is the in-process fake in fake-relay.mjs, which speaks
// seedrelay's wire. Run after `npm run build`.

import { testkit } from "./testkit.mjs";
import {
  makeTransportHost, until, linkedPeers, transportOp, OpArgs, PROTO, generateKeyPair,
} from "./transport-harness.mjs";
import { FakeRelay } from "./fake-relay.mjs";
import { randomBytes } from "node:crypto";

const { test, assert, summary } = testkit();
const settle = (ms = 50) => new Promise((r) => setTimeout(r, ms));
const RELAY = "ws://relay:1";
// A private relay's secret: random, since whoever sees a registration can test guesses at it.
const SECRET = randomBytes(32).toString("hex");

const relayState = async (node) => (await transportOp(node, new OpArgs("relayState")))[0];
const joinRelay = (node, url = RELAY) => transportOp(node, new OpArgs("relay").text(url));
const addr = (node, peer, dest, secret = new Uint8Array(32)) =>
  transportOp(node, new OpArgs("addr").blob(Buffer.from(peer, "hex")).blob(secret).text(dest));
const linked = async (a, b) => (await linkedPeers(a)).includes(b.peerId) && (await linkedPeers(b)).includes(a.peerId);
const welcome = (node, peers) =>
  transportOp(node, new OpArgs("welcome").blob(Buffer.concat(peers.map((p) => Buffer.from(p, "hex")))));
const forget = (node, peer) => transportOp(node, new OpArgs("forget").blob(Buffer.from(peer, "hex")));
/** Whether `a`'s request reaches `b`. */
const reaches = async (a, b) => {
  try { await a.request(b.peerId, PROTO, Uint8Array.of(1)); return true; } catch { return false; }
};
// Short deadlines, for tests where a refused caller waits one out.
const FAST = { transportConfig: { handshakeTimeoutMs: 300, unverifiedTimeoutMs: 300 } };

/** A node whose sockets are the relay's. */
function relayNode(relay, opts = {}) {
  return makeTransportHost({ channels: relay.factory(), ...opts });
}

/** Sockets that reach either of two relays. */
const either = (a, b) => ({
  connect: (dest) => a.connect(dest) ?? b.connect(dest),
  listen: async (addrs) => addrs.map(() => 0),
  close() {},
});

/** Register both on the relay and link `a` to `b` through it, as an app that learned `b`'s
 *  key would. */
async function relayed(a, b) {
  for (const n of [a, b]) await joinRelay(n);
  await addr(a, b.peerId, "relay+" + RELAY);
  await a.request(b.peerId, PROTO, Uint8Array.of(0));
}

console.log("\nRelays: registration, splices and the move to a direct link (§12.7)\n");

await test("a node reaches a key through a relay, the handshake running through the splice", async (keep) => {
  const relay = new FakeRelay("relay:1");
  const secret = new Uint8Array(32).fill(7);
  const A = keep(await relayNode(relay));
  const B = keep(await relayNode(relay, { contactSecret: secret }));
  assert(await relayState(B) === 0, "no relay before one is joined");
  await joinRelay(B, RELAY + "/");
  assert(await relayState(B) === 1, "registered by the time `relay` answers");
  await addr(A, B.peerId, "relay+" + RELAY, secret);
  const resp = await A.request(B.peerId, PROTO, Uint8Array.of(1, 2, 3));
  assert(resp.length === 3 && resp[2] === 3, "a request crosses the splice");
  assert(relay.splices.length === 1, `one splice, got ${relay.splices.length}`);
  assert(relay.spliceBytes > 1233, "the handshake went through the relay");
  assert(await linked(A, B), "both ends hold the link");
});

await test("a relay URL names a relay and nothing more", async (keep) => {
  const A = keep(await relayNode(new FakeRelay("relay:1")));
  let msg = "";
  try { await joinRelay(A, RELAY + "/room"); } catch (e) { msg = String(e.message); }
  assert(msg.includes("no path"), `a path is refused, got "${msg}"`);
});

await test("a registration signed for another relay is refused", async (keep) => {
  // A relay reached as relay:1 that knows itself as elsewhere:1, as one relay passing
  // another's nonce through would.
  const relay = new FakeRelay("relay:1", { signedFor: "elsewhere:1" });
  const B = keep(await relayNode(relay));
  await joinRelay(B);
  await settle(200);
  assert(await relayState(B) === 2, "a node whose signature names another relay is not registered");
  assert(relay.registered.size === 0);
});

await test("a private relay registers only a node given its secret, which never crosses the wire", async (keep) => {
  const secret = SECRET;
  const relay = new FakeRelay("relay:1", { secret });
  const join = (node, s) => transportOp(node, new OpArgs("relay").text(RELAY).text(s));
  const none = keep(await relayNode(relay));
  await joinRelay(none);
  const wrong = keep(await relayNode(relay));
  await join(wrong, randomBytes(32).toString("hex"));
  const A = keep(await relayNode(relay));
  const B = keep(await relayNode(relay));
  for (const n of [A, B]) await join(n, secret);
  assert(await relayState(none) === 2 && await relayState(wrong) === 2, "no secret, or another, is not registered");
  assert(await relayState(A) === 1 && await relayState(B) === 1, "the secret registers");
  assert(relay.macs.every((mac) => mac.length === 64 && !mac.includes(Buffer.from(secret))), "a 64-byte MAC, never the secret");
  // The splice needs no proof of its own; A calls B through the private relay.
  await addr(A, B.peerId, "relay+" + RELAY);
  const resp = await A.request(B.peerId, PROTO, Uint8Array.of(4));
  assert(resp[0] === 4, "a request crosses the private relay");
});

await test("a node given a secret still registers on a relay without one, which ignores the MAC", async (keep) => {
  const relay = new FakeRelay("relay:1");
  const A = keep(await relayNode(relay));
  await transportOp(A, new OpArgs("relay").text(RELAY).text(SECRET));
  assert(await relayState(A) === 1, "registered");
  assert(relay.macs.length === 1, "and the MAC was sent");
});

await test("the secret is proved to the home relay alone, not to a relay a peer is called through", async (keep) => {
  const home = new FakeRelay("relay:1", { secret: SECRET });
  const other = new FakeRelay("other:1");
  const A = keep(await makeTransportHost({ channels: either(home, other) }));
  const B = keep(await relayNode(other));
  await transportOp(A, new OpArgs("relay").text(RELAY).text(SECRET));
  await joinRelay(B, "ws://other:1");
  await addr(A, B.peerId, "relay+ws://other:1");
  const resp = await A.request(B.peerId, PROTO, Uint8Array.of(5));
  assert(resp[0] === 5, "A calls B through the other relay");
  assert(home.macs.length === 1, "the home relay got the MAC");
  assert(other.registered.has(A.peerId) && other.macs.length === 0, "the other registered A without one");
});

await test("a relay a peer was only called through is left once it idles, and the home relay kept", async (keep) => {
  const home = new FakeRelay("relay:1"), other = new FakeRelay("other:1");
  const A = keep(await makeTransportHost({ channels: either(home, other), transportConfig: { linkIdleTimeoutMs: 200 } }));
  const B = keep(await relayNode(other));
  await joinRelay(A);
  await joinRelay(B, "ws://other:1");
  await addr(A, B.peerId, "relay+ws://other:1");
  await A.request(B.peerId, PROTO, Uint8Array.of(1));
  assert(other.registered.has(A.peerId), "a call registers the caller on the relay it goes through");
  await until(() => !other.registered.has(A.peerId), 3000, "the idle relay to be left");
  assert(await relayState(A) === 1 && home.registered.has(A.peerId), "the home relay is kept");
  const resp = await A.request(B.peerId, PROTO, Uint8Array.of(2));
  assert(resp[0] === 2, "the next call goes through it again");
});

await test("a key the relay does not know fails the request at once", async (keep) => {
  const relay = new FakeRelay("relay:1");
  const A = keep(await relayNode(relay));
  await addr(A, "ab".repeat(32), "relay+" + RELAY);
  const t0 = Date.now();
  let failed = false;
  try { await A.request("ab".repeat(32), PROTO, Uint8Array.of(1)); } catch { failed = true; }
  assert(failed, "the request fails");
  assert(Date.now() - t0 < 1000, `it fails at once, took ${Date.now() - t0} ms`);
  assert(relay.calls === 1, "the relay was asked");
});

await test("the callee's contact secret still gates a relayed dial", async (keep) => {
  const relay = new FakeRelay("relay:1");
  const A = keep(await relayNode(relay, { transportConfig: { handshakeTimeoutMs: 300 } }));
  const B = keep(await relayNode(relay, { contactSecret: new Uint8Array(32).fill(1), transportConfig: { unverifiedTimeoutMs: 300 } }));
  await joinRelay(B);
  await until(async () => (await relayState(B)) === 1, 2000, "B registered");
  await addr(A, B.peerId, "relay+" + RELAY, new Uint8Array(32).fill(2));
  let failed = false;
  try { await A.request(B.peerId, PROTO, Uint8Array.of(1)); } catch { failed = true; }
  assert(failed, "a caller without the secret gets nothing through the splice");
  assert(!(await linkedPeers(B)).includes(A.peerId));
});

await test("a welcomed caller is answered without the contact secret, and nobody else is", async (keep) => {
  const relay = new FakeRelay("relay:1");
  const secret = new Uint8Array(32).fill(1);
  const A = keep(await relayNode(relay, FAST));   // welcomed, and given no secret
  const C = keep(await relayNode(relay, FAST));   // not welcomed
  const B = keep(await relayNode(relay, { contactSecret: secret, ...FAST }));
  for (const n of [A, B, C]) await joinRelay(n);
  await welcome(B, [A.peerId]);
  for (const n of [A, C]) await addr(n, B.peerId, "relay+" + RELAY);
  assert(await reaches(A, B), "the welcomed caller links with no secret");
  assert(!(await reaches(C, B)) && !(await linkedPeers(B)).includes(C.peerId),
    "a caller B does not welcome still needs its secret");
  await addr(C, B.peerId, "relay+" + RELAY, secret);
  assert(await reaches(C, B), "and links once it presents it");
});

await test("a welcomed caller that holds the contact secret links with it too", async (keep) => {
  const relay = new FakeRelay("relay:1");
  const secret = new Uint8Array(32).fill(1);
  const A = keep(await relayNode(relay, FAST));
  const B = keep(await relayNode(relay, { contactSecret: secret, ...FAST }));
  for (const n of [A, B]) await joinRelay(n);
  await welcome(B, [A.peerId]);
  await addr(A, B.peerId, "relay+" + RELAY, secret);
  assert(await reaches(A, B), "the secret opens a welcomed accept as it opens any");
});

await test("a welcome is for that key alone: nobody else passes the gate in its name", async (keep) => {
  // A relay that names every caller as A, whom B welcomes. C's msg1 then opens with no
  // secret, but C cannot prove A's key at msg3, and B takes no other.
  const relay = new FakeRelay("relay:1");
  const A = keep(await relayNode(relay, FAST));
  const C = keep(await relayNode(relay, FAST));
  const B = keep(await relayNode(relay, { contactSecret: new Uint8Array(32).fill(1), ...FAST }));
  for (const n of [A, B, C]) await joinRelay(n);
  await welcome(B, [A.peerId]);
  relay.callerName = A.peerId;
  await addr(C, B.peerId, "relay+" + RELAY);
  assert(!(await reaches(C, B)), "the caller behind A's name gets nothing through");
  assert((await linkedPeers(B)).length === 0, "and B holds no link to anyone");
});

await test("welcome names the whole set, and forget drops a peer's links and its address", async (keep) => {
  const relay = new FakeRelay("relay:1");
  const A = keep(await relayNode(relay, FAST));
  const B = keep(await relayNode(relay, { contactSecret: new Uint8Array(32).fill(1), ...FAST }));
  for (const n of [A, B]) await joinRelay(n);
  await welcome(B, [A.peerId]);
  await addr(A, B.peerId, "relay+" + RELAY);
  assert(await reaches(A, B) && await linked(A, B), "linked while welcomed");
  // B hangs up on A: the link goes at both ends, with a goodbye.
  await forget(B, A.peerId);
  await until(async () => !(await linkedPeers(A)).includes(B.peerId) && !(await linkedPeers(B)).includes(A.peerId),
    2000, "the link to close at both ends");
  // A still has B's address and calls again, but B no longer welcomes it.
  await welcome(B, []);
  assert(!(await reaches(A, B)), "a peer left out of the next welcome needs the secret again");
  // And a forgotten address is no address: the request fails without a call.
  const calls = relay.calls;
  await forget(A, B.peerId);
  assert(!(await reaches(A, B)) && relay.calls === calls, "a forgotten peer is not dialed");
  let msg = "";
  try { await transportOp(A, new OpArgs("welcome").blob(Uint8Array.of(1, 2, 3))); } catch (e) { msg = String(e.message ?? e); }
  assert(msg.includes("32-byte"), `a malformed welcome is refused, got "${msg}"`);
});

await test("a caller outside the callee's admitPeers gets no socket", async (keep) => {
  const relay = new FakeRelay("relay:1");
  const A = keep(await relayNode(relay, { transportConfig: { handshakeTimeoutMs: 300 } }));
  const B = keep(await relayNode(relay, { admitPeers: [generateKeyPair().publicKey] }));
  await joinRelay(B);
  await addr(A, B.peerId, "relay+" + RELAY);
  let failed = false;
  try { await A.request(B.peerId, PROTO, Uint8Array.of(1)); } catch { failed = true; }
  assert(failed, "the request fails");
  assert(relay.calls === 1 && relay.splices.length === 0, "the callee never opened its end");
});

await test("a restarted relay is redialed, and the next send links again", async (keep) => {
  const relay = new FakeRelay("relay:1");
  const A = keep(await relayNode(relay));
  const B = keep(await relayNode(relay));
  await relayed(A, B);
  relay.restart();
  await until(async () => (await relayState(A)) === 2, 2000, "the dropped relay to read as redialing");
  await until(async () => (await relayState(A)) === 1 && (await relayState(B)) === 1, 5000, "the relay to be redialed");
  const resp = await A.request(B.peerId, PROTO, Uint8Array.of(1));
  assert(resp[0] === 1, "a request dials through the relay again");
  assert(relay.splices.length === 2, `a second splice, got ${relay.splices.length}`);
});

await test("the host is told its status when the relay's state changes", async (keep) => {
  const relay = new FakeRelay("relay:1");
  // The relay's state is the status's first byte. A status may be told again unchanged.
  const told = [];
  const states = () => told.filter((s, i) => s !== told[i - 1]).join();
  const A = keep(await relayNode(relay, { onStatus: (status) => told.push(status[0]) }));
  await joinRelay(A);
  assert(states() === "2,1", `joining tells it is on its way, then registered, got ${told}`);
  relay.restart();
  await until(() => states() === "2,1,2,1", 5000, "the drop and the redial to be told");
  await joinRelay(A, "");
  await until(() => states() === "2,1,2,1,0", 2000, "leaving to be told");
});

await test("a call the relay cannot join fails that send, and the next one goes through", async (keep) => {
  const relay = new FakeRelay("relay:1");
  relay.refuseSplices = true;
  const A = keep(await relayNode(relay, { transportConfig: { handshakeTimeoutMs: 300 } }));
  const B = keep(await relayNode(relay));
  for (const n of [A, B]) await joinRelay(n);
  await addr(A, B.peerId, "relay+" + RELAY);
  let failed = false;
  try { await A.request(B.peerId, PROTO, Uint8Array.of(1)); } catch { failed = true; }
  assert(failed, "no splice, no link");
  relay.refuseSplices = false;
  const resp = await A.request(B.peerId, PROTO, Uint8Array.of(2));
  assert(resp[0] === 2);
});

await test("what was sent to a peer before it is forgotten reaches it, ahead of the goodbye", async (keep) => {
  const relay = new FakeRelay("relay:1");
  let reason = "";
  // A seals slowly, as a busy link does: a record waits its turn behind the ones before
  // it, so most of these are still queued when the close comes.
  const slowSeal = (name, answer) => (name.endsWith("/seal") ? new Promise((r) => setTimeout(() => r(answer), 20)) : answer);
  const A = keep(await relayNode(relay, { onHostAnswer: slowSeal }));
  const B = keep(await relayNode(relay, { onLinkClosed: (_id, r) => { reason = r; } }));
  await relayed(A, B);
  const before = (await B.seen()).length;
  const sends = [];
  for (let i = 0; i < 10; i++) sends.push(A.sendNoReply(B.peerId, PROTO, Uint8Array.of(9, i)));
  await Promise.all(sends);
  await forget(A, B.peerId);
  await until(() => reason !== "", 3000, "B's link to close");
  const got = (await B.seen()).length - before;
  assert(got === 10, `all 10 records arrive, got ${got}`);
  assert(reason === "clean", `and the goodbye behind them, got "${reason}"`);
});

await test("the host is told its status when who is linked changes, ahead of a new peer's first frame", async (keep) => {
  const relay = new FakeRelay("relay:1");
  // What B's host hears, in order: who is linked, which is the status behind its first
  // byte (`onStatus`), and each frame delivered.
  const heard = [];
  const A = keep(await relayNode(relay));
  const B = keep(await relayNode(relay, {
    onStatus: (status) => heard.push(Buffer.from(status.subarray(1)).toString("hex")),
    onHostCall: (name) => { if (name === "link/deliver") heard.push("frame"); },
  }));
  // A's request is what dials, so its frame comes in right behind the handshake.
  await relayed(A, B);
  const linked = heard.indexOf(A.peerId + "00");
  assert(linked >= 0 && linked < heard.indexOf("frame"),
    `B is told A is linked, through the relay, before A's frame is delivered, got ${heard}`);
  await forget(B, A.peerId);
  await until(() => heard.at(-1) === "", 2000, "B to be told nobody is linked");
});

summary("Relays");
