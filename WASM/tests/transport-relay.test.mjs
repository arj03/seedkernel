// Relays (§12.7): a node registers its key on a relay with a signature, meets a room's
// members there, and reaches any registered key through a splice the relay joins end to
// end, the channel handshake running straight through it. A relayed link then moves to a
// direct one the peer advertised, and the splice is retired. The relay is the in-process
// fake in fake-relay.mjs, which speaks seedrelay's wire. Run after `npm run build`.

import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { importBuilt, testkit } from "./testkit.mjs";
import {
  makeTransportHost, until, linkedPeers, transportOp, OpArgs, PROTO, LoopbackChannels, generateKeyPair,
} from "./transport-harness.mjs";
import { FakeRelay } from "./fake-relay.mjs";

const imp = importBuilt(join(dirname(fileURLToPath(import.meta.url)), ".."));
const { combineChannels } = await imp("build/services/socket-seam.js");

const { test, assert, summary } = testkit();
const settle = (ms = 50) => new Promise((r) => setTimeout(r, ms));
const RELAY = "ws://relay:1";

const relayState = async (node) => (await transportOp(node, new OpArgs("relayState")))[0];
const joinRelay = (node, url) => transportOp(node, new OpArgs("relay").text(url));
const addr = (node, peer, dest, secret = new Uint8Array(32)) =>
  transportOp(node, new OpArgs("addr").blob(Buffer.from(peer, "hex")).blob(secret).text(dest));
const linked = async (a, b) => (await linkedPeers(a)).includes(b.peerId) && (await linkedPeers(b)).includes(a.peerId);

/** A node whose sockets are the relay and, optionally, a direct in-process fabric. */
function relayNode(relay, opts = {}) {
  const factories = [relay.factory()];
  if (opts.fabric) factories.push(opts.fabric.view());
  return makeTransportHost({ channels: combineChannels(...factories), ...opts });
}

console.log("\nRelays: registration, rooms, splices and the move to a direct link (§12.7)\n");

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

await test("a registration signed for another relay is refused", async (keep) => {
  // A relay reached as relay:1 that knows itself as elsewhere:1, as one relay passing
  // another's nonce through would.
  const relay = new FakeRelay("relay:1", { signedFor: "elsewhere:1" });
  const B = keep(await relayNode(relay));
  await joinRelay(B, RELAY + "/");
  await settle(200);
  assert(await relayState(B) === 2, "a node whose signature names another relay is not registered");
  assert(relay.registered.size === 0);
});

await test("a room's members link to each other with no address given", async (keep) => {
  const relay = new FakeRelay("relay:1");
  const A = keep(await relayNode(relay));
  const B = keep(await relayNode(relay));
  const C = keep(await relayNode(relay));
  for (const n of [A, B, C]) await joinRelay(n, RELAY + "/room");
  await until(async () => (await linked(A, B)) && (await linked(A, C)) && (await linked(B, C)), 3000, "the room to link up");
  assert(relay.splices.length === 3, `one splice per pair, got ${relay.splices.length}`);
  const resp = await C.request(A.peerId, PROTO, Uint8Array.of(9));
  assert(resp[0] === 9, "either key can send");
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
  await joinRelay(B, RELAY + "/");
  await until(async () => (await relayState(B)) === 1, 2000, "B registered");
  await addr(A, B.peerId, "relay+" + RELAY, new Uint8Array(32).fill(2));
  let failed = false;
  try { await A.request(B.peerId, PROTO, Uint8Array.of(1)); } catch { failed = true; }
  assert(failed, "a caller without the secret gets nothing through the splice");
  assert(!(await linkedPeers(B)).includes(A.peerId));
});

await test("a caller outside the callee's admitPeers gets no socket", async (keep) => {
  const relay = new FakeRelay("relay:1");
  const A = keep(await relayNode(relay, { transportConfig: { handshakeTimeoutMs: 300 } }));
  const B = keep(await relayNode(relay, { admitPeers: [generateKeyPair().publicKey] }));
  await joinRelay(B, RELAY + "/");
  await addr(A, B.peerId, "relay+" + RELAY);
  let failed = false;
  try { await A.request(B.peerId, PROTO, Uint8Array.of(1)); } catch { failed = true; }
  assert(failed, "the request fails");
  assert(relay.calls === 1 && relay.splices.length === 0, "the callee never opened its end");
});

await test("a relayed link moves to an advertised direct address, and the splice is retired", async (keep) => {
  const relay = new FakeRelay("relay:1");
  const fabric = new LoopbackChannels();
  // A room shares one contact secret.
  const contactSecret = new Uint8Array(32).fill(5);
  const A = keep(await relayNode(relay, { fabric, contactSecret }));
  const B = keep(await relayNode(relay, {
    fabric,
    listen: [{ label: "tcp", host: "127.0.0.1", port: 24001 }],
    contactSecret,
    transportConfig: { advertise: ["tcp://b:24001"] },
  }));
  for (const n of [A, B]) await joinRelay(n, RELAY + "/room");
  await until(async () => linked(A, B), 3000, "the relayed link");
  await until(() => relay.splices.every((pair) => pair.every((e) => e.dead)), 3000, "the splice to be retired");
  assert(await linked(A, B), "still linked, now directly");
  const before = relay.spliceBytes;
  const resp = await A.request(B.peerId, PROTO, Uint8Array.of(4, 5));
  assert(resp[1] === 5, "a request after the move");
  const back = await B.request(A.peerId, PROTO, Uint8Array.of(6));
  assert(back[0] === 6, "and back");
  assert(relay.spliceBytes === before, "no traffic through the relay after the move");
});

await test("an advertised loopback, LAN or numeric-trick address is not dialed", async (keep) => {
  const relay = new FakeRelay("relay:1");
  // The fabric routes by port alone, so any of these would reach B's listener if dialed.
  const fabric = new LoopbackChannels();
  const contactSecret = new Uint8Array(32).fill(5);
  const A = keep(await relayNode(relay, { fabric, contactSecret }));
  const B = keep(await relayNode(relay, {
    fabric,
    listen: [{ label: "tcp", host: "127.0.0.1", port: 24002 }],
    contactSecret,
    transportConfig: { advertise: ["tcp://127.0.0.1:24002", "tcp://192.168.1.9:24002", "tcp://0x7f.1:24002",
      "tcp://2130706433:24002", "tcp://localhost:24002", "tcp://[::1]:24002", "ws://169.254.169.254:24002/x"] },
  }));
  for (const n of [A, B]) await joinRelay(n, RELAY + "/room");
  await until(async () => linked(A, B), 3000, "the relayed link");
  await settle(300);
  assert(relay.splices[0].every((e) => !e.dead), "the link stays on the relay");
});

await test("a restarted relay is redialed, and its room links again", async (keep) => {
  const relay = new FakeRelay("relay:1");
  const A = keep(await relayNode(relay));
  const B = keep(await relayNode(relay));
  for (const n of [A, B]) await joinRelay(n, RELAY + "/room");
  await until(async () => linked(A, B), 3000, "the relayed link");
  relay.restart();
  await until(async () => (await relayState(A)) === 2, 2000, "the dropped relay to read as redialing");
  await until(async () => (await relayState(A)) === 1 && (await relayState(B)) === 1, 5000, "the relay to be redialed");
  await until(async () => linked(A, B), 3000, "the room to link again");
  const resp = await A.request(B.peerId, PROTO, Uint8Array.of(1));
  assert(resp[0] === 1);
});

await test("a room member whose link is lost is called again", async (keep) => {
  const relay = new FakeRelay("relay:1");
  const A = keep(await relayNode(relay));
  const B = keep(await relayNode(relay));
  for (const n of [A, B]) await joinRelay(n, RELAY + "/room");
  await until(async () => linked(A, B), 3000, "the relayed link");
  for (const e of relay.splices[0]) e.kill();
  await until(async () => !(await linked(A, B)), 2000, "the link to drop");
  await until(async () => linked(A, B), 4000, "the smaller key to call again");
  assert(relay.splices.length === 2, `a second splice, got ${relay.splices.length}`);
});

await test("a room call that fails is tried again", async (keep) => {
  const relay = new FakeRelay("relay:1");
  relay.refuseSplices = true;
  const A = keep(await relayNode(relay));
  const B = keep(await relayNode(relay));
  for (const n of [A, B]) await joinRelay(n, RELAY + "/room");
  await until(() => relay.calls >= 1, 2000, "the first call");
  await settle(100);
  assert(!(await linked(A, B)), "no splice, no link");
  relay.refuseSplices = false;
  await until(async () => linked(A, B), 5000, "a later call to get through");
  assert(relay.calls >= 2, `the member was called again, ${relay.calls} call(s)`);
});

await test("the idle clock spares the last link to a room member, and only that", async (keep) => {
  const relay = new FakeRelay("relay:1");
  const A = keep(await relayNode(relay, { linkIdleTimeoutMs: 200 }));
  const B = keep(await relayNode(relay, { linkIdleTimeoutMs: 200 }));
  const C = keep(await relayNode(relay, { linkIdleTimeoutMs: 200 }));
  for (const n of [A, B]) await joinRelay(n, RELAY + "/room");
  await until(async () => linked(A, B), 3000, "the relayed link");
  // C is in no room with B: it reaches B by address.
  await addr(C, B.peerId, "relay+" + RELAY);
  await C.request(B.peerId, PROTO, Uint8Array.of(1));
  await settle(800);
  assert(await linked(A, B), "the room's link outlives four idle windows");
  assert(relay.splices[0].every((e) => !e.dead), "on its first splice");
  assert(!(await linkedPeers(C)).includes(B.peerId), "a link outside the room still goes idle");
});

summary("Relays");
