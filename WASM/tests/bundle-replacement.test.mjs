// Explicit replacement targets a slot, independently of its author's identity.
import assert from "node:assert/strict";
import {
  sodium, generateKeyPair, authorBundle, testAuthor, bootShell, MemoryFs,
  FreshnessMarks, toHex, concatBytes, imp, withTestBudget,
} from "./fixtures.mjs";

const { DEFAULT_MAX_APP_SLOTS } = await imp("build/host/wasm-limits.js");
const alice = testAuthor(), bob = testAuthor(), carol = testAuthor();
const bundle = (author, app, version = 1, extra = {}) => authorBundle(sodium, author, {
  app, version, modules: [], guestSource: "function handle() { return new Uint8Array(); }",
  guestRequires: [], guestConfig: { tag: version }, ...extra,
}).blob;
const linkBundle = (author, version = 1, extra = {}) => bundle(author, "transport", version, {
  guestRequires: ["node", "link"], services: ["_net"], ...extra,
});

async function node({ transport = false, store = new FreshnessMarks(), admit = () => true } = {}) {
  const records = [], control = { hook: null };
  const identity = generateKeyPair();
  const result = await bootShell({
    sodium, identity, fs: new MemoryFs(), freshnessStore: store,
    transport, admit,
    createRealm: async (o) => {
      // Compile the fixture without executing guest top-level code.
      new Function(o.source);
      const app = Function(o.source.split("\n").slice(0, 3).join("\n") + "\nreturn APP;")();
      const r = { tag: app.tag, seam: withTestBudget(o.hostCall), disposed: false,
        call: async () => Uint8Array.of(app.tag), dispose() { r.disposed = true; } };
      records.push(r);
      if (control.hook) await control.hook(r);
      return r;
    },
  });
  return { ...result, identity, store, records, control };
}
let passed = 0;
async function test(name, run) { await run(); passed++; console.log(`  OK ${name}`); }

await test("another author replaces a chat owner under a new label atomically, with that label's scopes", async () => {
  const n = await node();
  try {
    const old = await n.shell.install(bundle(alice, "chat", 50, {
      protocols: ["chat", "old-only"], services: ["chat-local"], guestRequires: ["fs", "node"],
    }));
    await old.fs.put("private", Uint8Array.of(42));
    const next = await n.shell.install(bundle(bob, "other-chat", 1, {
      protocols: ["chat"], services: ["chat-local", "new-only"], guestRequires: ["fs", "node"],
    }), { replaces: "chat" });
    assert.equal(n.shell.resolve("chat"), "other-chat");
    assert.equal(n.shell.resolve("chat-local"), "other-chat");
    assert.equal(n.shell.resolve("old-only"), null);
    assert.equal(n.shell.resolve("new-only"), "other-chat");
    assert.equal(n.shell.uninstall("chat"), false);
    assert.equal(await next.fs.get("private"), null);
    assert.deepEqual(await old.fs.get("private"), Uint8Array.of(42));
    assert.notEqual(old.appScope, next.appScope);
    assert.equal(n.store.get(alice.id, "chat"), 50);
    assert.equal(n.store.get(bob.id, "other-chat"), 1);
    await assert.rejects(old.invoke(new Uint8Array()), /no longer loaded/);
    assert.equal(n.records[0].disposed, true);
    assert.deepEqual(await n.shell.call("chat-local", new Uint8Array()), Uint8Array.of(1));
  } finally { n.shell.close(); }
});

await test("another author keeping the label takes its data and signing scope, but not its history", async () => {
  const n = await node();
  const reach = { guestRequires: ["fs", "node"] };
  try {
    const old = await n.shell.install(bundle(alice, "chat", 50, reach));
    await old.fs.put("history", Uint8Array.of(42));
    const msg = Uint8Array.of(7, 7);
    const sig = await n.records[0].seam("node/sign", msg);
    // One slot per label: a second author's `chat` lands only by naming the one standing.
    await assert.rejects(n.shell.install(bundle(bob, "chat", 1, reach)), /'chat' is already installed/);
    const next = await n.shell.install(bundle(bob, "chat", 1, reach), { replaces: "chat" });
    assert.equal(next.appScope, old.appScope);
    assert.deepEqual(await next.fs.get("history"), Uint8Array.of(42));
    const verdict = await n.records[1].seam("node/verify", concatBytes([n.identity.publicKey, sig, msg]));
    assert.equal(verdict[0], 1, "the new author's slot verifies what the old one signed");
    assert.equal(n.store.get(alice.id, "chat"), 50);
    assert.equal(n.store.get(bob.id, "chat"), 1);
  } finally { n.shell.close(); }
});

await test("explicit replacement still asks app admission and enforces revocation and freshness", async () => {
  let allowed = true;
  const n = await node({ admit: () => allowed });
  try {
    const old = await n.shell.install(bundle(alice, "chat", 1, { services: ["chat"] }));
    allowed = false;
    await assert.rejects(n.shell.install(bundle(bob, "chat"), { replaces: "chat" }), /admission/);
    allowed = true;
    n.store.set(bob.id, "chat", 5);
    await assert.rejects(n.shell.install(bundle(bob, "chat", 4), { replaces: "chat" }), /downgrade/);
    n.store.revoke(bob.id);
    await assert.rejects(n.shell.install(bundle(bob, "chat", 6), { replaces: "chat" }), /revoked/);
    await assert.rejects(n.shell.install(bundle(carol, "chat"), { replaces: "absent" }), /not installed/);
    assert.equal(n.shell.resolve("chat"), "chat");
    assert.deepEqual(await old.invoke(new Uint8Array()), Uint8Array.of(1));
  } finally { n.shell.close(); }
});

await test("a replacement cannot take unrelated claims or merge two installed labels", async () => {
  const n = await node();
  try {
    await n.shell.install(bundle(alice, "chat", 1, { services: ["chat"] }));
    await n.shell.install(bundle(bob, "other", 1, { protocols: ["reserved-peer"], services: ["reserved"] }));
    for (const extra of [{ services: ["reserved"] }, { protocols: ["reserved-peer"] }])
      await assert.rejects(n.shell.install(bundle(carol, "candidate", 1, extra), { replaces: "chat" }), /already held/);
    await assert.rejects(n.shell.install(bundle(bob, "other", 2), { replaces: "chat" }), /is already installed/);
    assert.equal(n.records.length, 2, "known conflicts are refused before realm construction");
    assert.equal(n.shell.resolve("chat"), "chat");
    assert.equal(n.shell.resolve("reserved"), "other");
  } finally { n.shell.close(); }
});

await test("construction and persist failures retain the previous owner and candidate history", async () => {
  const flaky = { fail: false };
  const store = new FreshnessMarks(null, () => { if (flaky.fail) throw new Error("disk full"); });
  const n = await node({ store });
  try {
    await n.shell.install(bundle(alice, "chat", 1, { services: ["chat"] }));
    await assert.rejects(n.shell.install(bundle(bob, "chat", 1, { guestSource: "function {" }), { replaces: "chat" }));
    flaky.fail = true;
    await assert.rejects(n.shell.install(bundle(bob, "chat", 1, { services: ["chat"] }), { replaces: "chat" }), /disk full/);
    assert.equal(store.get(bob.id, "chat"), -Infinity);
    assert.equal(n.shell.resolve("chat"), "chat");
    assert.equal(n.records[0].disposed, false);
    assert.equal(n.records[1].disposed, true);
    flaky.fail = false;
    await n.shell.install(bundle(bob, "chat", 1, { services: ["chat"] }), { replaces: "chat" });
  } finally { n.shell.close(); }
});

await test("stale replacement refuses concurrent replacement, update, uninstall, and close", async () => {
  for (const action of ["replace", "update", "uninstall", "close", "revoke-candidate", "claim-race"]) {
    const n = await node();
    let release, entered;
    const waiting = new Promise((r) => { entered = r; });
    const blocked = new Promise((r) => { release = r; });
    try {
      await n.shell.install(bundle(alice, "chat", 1, { services: ["chat"] }));
      n.control.hook = async () => { n.control.hook = null; entered(); await blocked; };
      const pending = n.shell.install(bundle(bob, "chat", 1, { services: ["chat", "contested"] }), { replaces: "chat" });
      const refused = assert.rejects(pending, /target changed|node is closed|revoked|already held/);
      await waiting;
      if (action === "replace") await n.shell.install(bundle(carol, "chat", 1, { services: ["chat"] }), { replaces: "chat" });
      if (action === "update") await n.shell.install(bundle(alice, "chat", 2, { services: ["chat"] }), { replaces: "chat" });
      if (action === "uninstall") n.shell.uninstall("chat");
      if (action === "close") n.shell.close();
      if (action === "revoke-candidate") n.shell.revoke(toHex(bob.id));
      if (action === "claim-race") await n.shell.install(bundle(carol, "neighbor", 1, { services: ["contested"] }));
      release();
      await refused;
      assert.equal(n.store.get(bob.id, "chat"), -Infinity, action);
      assert.equal(n.records[1].disposed, true, action);
    } finally { release?.(); n.shell.close(); }
  }
});

await test("cross-author replacement works at the slot ceiling", async () => {
  const n = await node();
  try {
    for (let i = 0; i < DEFAULT_MAX_APP_SLOTS; i++) await n.shell.install(bundle(alice, `app${i}`));
    await n.shell.install(bundle(bob, "replacement"), { replaces: "app0" });
    await assert.rejects(n.shell.install(bundle(carol, "overflow")), /max app slots|already holds/);
    assert.equal(n.shell.uninstall("app0"), false);
  } finally { n.shell.close(); }
});

await test("transport author can change only through replacement of its current owner", async () => {
  let asks = 0;
  const n = await node({ transport: { bundle: linkBundle(alice) }, admit: () => { asks++; return true; } });
  // Bob's transport under a label of its own, so what refuses it below is the binding
  // rule and not the label Alice's transport holds.
  const bobLink = (version = 1) => linkBundle(bob, version, { app: "bob-transport" });
  try {
    const standing = n.shell.resolve("_net");
    // The standing transport's own label is taken like any other, so its next version
    // arrives by replacement; a DIFFERENT label reaching `link` is refused by the
    // binding rule instead, before it can contest the holder's service id.
    await assert.rejects(n.shell.install(linkBundle(alice, 2)), /is already installed/);
    await assert.rejects(n.shell.install(bobLink()), /claim 'link' is already held by 'transport'/);
    await n.shell.install(bundle(carol, "chat"));
    await assert.rejects(n.shell.install(bobLink(), { replaces: "chat" }), /claim 'link' is already held by 'transport'/);
    await n.shell.install(bobLink(), { replaces: standing });
    assert.equal(n.shell.resolve("_net"), "bob-transport");
    assert.equal(n.shell.uninstall(standing), false);
    assert.equal(n.transport.available(), true);
    assert.equal(asks, 1, "only the ordinary app requested app consent");
    n.store.set(alice.id, "transport", 10);
    await assert.rejects(n.shell.install(linkBundle(alice, 9), { replaces: "bob-transport" }), /downgrade/);
    n.store.revoke(alice.id);
    await assert.rejects(n.shell.install(linkBundle(alice, 11), { replaces: "bob-transport" }), /revoked/);
    assert.equal(n.shell.resolve("_net"), "bob-transport");
    // A version that DROPS `link` is no back door either: the label is taken, so taking
    // it over is the same explicit replacement as for any other app.
    await assert.rejects(n.shell.install(bundle(bob, "bob-transport", 2)), /is already installed/);
    await n.shell.install(bundle(carol, "offline", 1, { services: ["offline"] }), { replaces: "bob-transport" });
    assert.equal(n.transport.available(), false, "dropping link releases the driver");
    assert.equal(n.shell.resolve("_net"), null);
  } finally { n.shell.close(); }
  const offline = await node();
  try {
    await offline.shell.install(bundle(alice, "chat"));
    await assert.rejects(offline.shell.install(bobLink(), { replaces: "chat" }), /an install replacing/);
  } finally { offline.shell.close(); }
});

await test("boot selection still rejects revoked, stale, and non-link transport bundles", async () => {
  const store = new FreshnessMarks();
  store.set(alice.id, "transport", 10);
  await assert.rejects(node({ store, transport: { bundle: linkBundle(alice, 9) } }), /downgrade/);
  store.revoke(alice.id);
  await assert.rejects(node({ store, transport: { bundle: linkBundle(alice, 11) } }), /revoked/);
  await assert.rejects(node({ transport: { bundle: bundle(bob, "ordinary") } }), /must require "link"/);
});

console.log(`bundle replacement: ${passed} passed`);
