// The bundle, shell and host scaffolding the test suites share: sodium init, the author
// and guest fixtures, and the test-only module host.

import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { readFileSync } from "node:fs";
import { importBuilt, makeAuthor } from "./testkit.mjs";

export const root = join(dirname(fileURLToPath(import.meta.url)), "..");
export const imp = importBuilt(root);

export const { generateKeyPair, loadCrypto } = await imp("build/host/crypto-node.js");
export const { ModuleTable: JsModuleLoader } = await imp("build/host/module-table.js");
export const { bootShell } = await imp("build/host/shell-core.js");
export const { bootNodeShell } = await imp("build/host/shell-node.js");
export const { TransportHost } = await imp("build/host/transport-host.js");

// The host's already-readied instance, not a separate copy: libsodium-wrappers has
// separate "import" and "require" builds, so a require() here would return a second
// instance with its own wasm heap that nothing awaits .ready on.
export const sodium = await loadCrypto();

// One contact secret for the whole harness. In production each node has its own and
// hands it out with its address; one value here just means every test node is reachable
// by every other.
export const TEST_CONTACT = new Uint8Array(32).fill(3);
export const { createGuestSeam, guestSignScope, appSignScope, CallBudget } = await imp("build/host/guest-seam.js");
/** A seam called straight from a test, with the budget a realm would pass: an unbounded
 *  segment with no causal root and no spend record. */
export const withTestBudget = (seam) => (name, payload) =>
  seam(name, payload, new CallBudget(Infinity, undefined, undefined));
export const ALL_HOST_SERVICES = ["node", "fs", "timer", "link"];
export const TEST_TIMERS = { arm() {}, clear() {} };
/** Local service routing under which nothing claims any id. */
export const TEST_CALL_LOCAL = () => null;
export const { callerOf, readOp, writeOp } = await imp("build/services/op-frame.js");
/** Is this realm argument the host's wake event (§12.3)? */
export const isWake = (arg) => arg.length > 32 && callerOf(arg).fromHost && readOp(arg.subarray(32)).op === "wake";
export const { MemoryFs } = await imp("build/services/fs-memory.js");
/** A stand-in behind every host service, so a test seam may declare any of them. */
export const testBackends = () => ({
  node: appSignScope(sodium.crypto_sign_keypair(), "test"),
  fs: new MemoryFs(),
  timer: TEST_TIMERS,
  link: { open: () => ({ linkId: 0, stream: false }), send() {}, close() {}, deliver: async () => new Uint8Array(0) },
});
export const enc = new TextEncoder();
export const { NodeFs } = await imp("build/services/fs-node.js");
export const { createSafeRealm } = await imp("build/host/safe-js.js");
export const { toHex, fromHex, concatBytes, writeU32BE } = await imp("build/services/util.js");
export { bytesEqual } from "./bytes.mjs";

// Install's admission step (§12.4): tests use the same code path an install does.
export const { hybridAuthorId, FreshnessMarks, verifyBundle, loadBundleModules }
  = await imp("build/host/bundle.js");
export const { guestOpFraming, authorBundle } = await imp("build/scripts/bundle-author.js");
export const { policyFromJson, authorAllowlist, checkHostGates } = await imp("build/host/policy.js");
export const { withMlDsa65, loadMlDsa65, ML_DSA65_PK_LEN, ML_DSA65_SIG_LEN } = await imp("build/host/pq.js");

// Every app is a guest (§12.4), so every test bundle declares one. Tests that do not
// exercise the guest use this minimal program.
export const GUEST_TEXT = "function handle() { return new Uint8Array([1]); }";
export const GUEST_BYTES = new TextEncoder().encode(GUEST_TEXT);
export const GUEST = (extra = {}) => ({ requires: [], ...extra });

/** A manifest author (§12.4): the Ed25519 half, the ML-DSA-65 half, and the 32-byte id
 *  derived from both. Tests use `a.id` wherever the runtime names an author (policy,
 *  freshness marks, revocation) and pass the whole object to `signTestBundle`, so none
 *  can use half an identity. */
export const testAuthor = () => makeAuthor(sodium);

/** A Node-platform node for one test: `bootNodeShell` (shell-node.ts) with no network.
 *  Use it instead of {@link bootTestShell} for the disk-backed parts: NodeFs on a data
 *  directory and a file-backed freshness store. */
export const boot = async (cfg) => (await bootNodeShell(cfg)).shell;

/** A node for one test, through the shared assembly (`bootShell`, §12.8). The platform
 *  members are passed flat, as the assembly takes them; `fs` defaults to `false`, since
 *  most bundles here do not require `fs`.
 *
 *  `transportAuthor` boots a small signed link occupant for explicit replacement tests. */
export async function bootTestShell({ transportAuthor, ...opts } = {}) {
  const identity = opts.identity ?? generateKeyPair();
  const fixtureSource = "function handle() { return new Uint8Array(); } // fixture transport";
  const transport = transportAuthor ? {
    transport: { bundle: authorBundle(sodium, transportAuthor, {
      app: "fixture-transport", version: 1, modules: [], services: ["_fixture-transport"],
      guestSource: fixtureSource, guestRequires: ["link"],
    }).blob },
  } : {};
  const { shell } = await bootShell({
    sodium,
    modules: new JsModuleLoader(),
    freshnessStore: new FreshnessMarks(),
    fs: false,
    ...transport,
    ...opts,
    identity,
    ...(transportAuthor && opts.createRealm ? { createRealm: async (o) =>
      o.source.endsWith(fixtureSource)
        ? { call: async () => new Uint8Array(), dispose() {} }
        : opts.createRealm(o) } : {}),
  });
  return shell;
}

/** `verifyBundle`, then `admit`, then module loading (§12.4), for the policy and
 *  integrity tests that use their own module host without a shell. `admit` is awaited:
 *  a predicate may return a Promise, and treating one as a verdict would fail open. */
export async function loadBundle(host, blob, admit) {
  const v = verifyBundle(sodium, blob);
  if (!(await admit(v))) throw new Error("admit rejected");
  return installBundle(host, v);
}

// The empty payload, for a module whose `handle` takes no meaningful input.
export const EMPTY = new Uint8Array(0);

// A fresh module table (§3). It holds no policy, only the map.
export class TestModuleHost {
  constructor(loader) { this.loader = loader; this.slots = new Map(); this.names = new Map(); }
  build(mods) { return this.loader.build(mods); }
  adopt(key, modules, names = []) {
    this.slots.get(key)?.dispose();
    this.slots.set(key, modules);
    this.names.set(key, names);
  }
  async bindAll(key, mods) { this.adopt(key, await this.build(mods), mods.map((m) => m.name)); }
  callModule(key, name, payload, deadlineMs) {
    // PureModules.call resolves `{ bytes, ms }`; the direct-call tests want the bytes.
    const p = this.slots.get(key)?.call(name, payload, deadlineMs);
    return p ? p.then((r) => r.bytes) : Promise.resolve(null);
  }
  isBound(key, name) { return this.names.get(key)?.includes(name) ?? false; }
  removeApp(key) {
    const slot = this.slots.get(key);
    if (!slot) return 0;
    const n = this.names.get(key)?.length ?? 0;
    slot.dispose(); this.slots.delete(key); this.names.delete(key); return n;
  }
}
export const testHost = (loader) => new TestModuleHost(loader);
export const installBundle = async (host, v) => {
  const modules = await loadBundleModules(host, v);
  host.adopt(v.manifest.app, modules, v.modules.map(({ mod }) => mod.name));
  return { manifest: v.manifest, author: v.author, authorKeys: v.authorKeys, guestSource: v.guestSource };
};
export async function makeHost() {
  return { host: testHost(new JsModuleLoader()) };
}

export const forwarderBytes = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));

// Add ML-DSA-65 to the test instance as a target does at its crypto seam; the hybrid
// manifest suite needs a sodium with this method (§12.4).
withMlDsa65(sodium, await loadMlDsa65(readFileSync(join(root, "browser/mldsa65.wasm"))));

// Install one verified module as `app`'s whole module set. Async, since each module
// starts in its own worker and this returns once it has loaded.
export async function installMod(host, app, module, wasm) {
  await host.bindAll(app, [{ name: module, wasm }]);
}

export { signTestBundle, verifyTestBundle } from "./bundle-fixtures.mjs";
