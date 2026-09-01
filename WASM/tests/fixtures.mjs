// fixtures.mjs — the bundle/shell/host scaffolding every seedkernel test suite needs.
// Each suite in tests/*.test.mjs imports what it needs from here instead of restating
// sodium init, the author/guest fixtures, or the test-only ModuleTable host. Extracted
// from the single-file run.mjs so a suite file reads as its own topic, not a topic plus a
// copy of everyone else's setup.

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

// The host's already-readied instance rather than our own copy:
// libsodium-wrappers declares separate "import" and "require" conditions pointing at
// different builds, so a require() here returns a SECOND instance with its own wasm heap
// that nothing awaits .ready on. One shared instance is the rule (§12.1).
export const sodium = await loadCrypto();

// One contact secret for the whole harness. In production each node has its own and
// hands it out with its address; one value here just means every test node is reachable
// by every other.
export const TEST_CONTACT = new Uint8Array(32).fill(3);
export const { createGuestSeam, guestSignScope, appSignScope } = await imp("build/host/guest-seam.js");
export const ALL_HOST_SERVICES = ["node", "fs", "clock", "timer", "link"];
export const TEST_TIMERS = { arm() {}, clear() {} };
export const TEST_CALLS = { call: () => null };
export const { callerOf, readOp, writeOp } = await imp("build/host/op-frame.js");
export const { MemoryFs } = await imp("build/host/fs-memory.js");
export const enc = new TextEncoder();
export const { NodeFs } = await imp("build/host/fs-node.js");
export const { createSafeRealm } = await imp("build/host/safe-js.js");
export const { toHex, fromHex, concatBytes, writeU32BE } = await imp("build/core/util.js");
export { bytesEqual } from "./bytes.mjs";

// The loader's admission step and name derivation (§5.1, §12.4) — tests drive the SAME
// code path a bundle load does rather than a parallel copy of it.
export const { appKeyFor, genesisHash: bundleGenesisHash, hybridAuthorId, FreshnessMarks,
         verifyManifest, verifyBundle, loadBundleModules, moduleFile, MANIFEST_FILE, GUEST_FILE }
  = await imp("build/host/bundle.js");
export const { signManifest, packBundle, guestOpFraming, authorBundle } = await imp("build/host/bundle-author.js");
export const { policyFromJson, authorAllowlist, hostGates } = await imp("build/host/policy.js");
export const { withMlDsa65, loadMlDsa65, ML_DSA65_PK_LEN, ML_DSA65_SIG_LEN } = await imp("build/host/pq.js");
export const gHash = (b) => bundleGenesisHash(sodium, b);

// Every app is a guest (§12.4), so every bundle a test builds declares one. The stub
// used by tests that do not exercise the guest is the same minimal program throughout.
export const GUEST_TEXT = "function handle() { return new Uint8Array([1]); }";
export const GUEST_BYTES = new TextEncoder().encode(GUEST_TEXT);
export const GUEST = (extra = {}) => ({ hash: toHex(gHash(GUEST_BYTES)), requires: [], ...extra });

/** A manifest author (§12.4): the Ed25519 half, the ML-DSA-65 half, and the 32-byte id the
 *  two derive. Tests name `a.id` wherever the runtime names an author (policy pins, app
 *  keys, freshness marks) and hand the whole object to `signManifest`, so none can pin
 *  half an identity. */
export const testAuthor = () => makeAuthor(sodium);

/** A NODE-platform node for one test: `bootNodeShell` (shell-node.ts) minus the channel
 *  adapter, which these tests do not drive. The disk-backed platform — NodeFs on a data
 *  directory, a file-backed freshness store — is the point of reaching for it over
 *  {@link bootTestShell}, which stands a node with no disk. */
export const boot = async (cfg) => (await bootNodeShell(cfg)).shell;

/** A node for ONE test, through the one assembly (`bootShell`, §12.9). The platform
 *  members are stated flat, as the assembly takes them; `fs` defaults to `false` — most
 *  bundles here declare no `fs` cap, and handing them the in-memory backend would be a
 *  seam open the test never asked for.
 *
 *  `pinAuthor` is whose signature the TRANSPORT PIN admits (§12.5). The pin is derived
 *  from a blob, and with no blob it is fail-closed — every bundle reaching `link` is
 *  refused before any predicate under test is consulted. What is handed over is a real
 *  signed bundle of that author's, because the pin is read off a signature rather than
 *  off a name; the socket-less driver beside it is the browser-edge shape (§12.6). */
export async function bootTestShell({ pinAuthor, ...opts } = {}) {
  const identity = opts.identity ?? generateKeyPair();
  const pinned = pinAuthor ? {
    transport: {
      load: false,
      bundle: packBundle({
        [MANIFEST_FILE]: signManifest(sodium, pinAuthor,
          { app: "pin", version: 1, modules: [], guest: GUEST() }),
        [GUEST_FILE]: GUEST_BYTES,
      }),
    },
  } : {};
  const { shell } = await bootShell({
    sodium,
    modules: new JsModuleLoader(),
    freshnessStore: new FreshnessMarks(),
    fs: false,
    ...pinned,
    ...opts,
    identity,
  });
  return shell;
}

/** The admission context a bundle with no history lands under: an ordinary app, never
 *  loaded here before, from a key nobody has written off. The shell reads these off its
 *  freshness store; a test composing the load by hand states them. */
export const APP_CTX = { privileges: [], highWater: -Infinity, revoked: false };
export const LINK_CTX = { ...APP_CTX, privileges: ["link"] };

/** `verifyBundle` → `admit` → `installBundle` (§12.4), for the policy + integrity tests
 *  that own their own ModuleTable without a shell. `admit` is AWAITED — a composed
 *  policy answers with a Promise, and reading one as a verdict is fail-open. */
export async function loadBundle(host, blob, admit, ctx = APP_CTX) {
  const v = verifyBundle(sodium, blob);
  if (!(await admit(v, ctx))) throw new Error("admit rejected");
  return installBundle(host, v);
}

// The empty payload — a module whose `handle` takes no meaningful input.
export const EMPTY = new Uint8Array(0);

// Standard bootstrap (§3): a fresh module table. The host holds no policy — it is the
// map and nothing else.
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
  host.adopt(appKeyFor(v.author, v.manifest.app), modules, v.modules.map(({ mod }) => mod.name));
  return { manifest: v.manifest, author: v.author, authorKeys: v.authorKeys, guestSource: v.guestSource };
};
export async function makeHost() {
  return { host: testHost(new JsModuleLoader()) };
}

export const forwarderBytes = new Uint8Array(readFileSync(join(root, "build/forwarder.wasm")));

// ML-DSA-65 onto the test instance exactly as a target does at its crypto seam — the
// hybrid manifest suite is "a sodium that knows this method" (§12.4).
withMlDsa65(sodium, await loadMlDsa65(readFileSync(join(root, "browser/mldsa65.wasm"))));

// Install one verified module as the whole of `appKey`'s module set. Async: a bind stands
// each module up in its own worker and returns when it has loaded.
export async function installMod(host, appKey, module, wasm) {
  await host.bindAll(appKey, [{ name: module, wasm }]);
}

// The §5.1 app key a bundle's modules land under, `"<author hex>:<app>"` — the real
// derivation, not a mirror, so a test can name a table entry without packing a whole
// bundle and still land where the loader would put it.
export const appKey = (authorPk, app) => appKeyFor(authorPk, app);
