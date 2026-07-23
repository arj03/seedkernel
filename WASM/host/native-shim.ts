// The native loader's binding of the shared host core (README §12.9). The Go loader
// (native/) runs this inside QuickJS; it is bundled to native/host-installer.gen.js by
// scripts/bundle-loader.mjs, exactly like the netroute / ws / cap-bridge bundles.
//
// This file is a SEAM, not an implementation: every protocol rule — who may install
// (§12.5), the name derivation (§5.1), the admit-then-SetHandler step (§12.4), the
// manifest signature + its domain prefix (§12.4), the freshness arithmetic, the deny-all
// default — comes from bundle.ts and policy.ts, compiled once and shared. What lives here
// is only the glue that cannot: the Go bridge is byte-level, so the powers the loader
// needs (instantiate wasm, bind a name, write a file atomically) arrive as `bridge.*` and
// are adapted to the `BundleHost` / `FreshnessStore` interfaces here.
//
// Because it is TypeScript checked against those same interfaces, the drift that a
// hand-written mirror accumulates is now a compile error.

import { policyFromJson, type ShellPolicy } from "./policy.js";
import {
  FreshnessMarks, handlesOf, kernelNameFor, loadBundle,
  type BundleHost,
} from "./bundle.js";
import { bundlePreamble } from "./cap-bridge.js";
import { toHex } from "./util.js";

/** The byte-level primitives the Go loader exposes into the realm (native/main.go).
 *  Only the host powers QuickJS genuinely cannot reach: everything else is JS. */
declare const bridge: {
  /** Compile + instantiate handler bytes against the §4 ABI. Returns an opaque token
   *  for a later bindWasm; throws on structural failure. No table effect. */
  instantiateWasm(wasm: Uint8Array): unknown;
  /** Bind a pre-instantiated handler token at `name` on the handler table. */
  bindWasm(name: string, token: unknown): void;
  /** Release a handler token that will never be bound (bundle failed). Frees the
   *  wazero instance + compiled code. */
  discardWasm(token: unknown): void;
  /** Unbind `name` (SetHandler(name, null)). Exposed for operator revocation. */
  removeHandler(name: string): boolean;
  /** The persisted freshness store's contents, or null on first boot. */
  readFreshness(): string | null;
  /** Write the freshness store atomically (temp file + rename). */
  writeFreshness(json: string): void;
};

/** libsodium, in libsodium-wrappers method names (native/sodium.go exposeSodium). Satisfies
 *  the loader's `BundleCrypto` directly, so no adapter stands between the shared loader and
 *  Go's crypto. */
declare const sodium: {
  crypto_generichash(hashLength: number, message: Uint8Array, key?: Uint8Array | null): Uint8Array;
  crypto_sign_verify_detached(sig: Uint8Array, msg: Uint8Array, pk: Uint8Array): boolean;
};

/** The Go loader as a `BundleHost` — the two-phase install (instantiate all, then bind). */
const host: BundleHost = {
  instantiateWasm(wasm: Uint8Array): unknown { return bridge.instantiateWasm(wasm); },
  bindHandler(name: string, ref: unknown): void { bridge.bindWasm(name, ref); },
  discardHandler(ref: unknown): void { bridge.discardWasm(ref); },
};

/** The freshness store over the Go atomic-write seam (README §12.4). */
class NativeFreshnessStore extends FreshnessMarks {
  constructor() {
    super();
    this.load(bridge.readFreshness());
  }
  protected override persist(json: string): void { bridge.writeFreshness(json); }
}

let freshness: NativeFreshnessStore | null = null;
// The realm boots deny-all (README §14): setPolicy has not run, so the author set is
// empty and every install is refused. A permissive default here would be a silent
// second posture — the whole reason this file is generated rather than written.
let policy: ShellPolicy = policyFromJson(null);
const applyPolicy = (p: ShellPolicy): void => { policy = p; };

/** Narrow the realm's trust to a policy config (§12.5). `null` restores the deny-all
 *  default; malformed JSON throws, so a typo fails the loader's boot loudly. */
function setPolicy(json: string | null): void {
  applyPolicy(policyFromJson(json));
}

/** Load a signed bundle (README §12.4). Go has read the one bundle file — that is the
 *  whole fs seam — and passes its bytes; every check and its order comes from the shared
 *  loader. Returns a JSON descriptor of what Go must act on, or an `ERROR: …` string (the
 *  loader reports, it does not throw across the bridge).
 *
 *  The descriptor carries the guest SOURCE, not a filename: the source it returns is the
 *  one this loader hashed against the manifest, so Go runs exactly the bytes that were
 *  verified rather than looking a name up in a copy of its own. */
function loadBundleBlob(blob: ArrayBuffer): string {
  // Built on first use, not at module scope: Go learns its data directory (and so the
  // store's path) from the CLI *after* it evaluates this bundle.
  if (!freshness) freshness = new NativeFreshnessStore();
  try {
    const b = loadBundle(host, sodium, policy, new Uint8Array(blob), freshness);
    const modMap = Object.fromEntries(b.manifest.modules.map((m) =>
      [m.name, kernelNameFor(b.author, b.manifest.app, m.name)]));
    return JSON.stringify({
      app: b.manifest.app,
      version: b.manifest.version,
      author: toHex(b.author),
      // Protocol ids this app offers to serve (§12.10), defaulted here so Go never
      // reimplements the "absent ⇒ [app]" rule. Binding them is the operator's, not the
      // loader's: declaring confers no traffic.
      handles: handlesOf(b.manifest),
      // Authority and config live inside `guest` — a handler-only bundle has neither
      // (§12.4). `guestSource` is "" in that case and Go builds no realm.
      caps: b.manifest.guest?.caps ?? [],
      config: b.manifest.guest?.config ?? {},
      guestSource: b.guestSource,
      // The "const BUNDLE = {…};\n" preamble this bundle's guest runs under. Built here
      // from the admitted manifest so Go never re-derives the signing prefix.
      bundlePreamble: bundlePreamble({ app: b.manifest.app, author: b.author }),
      // Logical → kernel name map for MODULE_CALL resolution (the bridge needs it).
      modules: modMap,
    });
  } catch (e) {
    return "ERROR: " + (e as Error).message;
  }
}

export { setPolicy, loadBundleBlob };
