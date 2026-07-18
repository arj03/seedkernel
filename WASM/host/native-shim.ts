// The native loader's binding of the shared host core (README §12.9). The Go loader
// (native/) runs this inside QuickJS; it is bundled to native/host-installer.gen.js by
// scripts/bundle-loader.mjs, exactly like the netroute / ws / cap-bridge bundles.
//
// This file is a SEAM, not an implementation: every protocol rule — who may bind a
// name (§7.4), the manifest signature + its domain prefix (§12.4), the freshness
// arithmetic, the deny-all default — comes from installer.ts, bundle.ts and
// policy.ts, compiled once and shared. What lives here is only the glue that
// cannot: the Go bridge is byte-level, so the powers the registry needs
// (instantiate wasm, hash, query the handler table, write a file atomically)
// arrive as `bridge.*` and `sodium.*` and are adapted to the `InstallerHost` /
// `BundleHost` / `FreshnessStore` interfaces here.
//
// Because it is TypeScript checked against those same interfaces, the drift that a
// hand-written mirror accumulates is now a compile error.

import { Installer, type InstallerHost } from "./installer.js";
import { buildApproveInstall, policyFromJson, type ShellPolicy } from "./policy.js";
import { FreshnessMarks, loadBundle, type BundleHost, type BundleSource } from "./bundle.js";
import { toHex } from "./util.js";

/** The genesis signature suite's algo_id (§6.2) — an Ed25519 manifest author. */
const GENESIS_ALGO_ID = 0x0000;

/** The byte-level primitives the Go loader exposes into the realm (native/main.go).
 *  Only the host powers QuickJS genuinely cannot reach: everything else is JS. */
declare const bridge: {
  /** Instantiate handler bytes against the §4 ABI and SetHandler them at `name`. */
  installWasm(name: Uint8Array, wasm: Uint8Array): boolean;
  /** Does a handler already occupy `name`? (The kernel's `find_handler`.) */
  isRegistered(name: Uint8Array): boolean;
  /** Unbind `name` (SetHandler(name, null)). */
  removeHandler(name: Uint8Array): boolean;
  /** The persisted freshness store's contents, or null on first boot. */
  readFreshness(): string | null;
  /** Write the freshness store atomically (temp file + rename). */
  writeFreshness(json: string): void;
};

/** libsodium, in libsodium-wrappers method names (native/sodium.go exposeSodium). */
declare const sodium: {
  crypto_hash_sha3256(data: Uint8Array): Uint8Array;
  crypto_sign_verify_detached(sig: Uint8Array, msg: Uint8Array, pk: Uint8Array): boolean;
};

/** The Go loader as an `InstallerHost` + `BundleHost`. Every member is a one-line
 *  forward to the bridge — if one grows logic, it belongs in the shared core instead. */
class NativeHost implements InstallerHost, BundleHost {
  readonly installer = new Installer(this);

  genesisHash(data: Uint8Array): Uint8Array { return sodium.crypto_hash_sha3256(data); }
  _installWasmHandler(name: Uint8Array, wasm: Uint8Array): boolean { return bridge.installWasm(name, wasm); }
  removeHandler(name: Uint8Array): boolean { return bridge.removeHandler(name); }
  isRegistered(name: Uint8Array): boolean { return bridge.isRegistered(name); }

  installBundleModule(name: Uint8Array, wasm: Uint8Array, authorPubKey: Uint8Array): boolean {
    return this.installer.installDirect(name, wasm, { algoId: GENESIS_ALGO_ID, publicKey: authorPubKey });
  }
}

/** The freshness store over the Go atomic-write seam (README §12.4). */
class NativeFreshnessStore extends FreshnessMarks {
  constructor() {
    super();
    this.load(bridge.readFreshness());
  }
  protected override persist(json: string): void { bridge.writeFreshness(json); }
}

const host = new NativeHost();
let freshness: NativeFreshnessStore | null = null;
// The realm boots deny-all (README §14): setPolicy has not run, so the author set is
// empty and every install is refused. A permissive default here would be a silent
// second posture — the whole reason this file is generated rather than written.
let policy: ShellPolicy = policyFromJson(null);
const applyPolicy = (p: ShellPolicy): void => {
  policy = p;
  host.installer.setApproveInstall(buildApproveInstall(host, p));
};
applyPolicy(policy);

/** Narrow the realm's trust to a policy config (§7.4). `null` restores the deny-all
 *  default; malformed JSON throws, so a typo fails the loader's boot loudly. */
function setPolicy(json: string | null): void {
  applyPolicy(policyFromJson(json));
}

/** Load a signed bundle (README §12.4). Go has already read the directory — it is the
 *  fs seam — and passes `{ filename: ArrayBuffer }`; every check and its order comes
 *  from the shared loader. Returns a slim JSON descriptor of what Go must act on, or
 *  an `ERROR: …` string (the loader reports, it does not throw across the bridge). */
function loadBundleFiles(files: Record<string, ArrayBuffer>): string {
  const src: BundleSource = {
    read: (file) => {
      const b = files[file];
      if (!b) throw new Error(`bundle: missing file ${file}`);
      return new Uint8Array(b);
    },
    readText: (file) => new TextDecoder().decode(src.read(file)),
  };
  // Built on first use, not at module scope: Go learns its data directory (and so the
  // store's path) from the CLI *after* it evaluates this bundle.
  if (!freshness) freshness = new NativeFreshnessStore();
  try {
    const b = loadBundle(host, sodium, policy, src, freshness);
    return JSON.stringify({
      app: b.manifest.app,
      version: b.manifest.version,
      author: toHex(b.author),
      caps: b.manifest.caps,
      guest: b.manifest.guest.file,
      config: b.manifest.config ?? {},
      installed: b.installed,
    });
  } catch (e) {
    return "ERROR: " + (e as Error).message;
  }
}

export { setPolicy, loadBundleFiles };
