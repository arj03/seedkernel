// Build the transport bundle — the signed artifact the host ships and loads at boot
// (§12.6). Assembles the guest from its parts (scripts/guest-source.mjs), signs a
// transport manifest with the transport author key, packs the container, and writes:
//
//   build/transport.skb        the bundle blob (--transport for the CLI)
//   host/transport-bundle.ts   base64 inline for the JS targets
//
// Both outputs are generated and gitignored. host/main.ts imports the second, so a
// clean checkout cannot typecheck until this script has run — hence `build` and
// `build:loader` sequencing it ahead of tsc.
//
// It also prints the author id, WHICH IS WHAT POLICY PINS: the node admits the
// transport only when the operator's `grants.link` lists it (§12.5), so a different
// build with a different key needs a different policy entry.
//
// The manifest is signed under suite `0x02`, the hybrid Ed25519 + ML-DSA-65 envelope
// (§12.4, §14.1), using host/bundle.ts's `authorBundle` (hash, assemble, validate, sign,
// pack — one call, carrying the derived author id), `hybridAuthorKeysFromSeed`, and
// host/pq.ts's ML-DSA-65 driver — the SAME functions the runtime signs and verifies
// bundles with, not a second copy. Those live in host/*.ts, and this script must run
// BEFORE the project's full `tsc -p .` (host/main.ts imports this script's OWN
// generated output,
// host/transport-bundle.ts, so a clean checkout cannot typecheck until this script has
// run). That would ordinarily make host/bundle.ts and host/pq.ts unavailable here too —
// they are typescript, not yet built — so `npm run build:transport-bundle` first runs a
// narrow bootstrap compile (tsconfig.transport-prebuild.json) covering only the
// import-free subgraph this script needs (core/util.ts, core/domains.ts,
// core/wasm-limits.ts, host/bundle.ts, host/pq.ts — none of which reach host/main.ts or
// the not-yet-generated transport-bundle.ts), and this script imports THAT output. The
// full `build:host` compile afterward overwrites those same build/ files with identical
// canonical output, so nothing is left half-built.
//
// A PQ *identity* is as immovable as a PQ verifier: the 0x02 author id is a key-set
// hash, so an author migrating later changes every pin and every table name built on
// the old id. The ML-DSA half is derived from the same `--key` seed, so one key file
// holds the whole identity.
//
// The author key is `--key <32-byte seed hex>`, defaulting to transport/author.key —
// generated on first run and gitignored, so a fresh clone mints its own author.
// Nothing in-repo pins a fixed id: a policy entry is derived from the built artifact
// (`verifyBundle(blob).author`), as the tests do. This is a well-known developer
// identity, not a trust boundary; the operator's pin is the trust decision.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import sodiumDefault from "libsodium-wrappers-sumo";
import { readGuestSource, readGuestAbi } from "./guest-source.mjs";
import { authorBundle, hybridAuthorKeysFromSeed } from "../build/host/bundle.js";
import { createMlDsa65, withMlDsa65 } from "../build/host/pq.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");

const args = process.argv.slice(2);
const keyFlag = (() => {
  const i = args.indexOf("--key");
  return i >= 0 && args[i + 1] ? args[i + 1] : undefined;
})();

const toHex = (b) => Buffer.from(b).toString("hex");

async function main() {
  await sodiumDefault.ready;
  let sodium = sodiumDefault;

  let seed;
  const keyPath = join(root, "transport", "author.key");
  if (keyFlag) {
    seed = Uint8Array.from(Buffer.from(keyFlag, "hex"));
  } else if (existsSync(keyPath)) {
    seed = Uint8Array.from(Buffer.from(readFileSync(keyPath, "utf8").trim(), "hex"));
  } else {
    seed = sodium.randombytes_buf(32);
    writeFileSync(keyPath, toHex(seed) + "\n", { mode: 0o600 });
    console.log("  wrote transport/author.key (keep it; this clone's bundle is signed by it)");
  }
  if (seed.length !== 32) throw new Error("--key must be 32 bytes of hex");

  // The ML-DSA-65 driver, mixed onto `sodium` (pq.ts `withMlDsa65`) so the one object
  // satisfies both `AuthorSeedCrypto` and `ManifestCrypto` below — libsodium supplies the
  // Ed25519 half and `crypto_generichash`, the mixin supplies the ML-DSA-65 half.
  const mldsaInstance = new WebAssembly.Instance(
    new WebAssembly.Module(readFileSync(join(root, "browser", "mldsa65.wasm"))), {});
  sodium = withMlDsa65(sodium, createMlDsa65(mldsaInstance));

  // The author's key set: the Ed25519 key from the seed, and the ML-DSA-65 key derived
  // from the SAME seed (host/bundle.ts `hybridAuthorKeysFromSeed`), so a rebuild with the
  // same key is the same author (§12.4).
  const keys = hybridAuthorKeysFromSeed(sodium, seed);

  const guest = readGuestSource();
  // ws.wasm rides IN the bundle: the RFC 6455 codec is content, so it arrives through the
  // one install path signed by this program's own author and is reached by logical name.
  // An ordinary §4 pure transform, admitted like any other module.
  const wsWasm = readFileSync(join(root, "build", "ws.wasm"));
  const { blob, author } = authorBundle(sodium, keys, {
    app: "transport",
    version: 1,
    // The local service name chosen by this composition. It has no kernel semantics.
    protocols: ["_net"],
    modules: [{ name: "ws", wasm: wsWasm }],
    guestSource: guest,
    // Read off the seam this program is compiled against, never retyped: a bundle
    // whose declared ABI and actual ABI can differ is one that loads and then
    // misreads its own arguments (the failure `guest.abi` exists to make loud).
    guestAbi: readGuestAbi(),
    // EXACTLY the authorities this program holds, and so exactly what an operator
    // agrees to in granting it `link`. `link/*` — the sockets behind opaque link ids —
    // are the ONLY names carrying that privilege.
    //
    // What this program PROVIDES back is not here: it is not an authority it calls, it
    // is the id it claims above. Its ws.wasm and its crypto are absent because neither
    // is a grant and neither can be missing — a bare `host.call` name reaches modules
    // from this same signed bundle, and the primitive catalog is total on any host with
    // a guest seam. What this program needs of them is the `abi` above (§12.1).
    guestRequires: [
      "node/random",
      "link/config", "link/open", "link/send", "link/close", "link/stat",
      "link/authenticated", "link/down", "link/sign", "link/verify", "route/deliver",
      "timer/arm", "timer/clear",
    ],
  });
  // The 0x02 author id: the key-set hash policy pins, table names derive from, and
  // freshness is keyed by — NOT the Ed25519 key (bundle.ts `hybridAuthorId`). Carried
  // on the authorBundle value above.
  writeFileSync(join(root, "build", "transport.skb"), blob);
  const b64 = Buffer.from(blob).toString("base64");
  const ts = `// GENERATED by scripts/build-transport-bundle.mjs — DO NOT EDIT.
// The artifact-shipped transport bundle (§12.6), signed by the seed transport author
//   ${toHex(author)}
// under the hybrid suite 0x02 (Ed25519 + ML-DSA-65, §14.1) — pin that id in policy
// under \`grants.link\` (\u00a712.5) or build your own with this script and pin that.
// A rebuild with a different key is a new author and a new policy entry; the ML-DSA half
// is derived from the same seed, so one key file holds the whole identity.
import { fromBase64 } from "../core/util.js";
export const TRANSPORT_BUNDLE_B64 = "${b64}";
let decoded: Uint8Array | null = null;
/** The artifact-shipped transport bundle as raw bytes (§12.6) — the shape every
 *  consumer of this artifact wants, instead of the b64 string and a hand-rolled
 *  atob loop. A fresh copy per call; the blob is a value callers may hand to the
 *  bundle loader, which does not mutate it but is not relied on either. */
export function transportBundleBytes() {
    if (decoded === null) decoded = fromBase64(TRANSPORT_BUNDLE_B64);
    return decoded.slice();
}
`;
  writeFileSync(join(root, "host", "transport-bundle.ts"), ts);
  console.log(`  transport bundle: build/transport.skb (${blob.length} B)`);
  console.log(`  transport author: ${toHex(author)} (hybrid 0x02)`);
  console.log(`  ed25519 half:     ${toHex(keys.ed.publicKey)}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
