// Build the transport bundle — the signed artifact the host ships and loads at
// boot (§12.6). Reads transport/guest.js (the AKE,
// record layer, link routing and request/response layer as a zero-authority guest
// program), signs a `role: "transport"` manifest with the transport author key,
// packs the container, and writes:
//
//   build/transport.skb        the bundle blob (--transport for the CLI)
//   host/transport-bundle.ts   base64 inline for the JS targets (like ws-wasm.ts)
//
// Both outputs are generated and gitignored. host/main.ts imports the second, so a
// clean checkout cannot typecheck until this script has run — which is why both
// `build` and `build:loader` sequence it ahead of tsc.
//
// It also prints the author id. THE AUTHOR ID IS WHAT POLICY PINS: the node admits
// the transport only when the operator's `roles.transport` lists it (§12.5), so
// a different build with a different key simply needs a different policy entry.
//
// The author key: `--key <32-byte seed hex>`. The default seed lives at
// transport/author.key, generated on first run and gitignored, so a fresh clone
// mints its own transport author. Nothing in-repo pins a fixed id — a policy entry
// is derived from the built artifact (`verifyBundle(blob).author`), which is what
// the tests do. This is a well-known developer identity, not a trust boundary: the
// operator's policy pin is the trust decision.

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import sodiumDefault from "libsodium-wrappers-sumo";

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
  const sodium = sodiumDefault;

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

  // The bundle format's build-side functions, mirrored here so this script is
  // self-contained (it must run BEFORE build:host on a clean checkout). They
  // match bundle.ts byte for byte: the manifest envelope is
  // `[suite(1)][pk(32)][sig(64)][utf8 json]` over `DOMAIN_manifest ‖ suite ‖ json`,
  // and the container is `"SKB1" ‖ count u16 ‖ …`. The loader unpacks exactly
  // what this packs.
  const DOMAIN_MANIFEST = new TextEncoder().encode("seedkernel-manifest-sig-v1\0");
  const MANIFEST_FILE = "manifest.bundle";
  const GUEST_FILE = "guest.js";
  const concat = (parts) => {
    let len = 0; for (const p of parts) len += p.length;
    const out = new Uint8Array(len); let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  };
  const signManifest = (s, sk, pk, m) => {
    const json = new TextEncoder().encode(JSON.stringify(m));
    const suite = 0x01; // SUITE_MANIFEST_GENESIS
    const pre = concat([DOMAIN_MANIFEST, Uint8Array.of(suite), json]);
    const sig = s.crypto_sign_detached(pre, sk);
    return concat([Uint8Array.of(suite), pk, sig, json]);
  };
  const packBundle = (files) => {
    const names = Object.keys(files);
    const header = new Uint8Array(6);
    header.set([0x53, 0x4b, 0x42, 0x31], 0);
    new DataView(header.buffer).setUint16(4, names.length, false);
    const parts = [header];
    for (const name of names) {
      const nameBytes = new TextEncoder().encode(name);
      const data = files[name];
      const rec = new Uint8Array(2 + nameBytes.length + 4);
      const dv = new DataView(rec.buffer);
      dv.setUint16(0, nameBytes.length, false);
      rec.set(nameBytes, 2);
      dv.setUint32(2 + nameBytes.length, data.length, false);
      parts.push(rec, data);
    }
    return concat(parts);
  };

  const kp = sodium.crypto_sign_seed_keypair(seed);
  const guest = readFileSync(join(root, "transport", "guest.js"));
  const manifest = {
    app: "transport",
    version: 1,
    role: "transport",
    modules: [],
    guest: {
      hash: toHex(sodium.crypto_generichash(32, guest)),
      abi: 1,
      // The AUTHORITIES this program is granted, and the whole of them: SIGN (scoped by
      // the transport slot to DOMAIN_channel), RANDOM and CLOCK; `rawnet`, the sockets
      // behind opaque link ids; `timer`, because a zero-authority realm has no
      // setTimeout; and `transport`, where it reports its structured output. The last
      // two of those are slot-only and the loader refuses them to a bundle claiming no
      // role. No `net` — that domain IS this program's output, and its own NET_SEND
      // would loop back into itself.
      caps: ["crypto", "clock", "timer", "rawnet", "transport"],
      // The primitives it calls by name. NOT a grant — a pure transform reaches nothing
      // — but a compatibility claim, so a host lacking one refuses this bundle by name
      // instead of failing mid-handshake.
      primitives: [
        "blake2b-256", "ed25519/verify",
        "chacha20poly1305-ietf/seal", "chacha20poly1305-ietf/open", "x25519/dh",
      ],
    },
  };
  const env = signManifest(sodium, kp.privateKey, kp.publicKey, manifest);
  const blob = packBundle({ [MANIFEST_FILE]: env, [GUEST_FILE]: guest });

  writeFileSync(join(root, "build", "transport.skb"), blob);
  const b64 = Buffer.from(blob).toString("base64");
  const ts = `// GENERATED by scripts/build-transport-bundle.mjs — DO NOT EDIT.
// The artifact-shipped transport bundle (§12.6): the
// channel AKE, record layer, link routing and request/response layer as a signed
// bundle claiming the transport role. Signed by the seed transport author
//   ${toHex(kp.publicKey)}
// — pin that id in policy as \`roles.transport\` (\u00a712.5) or build your own
// with this script and pin that. Rebuild with a different key: new author, new
// policy entry. See scripts/build-transport-bundle.mjs.
export const TRANSPORT_BUNDLE_B64 = "${b64}";
`;
  writeFileSync(join(root, "host", "transport-bundle.ts"), ts);
  console.log(`  transport bundle: build/transport.skb (${blob.length} B)`);
  console.log(`  transport author: ${toHex(kp.publicKey)}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
