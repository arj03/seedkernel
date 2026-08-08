// Build the transport bundle — the signed artifact the host ships and loads at
// boot (§12.6). Reads transport/guest.js (the AKE,
// record layer, link routing and request/response layer as a zero-authority guest
// program), signs a transport manifest with the transport author key,
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
// the transport only when the operator's `transportAuthors` lists it (§12.5), so
// a different build with a different key simply needs a different policy entry.
//
// The manifest is signed under suite `0x02`, the hybrid Ed25519 + ML-DSA-65
// envelope (§12.4, §14.1): a PQ verifier could never have been delivered as a
// bundle, and a PQ *identity* is equally immovable — the 0x02 author id is a
// key-set hash, not the Ed25519 key, so an author who migrates later changes every
// pin and every table name built on the old id. The artifact therefore ships
// hybrid from the start; the ML-DSA half of the key set is derived from the same
// `--key` seed as the Ed25519 half, so one key file still holds the whole identity.
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

// FIPS 204 ML-DSA-65 field widths — the same numbers pq.ts cross-checks the module
// against at load (`ML_DSA65_*`), restated here because this script must run before
// build:host on a clean checkout and mirrors the build-side surface byte for byte.
const ML_DSA65_PK_LEN = 1952;
const ML_DSA65_SK_LEN = 4032;
const ML_DSA65_SIG_LEN = 3309;
const ML_DSA65_SEED_LEN = 32;
const ML_DSA65_RND_LEN = 32;

// A self-contained ML-DSA-65 driver over mldsa65.wasm, mirroring pq.ts's bump
// allocator: every call rewinds to __heap_base, writes its inputs into the module's
// own linear memory, runs it, and reads the output back. The module never allocates
// and never retains anything across a call, so a bump pointer is the whole memory
// manager and there is no free list to corrupt.
function makeMlDsa(wasmBytes) {
  const e = new WebAssembly.Instance(new WebAssembly.Module(wasmBytes), {}).exports;
  const widths = [
    ["public key", e.mldsa65_publickeybytes(), ML_DSA65_PK_LEN],
    ["secret key", e.mldsa65_secretkeybytes(), ML_DSA65_SK_LEN],
    ["signature", e.mldsa65_signaturebytes(), ML_DSA65_SIG_LEN],
  ];
  for (const [what, got, want] of widths) {
    if (got !== want) throw new Error(`transport: mldsa65.wasm reports ${what} width ${got}, expected ${want}`);
  }
  const heapBase = e.__heap_base.value;
  let top = heapBase;
  const rewind = () => { top = heapBase; };
  const alloc = (n) => {
    const p = (top + 15) & ~15;
    top = p + n;
    const short = top - e.memory.buffer.byteLength;
    if (short > 0) e.memory.grow(Math.ceil(short / 65536) + 1);
    return p;
  };
  const bytes = () => new Uint8Array(e.memory.buffer);
  const put = (b) => { const p = alloc(b.length); bytes().set(b, p); return p; };
  // FIPS 204's hedging randomness, drawn here like pq.ts draws it: from the host's
  // CSPRNG rather than from inside the module, which keeps it import-free.
  const rnd = (n) => { const o = new Uint8Array(n); globalThis.crypto.getRandomValues(o); return o; };
  return {
    keypair(seed) {
      if (seed.length !== ML_DSA65_SEED_LEN) throw new Error(`transport: ml-dsa-65 seed must be ${ML_DSA65_SEED_LEN} bytes`);
      rewind();
      const pkP = alloc(ML_DSA65_PK_LEN), skP = alloc(ML_DSA65_SK_LEN), seedP = put(seed);
      if (e.mldsa65_keypair(pkP, skP, seedP) !== 1) throw new Error("transport: ml-dsa-65 keygen failed");
      const m = bytes();
      return {
        publicKey: m.slice(pkP, pkP + ML_DSA65_PK_LEN),
        privateKey: m.slice(skP, skP + ML_DSA65_SK_LEN),
      };
    },
    sign(message, sk) {
      if (sk.length !== ML_DSA65_SK_LEN) throw new Error(`transport: ml-dsa-65 secret key must be ${ML_DSA65_SK_LEN} bytes`);
      rewind();
      const sigP = alloc(ML_DSA65_SIG_LEN);
      const msgP = put(message);
      const rndP = put(rnd(ML_DSA65_RND_LEN));
      const skP = put(sk);
      if (e.mldsa65_sign(sigP, msgP, message.length, 0, 0, rndP, skP) !== 1) {
        throw new Error("transport: ml-dsa-65 signing failed");
      }
      return bytes().slice(sigP, sigP + ML_DSA65_SIG_LEN);
    },
  };
}

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
  // `[0x02][edPk(32)][mlDsaPk(1952)][edSig(64)][mlDsaSig(3309)][utf8 json]` over
  // `DOMAIN_manifest ‖ suite ‖ edPk ‖ mlDsaPk ‖ json`, and the container is
  // `"SKB1" ‖ count u16 ‖ …`. The loader unpacks exactly what this packs.
  const DOMAIN_MANIFEST = new TextEncoder().encode("seedkernel-manifest-sig-v1\0");
  const DOMAIN_MANIFEST_AUTHOR = new TextEncoder().encode("seedkernel-manifest-author-v1\0");
  const PQ_SEED_LABEL = new TextEncoder().encode("seedkernel-author-mldsa-v1");
  const MANIFEST_FILE = "manifest.bundle";
  const GUEST_FILE = "guest.js";
  const concat = (parts) => {
    let len = 0; for (const p of parts) len += p.length;
    const out = new Uint8Array(len); let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
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

  // The author's key set under suite 0x02: the Ed25519 key from the seed, and the
  // ML-DSA-65 key derived from the SAME seed, so one key file holds the whole
  // identity and a rebuild with the same key is the same author (§12.4).
  const kp = sodium.crypto_sign_seed_keypair(seed);
  const pqSeed = sodium.crypto_generichash(32, concat([seed, PQ_SEED_LABEL]));
  const mldsa = makeMlDsa(readFileSync(join(root, "browser", "mldsa65.wasm")));
  const pq = mldsa.keypair(pqSeed);

  const guest = readFileSync(join(root, "transport", "guest.js"));
  // ws.wasm rides IN the bundle: the RFC 6455 codec is content, so it arrives through
  // the one install path signed by this program's own author and is reached by logical
  // name through host.call. It is an ordinary §4 pure transform — three exports, no
  // imports but the AS shims — so the loader admits it like any other module.
  const wsWasm = readFileSync(join(root, "build", "ws.wasm"));
  const manifest = {
    app: "transport",
    version: 1,
    modules: [{ name: "ws", hash: toHex(sodium.crypto_generichash(32, wsWasm)) }],
    guest: {
      hash: toHex(sodium.crypto_generichash(32, guest)),
      abi: 3,
      // EXACTLY the authorities this program holds — and, since the list is grants only,
      // exactly what an operator is agreeing to when they mount it. `node/sign` +
      // `node/verify` (slot-scoped signing and its verification twin) and
      // `node/random` (entropy); `link/*`, the sockets behind
      // opaque link ids; `timer/*`, because a zero-authority realm has no setTimeout;
      // `transport/*`, where it reports its structured output. The last two are the
      // catalog's mount halves (`mount:sockets` + `mount:report`): the shell refuses a
      // bundle naming either to the ordinary app path and requires BOTH of a mount —
      // which is what makes this list, and not a self-description, the thing that says
      // what this bundle is. No `net`: that vocabulary IS this program's output, and its
      // own net/send would loop back into itself.
      //
      // Its ws.wasm and its crypto are absent because neither is a grant and neither can
      // be missing — a bare `host.call` name reaches modules that arrived in this same
      // signed bundle, and the primitive catalog is total on any host that has a cap
      // bridge at all. What this program needs of them is `abi: 3` above (§12.1).
      requires: [
        "node/sign", "node/verify", "node/random",
        "link/open", "link/send", "link/close", "link/stat",
        "timer/arm", "timer/clear",
        "transport/deliver", "transport/settle", "transport/link-auth",
        "transport/peer-edge", "transport/ready", "transport/link-down",
      ],
    },
  };
  const json = new TextEncoder().encode(JSON.stringify(manifest));
  const suite = 0x02; // SUITE_MANIFEST_HYBRID_PQ: Ed25519 + ML-DSA-65, both required
  const pre = concat([DOMAIN_MANIFEST, Uint8Array.of(suite), kp.publicKey, pq.publicKey, json]);
  const edSig = sodium.crypto_sign_detached(pre, kp.privateKey);
  const pqSig = mldsa.sign(pre, pq.privateKey);
  const env = concat([Uint8Array.of(suite), kp.publicKey, pq.publicKey, edSig, pqSig, json]);
  // The 0x02 author id: the key-set hash policy pins, table names derive from, and
  // freshness is keyed by — NOT the Ed25519 key (bundle.ts `hybridAuthorId`).
  const authorId = sodium.crypto_generichash(32, concat([DOMAIN_MANIFEST_AUTHOR, Uint8Array.of(suite), kp.publicKey, pq.publicKey]));
  const blob = packBundle({ [MANIFEST_FILE]: env, [GUEST_FILE]: guest, "ws.wasm": wsWasm });

  writeFileSync(join(root, "build", "transport.skb"), blob);
  const b64 = Buffer.from(blob).toString("base64");
  const ts = `// GENERATED by scripts/build-transport-bundle.mjs — DO NOT EDIT.
// The artifact-shipped transport bundle (§12.6): the
// channel AKE, record layer, link routing and request/response layer as a signed
// bundle for the shell's explicit transport mount. Signed by the seed transport author
//   ${toHex(authorId)}
// under the hybrid suite 0x02 (Ed25519 + ML-DSA-65, §14.1) — pin that id in policy
// as \`transportAuthors\` (\u00a712.5) or build your own with this script and pin that.
// Rebuild with a different key: new author, new policy entry. The ML-DSA half of the
// key set is derived from the same seed, so one key file holds the whole identity.
// See scripts/build-transport-bundle.mjs.
export const TRANSPORT_BUNDLE_B64 = "${b64}";
`;
  writeFileSync(join(root, "host", "transport-bundle.ts"), ts);
  console.log(`  transport bundle: build/transport.skb (${blob.length} B)`);
  console.log(`  transport author: ${toHex(authorId)} (hybrid 0x02)`);
  console.log(`  ed25519 half:     ${toHex(kp.publicKey)}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
