// host.js — seedkernel host orchestration, run inside QuickJS by the Go loader.
// This is the REUSABLE layer (installer §7 + bundle verification §13); the Go
// loader is only a bridge — `bridge.*` exposes byte-level primitives into the
// wasm runtime, which QuickJS cannot touch directly. Same logic as
// host/installer.ts and host/bundle.ts; future host logic is written once, here.
"use strict";

const records = new Map(); // nameHex  -> { algo, pk, hash }   (§7.1)
const lastSeen = new Map(); // pkHex   -> seq                                 (§4.4)

const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (s) => Uint8Array.from(s.match(/../g) || [], (h) => parseInt(h, 16));
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

// ── Installer (README §7) ────────────────────────────────────────────────

// The shell's install policy. null ⇒ the permissive default (first installs
// accepted). When set via setPolicy it narrows trust to a closed author-key set
// and an optional module bytesHash allowlist — mirrors host/policy.ts (parsePolicy
// + buildApproveInstall) for the Go target. Capabilities are no longer install-
// declared (the JS sandbox is the confinement), so there is no cap allowlist.
let policy = null;

function parsePolicy(json) {
  const raw = JSON.parse(json);
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new Error("policy: expected a JSON object");
  const hexList = (v, field) => {
    if (!Array.isArray(v) || v.some((x) => typeof x !== "string")) throw new Error(`policy: "${field}" must be an array of hex strings`);
    return v.map((s) => s.toLowerCase());
  };
  const authors = hexList(raw.authors, "authors");
  if (authors.length === 0) throw new Error('policy: "authors" must list at least one allowed author key');
  const p = { authors: new Set(authors), modules: null };
  if (raw.modules !== undefined) p.modules = new Set(hexList(raw.modules, "modules"));
  return p;
}
globalThis.setPolicy = function (json) { policy = parsePolicy(json); };

// approve — the §7.4 install gate. Two rules for WHO may bind a name (capabilities
// are no longer install-declared): a subsequent install must match the existing
// record's author; a first install is accepted by the permissive default, or gated
// by the policy's author set + optional module bytesHash allowlist. Mirrors
// host/policy.ts (referencePolicy) + host/installer.ts.
function approve(author, hash, ex) {
  if (ex) return author.algo === ex.algo && eq(author.pk, ex.pk);
  if (policy) {
    if (!policy.authors.has(hex(author.pk))) return false;
    if (policy.modules && !policy.modules.has(hex(hash))) return false;
  }
  return true;
}

// onInstall — the §7.2 install-message handler. Go calls this when a signed
// install envelope dispatches; `payloadBuf` is the §7.2 payload (ArrayBuffer).
globalThis.onInstall = function (payloadBuf) {
  const p = new Uint8Array(payloadBuf);
  const sig = new Uint8Array(bridge.topSigner());
  if (sig.length < 3 || p.length < 5) return;
  const author = { algo: (sig[0] << 8) | sig[1], pk: sig.slice(2) };

  // §7.2 payload: [seq u32][name_len u8][name][wasm]. No cap block — capabilities
  // are no longer install-declared (mirrors host/installer.ts).
  const seq = ((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]) >>> 0;
  let o = 4;
  const nLen = p[o++];
  if (nLen === 0 || o + nLen > p.length) return;
  const name = p.slice(o, (o += nLen));
  const wasm = p.slice(o);
  if (wasm.length === 0) return;

  const hash = sodium.crypto_hash_sha3256(wasm); // bytes_hash = genesisHash(wasm) (§7.1)
  const pkHex = hex(author.pk);
  if (lastSeen.has(pkHex) && seq <= lastSeen.get(pkHex)) return; // §4.4 replay
  lastSeen.set(pkHex, seq);

  const ex = records.get(hex(name)) || null;
  if (!approve(author, hash, ex)) return;
  if (!bridge.installWasm(name, wasm)) return;
  records.set(hex(name), { algo: author.algo, pk: author.pk, hash });
};

// ── Bundle verification (README §13.4) ───────────────────────────────────

// Domain-separation prefix for the manifest signature (README §13.4, §17.1):
// "seedkernel-manifest-sig-v1\0". Prepended to the JSON before verifying, never
// stored in the envelope — mirrors host/bundle.ts. The disjoint prefix keeps a
// manifest signature from doubling as an envelope-wrapper or channel-handshake
// signature over the same bytes.
const DOMAIN_MANIFEST = Uint8Array.from("seedkernel-manifest-sig-v1\0", (c) => c.charCodeAt(0));

// verifyBundle checks an app bundle's signed manifest and module/guest content
// integrity, returning a slim descriptor for Go to act on (Go dispatches the
// pre-signed installs). `files` is { filename: ArrayBuffer }. Mirrors bundle.ts
// verifyManifest + contentMatches.
globalThis.verifyBundle = function (manifestEnvBuf, files) {
  const env = new Uint8Array(manifestEnvBuf);
  if (env.length < 96) return "ERROR: manifest too short";
  const author = env.slice(0, 32), sig = env.slice(32, 96), json = env.slice(96);
  // Verify over DOMAIN_manifest ‖ json (§13.4); the prefix is signed, not stored.
  const preimage = new Uint8Array(DOMAIN_MANIFEST.length + json.length);
  preimage.set(DOMAIN_MANIFEST, 0);
  preimage.set(json, DOMAIN_MANIFEST.length);
  // sodium.* reads its args via JsTypedArrayToGo, which copies and leaves the source
  // intact, so `author`/`json` survive for the policy check + parsing below.
  if (!sodium.crypto_sign_verify_detached(sig, preimage, author)) return "ERROR: bad manifest signature";
  if (policy && !policy.authors.has(hex(author))) return "ERROR: manifest author not in policy"; // §13.4 bundle governance
  let s = "";
  for (let i = 0; i < json.length; i++) s += String.fromCharCode(json[i]); // manifest is ASCII
  const m = JSON.parse(s);

  const sha = (buf) => hex(sodium.crypto_hash_sha3256(new Uint8Array(buf)));
  for (const mod of m.modules) {
    if (sha(files[mod.file]) !== mod.hash.toLowerCase()) return "ERROR: hash mismatch " + mod.name;
  }
  if (sha(files[m.guest.file]) !== m.guest.hash.toLowerCase()) return "ERROR: guest hash mismatch";

  // Freshness key material (§13.4): version is an enforced monotonic integer.
  if (!Number.isInteger(m.version)) return "ERROR: manifest version must be an integer";

  return JSON.stringify({
    app: m.app, version: m.version, author: hex(author), caps: m.caps || [],
    guest: m.guest.file, config: m.config || {},
    modules: m.modules.map((x) => ({ name: x.name, install: x.install, kernelName: x.kernelName })),
  });
};
