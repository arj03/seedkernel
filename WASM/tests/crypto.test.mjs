// crypto.test.mjs — the manifest-suite envelope and the ACVP known-answer vector suites
// (§12.4, §14.1): the signed suite byte, ML-DSA-65 and ML-KEM-768 against NIST's published
// vectors, and the hybrid (Ed25519 + ML-DSA-65) manifest suite. Split out of the former
// single-file run.mjs; bundle-install.test.mjs and realm-guest.test.mjs cover the rest.
//
// Every test here is either pure envelope/vector arithmetic or deliberately probes a
// tampered/unsupported envelope byte — there is no valid-path bundle fixture to convert to
// `authorBundle`, except the hybrid suite's §6 end-to-end case (see below).

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { testkit } from "./testkit.mjs";
import {
  sodium, root, toHex, concatBytes, hybridAuthorId, verifyManifest, verifyBundle,
  signManifest, packBundle, authorBundle, testAuthor, appKey, testHost, installBundle,
  moduleFile, MANIFEST_FILE, GUEST_FILE, GUEST_TEXT, GUEST_BYTES, forwarderBytes,
  JsModuleLoader, loadMlDsa65, ML_DSA65_PK_LEN, ML_DSA65_SIG_LEN,
} from "./fixtures.mjs";

const { ok, assertEqual, summary } = testkit({ verbose: false });
const assert = ok;

// ─── Test: manifest suite byte — signed, so it cannot be edited in flight ────────
//
// The suite byte leads the §12.4 envelope and is part of the signed preimage
// `DOMAIN_manifest ‖ suite ‖ edPk ‖ mlDsaPk ‖ json`. That is what makes it safe to read
// the byte *before* verifying: a verifier needs it to know the field widths, and the
// signature it then checks commits to the same byte, so rewriting it only breaks the
// manifest. Algorithm confusion with a later suite is unrepresentable (§14.1).
//
// There is ONE live suite (§12.4), `0x02`. The retired Ed25519-only `0x01` is refused as
// a suite this host does not implement, which is what keeps the retirement from being a
// downgrade path an attacker can ask for.
async function testManifestSuiteByte() {
  console.log("Test: manifest suite byte — signed preimage, so an edited suite cannot verify");
  const author = testAuthor();
  // One module: this test is about the suite byte, not the module count.
  const manifest = { app: "suite-probe", version: 1, modules: [{ name: "fwd", hash: "aa" }], guest: { hash: "aa", requires: [] } };
  const env = signManifest(sodium, author, manifest);

  // Layout: the suite byte leads, and the author's Ed25519 key follows it (not at
  // offset 0). The rest of the envelope is testHybridManifestSuite's subject.
  assertEqual(env[0], 0x02, "the envelope opens with the one manifest suite id");
  assertEqual(toHex(env.slice(1, 33)), toHex(author.ed.publicKey), "the Ed25519 key follows the suite byte");

  // 1. Untouched, it verifies and returns the author id + manifest.
  {
    const v = verifyManifest(sodium, env);
    assert(v !== null, "an untouched manifest verifies");
    assertEqual(toHex(v.author), toHex(author.id), "the derived author id round-trips");
    assertEqual(v.manifest.app, "suite-probe", "the manifest round-trips");
  }

  // 2. A suite this host does not implement is refused with its own message, not as a bad
  //    signature — which would misdirect an operator whose real problem is a bundle built
  //    for a host they are not running. `0x01` goes by the same rule as `0x7f`; there is
  //    no retired-suite special case.
  for (const suite of [0x01, 0x7f]) {
    const bad = env.slice(); bad[0] = suite;
    let msg = "";
    try { verifyManifest(sodium, bad); } catch (e) { msg = String(e.message); }
    assert(msg.includes("unsupported manifest suite"),
      `suite 0x${suite.toString(16)} reports itself (got: ${msg || "no throw"})`);
    assert(!msg.includes("signature"), "an unimplemented suite is not reported as a signature failure");
  }

  // 3. A whole, validly-signed 0x01 envelope — the shape a bundle built against the
  //    retired suite actually has — is refused the same way. The retirement is a property
  //    of the verifier, not of the fact that nobody happens to hold such a bundle.
  {
    const json = new TextEncoder().encode(JSON.stringify(manifest));
    const pre = concatBytes([new TextEncoder().encode("seedkernel-manifest-sig-v1\0"), Uint8Array.of(0x01), json]);
    const sig = sodium.crypto_sign_detached(pre, author.ed.privateKey);
    const legacyEnv = concatBytes([Uint8Array.of(0x01), author.ed.publicKey, sig, json]);
    let msg = "";
    try { verifyManifest(sodium, legacyEnv); } catch (e) { msg = String(e.message); }
    assert(msg.includes("unsupported manifest suite 0x01"),
      `a well-formed genesis-suite envelope is refused by suite (got: ${msg || "no throw"})`);
  }

  // 4. The load-bearing property: the suite byte is inside the signed preimage, so
  //    tampering anywhere in the envelope breaks the signature rather than the parse.
  {
    const forged = env.slice();
    forged[33] ^= 0x01; // flip a byte of the ML-DSA public key → must not verify
    assert(verifyManifest(sodium, forged) === null, "a tampered envelope does not verify");
  }

  console.log("  OK\n");
}

// ─── Test: ML-DSA-65 against NIST's own vectors (ACVP known-answer test) ─────────
//
// A round trip — sign, verify, flip a bit, verify again — is satisfied by an
// implementation that is wrong but self-consistent, and says nothing about whether two
// targets will agree. These are NIST's published ACVP vectors for ML-DSA-65 (external
// interface, pure, FIPS 204): fixed keys, messages and signatures with a verdict
// attached, plus sigGen cases where the signature must match byte for byte.
//
// That makes "one implementation across three targets" checkable rather than asserted:
// the same bytes the browser fetches, Node reads and the Go loader embeds, so a drifting
// build fails here instead of splitting the network into nodes that admit a bundle and
// nodes that refuse it.
async function testMlDsaAcvpVectors() {
  console.log("Test: ML-DSA-65 ACVP known-answer vectors (FIPS 204, external/pure)");
  const kat = JSON.parse(readFileSync(join(root, "tests/fixtures/mldsa65-acvp.json"), "utf8"));
  const hex = (h) => Uint8Array.from(Buffer.from(h, "hex"));
  const mldsa = await loadMlDsa65(readFileSync(join(root, "browser/mldsa65.wasm")));

  // The vectors carry FIPS 204 context strings; the runtime always signs with an
  // empty one (§12.4), so the raw module is exercised through the same low-level
  // entry the adapter wraps.
  const inst = (await WebAssembly.instantiate(readFileSync(join(root, "browser/mldsa65.wasm")), {})).instance;
  const e = inst.exports;
  const base = e.__heap_base.value;
  let top = base;
  const alloc = (n) => {
    const p = (top + 15) & ~15;
    top = p + n;
    const short = top - e.memory.buffer.byteLength;
    if (short > 0) e.memory.grow(Math.ceil(short / 65536) + 1);
    return p;
  };
  const put = (b) => { const p = alloc(b.length); new Uint8Array(e.memory.buffer).set(b, p); return p; };

  let checked = 0;
  for (const t of kat.sigVer) {
    top = base;
    const sig = put(hex(t.sig)), msg = hex(t.msg), m = put(msg);
    const ctx = hex(t.ctx), c = put(ctx), pk = put(hex(t.pk));
    const got = e.mldsa65_verify(sig, m, msg.length, c, ctx.length, pk) === 1;
    assertEqual(got, t.pass, `ACVP sigVer tc${t.tcId} (${t.reason})`);
    checked++;
  }
  for (const t of kat.sigGen) {
    top = base;
    const sk = put(hex(t.sk)), msg = hex(t.msg), m = put(msg);
    const ctx = hex(t.ctx), c = put(ctx), rnd = put(hex(t.rnd)), sig = alloc(ML_DSA65_SIG_LEN);
    assertEqual(e.mldsa65_sign(sig, m, msg.length, c, ctx.length, rnd, sk), 1, `ACVP sigGen tc${t.tcId} signs`);
    const out = new Uint8Array(e.memory.buffer).slice(sig, sig + ML_DSA65_SIG_LEN);
    assertEqual(toHex(out), t.sig, `ACVP sigGen tc${t.tcId} signature is byte-exact`);
    checked++;
  }

  // The adapter's own path (empty context, the runtime's only mode) must agree with the
  // raw module: a wrapper passing a stray context byte would still pass every vector
  // above.
  {
    const seed = new Uint8Array(32).fill(9);
    const kp = mldsa.ml_dsa65_keypair_from_seed(seed);
    assertEqual(kp.publicKey.length, ML_DSA65_PK_LEN, "keygen returns a full-width public key");
    const msg = new TextEncoder().encode("adapter path");
    const sig = mldsa.ml_dsa65_sign_detached(msg, kp.privateKey);
    assert(mldsa.ml_dsa65_verify_detached(sig, msg, kp.publicKey), "adapter verifies its own signature");
    top = base;
    const sp = put(sig), mp = put(msg), pp = put(kp.publicKey);
    assertEqual(e.mldsa65_verify(sp, mp, msg.length, 0, 0, pp), 1,
      "the raw module verifies what the adapter signed, with an empty context");
    sig[0] ^= 1;
    assert(!mldsa.ml_dsa65_verify_detached(sig, msg, kp.publicKey), "a flipped bit fails");
    assert(!mldsa.ml_dsa65_verify_detached(sig.slice(0, 10), msg, kp.publicKey),
      "a wrong-width signature is false, not a throw");
  }

  console.log(`  OK (${checked} NIST vectors)\n`);
}

// ─── Test: hybrid manifest suite 0x02 — Ed25519 + ML-DSA-65, both required ───────
//
// The §14.1 migration that cannot be delivered through its own mechanism: a PQ verifier
// shipped as a bundle would be admitted by the classical verifier, so the suite goes into
// the artifact ahead of need. What is pinned below is the *shape* — both signatures
// required, the author id bound to both keys, and a host without the PQ half refusing
// rather than falling back.
// ─── Test: ML-KEM-768 against NIST's own vectors (ACVP known-answer test) ────────
//
// testMlDsaAcvpVectors' argument, applied to the transport's own module: NIST's published ACVP
// vectors for ML-KEM-768 (FIPS 203): fixed coins with the key, ciphertext and shared
// secret that must come out of them byte for byte.
//
// Three of the five groups pin behaviour a round trip cannot reach at all: `decaps` over
// MODIFIED ciphertexts, where implicit rejection must produce NIST's specific unrelated
// secret rather than an error, and the two key checks (§7.2's modulus, §7.3's hash).
async function testMlKemAcvpVectors() {
  console.log("Test: ML-KEM-768 ACVP known-answer vectors (FIPS 203)");
  const kat = JSON.parse(readFileSync(join(root, "tests/fixtures/mlkem768-acvp.json"), "utf8"));
  const hex = (h) => Uint8Array.from(Buffer.from(h, "hex"));
  const kem = await new JsModuleLoader().build([{
    name: "mlkem",
    wasm: readFileSync(join(root, "browser/mlkem768.wasm")),
  }]);
  const call = async (...parts) => {
    const r = await kem.call("mlkem", concatBytes(parts));
    return r.bytes ?? new Uint8Array(0);
  };

  let checked = 0;
  for (const t of kat.keyGen) {
    const kp = await call(Uint8Array.of(0), hex(t.d + t.z));
    assertEqual(toHex(kp.slice(0, 1184)), t.ek, `ACVP keyGen tc${t.tcId} encapsulation key is byte-exact`);
    assertEqual(toHex(kp.slice(1184)), t.dk, `ACVP keyGen tc${t.tcId} decapsulation key is byte-exact`);
    checked++;
  }
  for (const t of kat.encaps) {
    const r = await call(Uint8Array.of(1), hex(t.ek), hex(t.m));
    assertEqual(r[0], 1, `ACVP encaps tc${t.tcId} accepts the vector's key`);
    assertEqual(toHex(r.slice(1, 1 + 1088)), t.c, `ACVP encaps tc${t.tcId} ciphertext is byte-exact`);
    assertEqual(toHex(r.slice(1 + 1088)), t.k, `ACVP encaps tc${t.tcId} shared secret is byte-exact`);
    checked++;
  }
  for (const t of kat.decaps) {
    const r = await call(Uint8Array.of(2), hex(t.dk), hex(t.c));
    assertEqual(r[0], 1, `ACVP decaps tc${t.tcId} accepts the vector's key`);
    // Both "valid decapsulation" and "modified ciphertext" cases run through here and
    // both must match: the modified ones are implicit rejection, which has one right
    // answer, not an error.
    assertEqual(toHex(r.slice(1)), t.k, `ACVP decaps tc${t.tcId} shared secret is byte-exact (${t.reason})`);
    checked++;
  }
  for (const t of kat.encapsKeyCheck) {
    const r = await call(Uint8Array.of(1), hex(t.ek), new Uint8Array(32));
    assertEqual(r[0] === 1, t.pass, `ACVP encapsulationKeyCheck tc${t.tcId} (${t.reason})`);
    checked++;
  }
  for (const t of kat.decapsKeyCheck) {
    const r = await call(Uint8Array.of(2), hex(t.dk), new Uint8Array(1088));
    assertEqual(r[0] === 1, t.pass, `ACVP decapsulationKeyCheck tc${t.tcId} (${t.reason})`);
    checked++;
  }

  assertEqual((await call(Uint8Array.of(1), new Uint8Array(10), new Uint8Array(32))).length, 0,
    "a wrong-width encapsulation request is an empty module answer");
  assertEqual((await call(Uint8Array.of(2), new Uint8Array(10), new Uint8Array(1088))).length, 0,
    "a wrong-width decapsulation request is an empty module answer");

  kem.dispose();
  console.log(`  OK (${checked} NIST vectors)\n`);
}

async function testHybridManifestSuite() {
  console.log("Test: hybrid manifest suite 0x02 — both signatures required, id binds both keys");

  const keys = testAuthor();
  const ed = keys.ed, pq = keys.mlDsa;
  // One module: this test is about the envelope, not the module count.
  const manifest = { app: "pq-probe", version: 1, modules: [{ name: "fwd", hash: "aa" }], guest: { hash: "aa", requires: [] } };
  const env = signManifest(sodium, keys, manifest);

  // 1. Layout: `[0x02][edPk 32][mlDsaPk 1952][edSig 64][mlDsaSig 3309][json]`. Both keys
  //    lead, so a verifier reads the whole key set before either signature.
  const OFF_ML_PK = 33, OFF_ED_SIG = OFF_ML_PK + ML_DSA65_PK_LEN;
  const OFF_ML_SIG = OFF_ED_SIG + 64, OFF_JSON = OFF_ML_SIG + ML_DSA65_SIG_LEN;
  assertEqual(env[0], 0x02, "the envelope opens with the hybrid manifest suite id");
  assertEqual(toHex(env.slice(1, 33)), toHex(ed.publicKey), "the Ed25519 key follows the suite byte");
  assertEqual(toHex(env.slice(OFF_ML_PK, OFF_ED_SIG)), toHex(pq.publicKey), "the ML-DSA key follows it");
  assertEqual(new TextDecoder().decode(env.slice(OFF_JSON)), JSON.stringify(manifest),
    "the manifest JSON is carried verbatim after both signatures");

  // 2. Untouched, it verifies — and the author id is the hash over BOTH keys, never
  //    either one (§12.4). That is what hybrid signing rests on: an attacker who breaks
  //    one algorithm cannot reach this identity while choosing the other half's key.
  {
    const v = verifyManifest(sodium, env);
    assert(v !== null, "an untouched hybrid manifest verifies");
    assertEqual(toHex(v.author), toHex(hybridAuthorId(sodium, ed.publicKey, pq.publicKey)),
      "the author id is the derived key-set hash");
    assert(toHex(v.author) !== toHex(ed.publicKey), "the author id is not the Ed25519 key");
    assertEqual(toHex(v.authorKeys.ed), toHex(ed.publicKey), "both signing keys are reported");
    assertEqual(toHex(v.authorKeys.mlDsa), toHex(pq.publicKey), "including the PQ one");
    assertEqual(v.manifest.app, "pq-probe", "the manifest round-trips");
  }

  // 3. Both halves are load-bearing: tampering with either signature fails the whole
  //    manifest. "Either verifies" would be exactly as strong as the weaker algorithm.
  {
    const badEd = env.slice(); badEd[OFF_ED_SIG] ^= 0x01;
    assert(verifyManifest(sodium, badEd) === null, "a broken Ed25519 half fails the manifest");
    const badMl = env.slice(); badMl[OFF_ML_SIG] ^= 0x01;
    assert(verifyManifest(sodium, badMl) === null, "a broken ML-DSA half fails the manifest");
  }

  // 4. The splice a hybrid format has to survive: swap in a different Ed25519 key with a
  //    validly-made signature of its own, keeping the original PQ key and signature.
  //    Both preimages commit to BOTH keys, so the surviving half no longer verifies —
  //    the pair cannot be taken apart and half-replaced.
  {
    const { generateKeyPair } = await import("./fixtures.mjs");
    const attacker = generateKeyPair();
    const json = new TextEncoder().encode(JSON.stringify(manifest));
    const pre = concatBytes([
      new TextEncoder().encode("seedkernel-manifest-sig-v1\0"), Uint8Array.of(0x02),
      attacker.publicKey, pq.publicKey, json,
    ]);
    const spliced = concatBytes([
      Uint8Array.of(0x02), attacker.publicKey, pq.publicKey,
      sodium.crypto_sign_detached(pre, attacker.privateKey),
      env.slice(OFF_ML_SIG, OFF_JSON), json,
    ]);
    assert(verifyManifest(sodium, spliced) === null,
      "an Ed25519 key swap invalidates the untouched ML-DSA half");
  }

  // 5. A host with no ML-DSA verifier REFUSES rather than falling back to the Ed25519
  //    signature alone — the downgrade the suite exists to prevent. Its own message, like
  //    an unknown suite's: a legibility failure, not a verdict on the bundle.
  {
    const classicalOnly = {
      crypto_sign_verify_detached: (...a) => sodium.crypto_sign_verify_detached(...a),
      crypto_generichash: (...a) => sodium.crypto_generichash(...a),
    };
    let msg = "";
    try { verifyManifest(classicalOnly, env); } catch (e) { msg = String(e.message); }
    assert(msg.includes("unsupported manifest suite 0x02"),
      `a host without ML-DSA refuses 0x02 (got: ${msg || "no throw"})`);
    assert(!msg.includes("signature invalid"), "and does not report it as a bad signature");
  }

  // 6. End to end: a signed bundle loads and its modules bind under the DERIVED id — the
  //    key-set hash, never either key — so names, policy and freshness are all keyed by
  //    the one identity the format produces.
  {
    const { blob } = authorBundle(sodium, keys, {
      app: "pq-app", version: 1,
      modules: [{ name: "codec", wasm: forwarderBytes }],
      guestSource: GUEST_TEXT, guestRequires: [],
    });
    const v = verifyBundle(sodium, blob);
    assertEqual(toHex(v.authorKeys.mlDsa), toHex(pq.publicKey),
      "verifyBundle carries the signing key set through to the policy seam");
    const host = testHost(new JsModuleLoader());
    await installBundle(host, v);
    const derived = appKey(hybridAuthorId(sodium, ed.publicKey, pq.publicKey), "pq-app");
    assert(host.isBound(derived, "codec"), "the module binds under the derived author id");
    assert(!host.isBound(appKey(ed.publicKey, "pq-app"), "codec"),
      "…and never under the Ed25519 key alone");
  }

  console.log("  OK\n");
}

// ─── Run ────────────────────────────────────────────────────────────────

await testManifestSuiteByte();
await testMlDsaAcvpVectors();
await testMlKemAcvpVectors();
await testHybridManifestSuite();

summary("Results");
