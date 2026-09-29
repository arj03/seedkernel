// The guest seam and realm lifecycle (§12.2, §12.3, §4.3): policy parsing, node/sign
// scoping, safe-js confinement, realm serialization, seam gating, and module-call
// budgeting. bundle-install.test.mjs covers the verify, admit and install lifecycle;
// crypto.test.mjs the manifest suite and ACVP vectors.
//
// Valid bundle fixtures go through `authorBundle` (scripts/bundle-author.ts), not
// `signTestBundle`; bundle-install.test.mjs's header explains the exceptions.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { testkit } from "./testkit.mjs";
import {
  sodium, generateKeyPair, JsModuleLoader, root,
  toHex, concatBytes, verifyTestBundle,
  signTestBundle, authorBundle, GUEST_TEXT, GUEST_BYTES, GUEST,
  testAuthor, bootTestShell, imp, MemoryFs,
  createGuestSeam, withTestBudget, guestSignScope, appSignScope, ALL_HOST_SERVICES, TEST_CALL_LOCAL, testBackends,
  createSafeRealm, callerOf, readOp, writeOp, forwarderBytes, installMod, makeHost, EMPTY,
} from "./fixtures.mjs";
import { bytesEqual } from "./bytes.mjs";

const { ok, assertEqual, summary, sleep } = testkit({ verbose: false });
const assert = ok;

// ─── Test: guest-side fan-out over the cross-realm call (Promise.all) ────────────
// Fan-out is not a host op: with real promises at the seam, a confined guest sends one
// request per peer itself with Promise.all over `_net`. Tested here through the seam's
// single-peer cross-realm call, concurrently, so the round trips overlap in one realm.

async function testGuestSeam() {
  console.log("Test: guest seam — host transforms, authorities and private modules (step 7)");

  const id = generateKeyPair();
  const otherKey = generateKeyPair();
  const fs = new MemoryFs();
  // Local service id routing: the shell's job in production, a stub here, so the seam is
  // tested for what it does: check the name, then pass the payload to whatever claims the
  // id. `_net` and `chat/v1` are claimed; `_nobody` is not.
  const claimed = new Set(["_net", "chat/v1"]);
  const callLocal = (idName) => (claimed.has(idName) ? Promise.resolve(U(9, 9)) : null);
  // This realm's declared requires (§12.10): every host service plus the local service ids
  // it calls, which is what tells them apart from a bare module name at dispatch.
  // `chat/v1` is here because a local service id is an ordinary claim and may contain a
  // `/` like a wire protocol id.
  const names = [...ALL_HOST_SERVICES, "_net", "_nobody", "chat/v1"];

  // A module reachable by name.
  const { host } = await makeHost();
  const testKey = "testapp";
  await installMod(host, testKey, "echo", forwarderBytes);

  // A host-derived signing scope binds the guest's node/sign name to a bundle namespace
  // (§12.2); a real node derives it from the manifest's `app` label.
  const signScope = appSignScope(id, "testapp");
  const scopeBytes = guestSignScope("testapp");
  const seam = withTestBudget(createGuestSeam({
    sodium,
    requires: names,
    backends: { ...testBackends(), node: signScope, fs },
    callLocal,
    // Scoped to one app, as the shell does: a bare name is a module in this app's map
    // and cannot reach outside it.
    modules: {
      names: new Set(["echo"]),
      call: (name, p) => host.slots.get(testKey)?.call(name, p) ?? Promise.resolve({ bytes: null, ms: 0 }),
    },
  }));
  const U = (...xs) => new Uint8Array(xs);

  try {
    // Primitives are reached by name under `crypto/`: there is no op number per
    // algorithm, and the seam knows nothing about cipher suites.
    const prim = (name, argBytes) => seam(`crypto/${name}`, argBytes);
    const msg = U(1, 2, 3, 4, 5);
    // crypto/blake2b takes RFC 7693's whole interface ([outLen][keyLen][key][msg]) and the
    // AEAD names take associated data (RFC 8439), so a standard protocol can be built on
    // them without a host release (tests/noise-vectors.js runs one).
    assert(bytesEqual(await prim("blake2b", concatBytes([U(32, 0), msg])), sodium.crypto_generichash(32, msg, null)), "crypto/blake2b, by name");
    const hex = (b) => Buffer.from(b).toString("hex");
    assertEqual(hex(await prim("blake2b", concatBytes([U(64, 0), new TextEncoder().encode("abc")]))),
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
      "crypto/blake2b: RFC 7693 Appendix A, 64-byte output");
    assertEqual(hex(await prim("blake2b", concatBytes([U(64, 64), Uint8Array.from({ length: 64 }, (_, i) => i)]))),
      "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568",
      "crypto/blake2b: BLAKE2's keyed KAT, first entry");
    for (const bad of [U(), U(0, 0), U(65, 0), U(32, 65), U(32, 8, 1, 2)]) {
      let refused = false;
      try { await prim("blake2b", bad); } catch { refused = true; }
      assert(refused, `crypto/blake2b refuses the mis-framed call [${[...bad]}]`);
    }
    const npub = new Uint8Array(12).fill(7), aeadKey = new Uint8Array(32).fill(9), ad = U(1, 2, 3);
    const aead = (adBytes, body) => {
      const len = new Uint8Array(4); new DataView(len.buffer).setUint32(0, adBytes.length);
      return concatBytes([npub, aeadKey, len, adBytes, body]);
    };
    const sealed = await prim("chacha20poly1305-ietf/seal", aead(ad, msg));
    assert(bytesEqual(sealed, sodium.crypto_aead_chacha20poly1305_ietf_encrypt(msg, ad, null, npub, aeadKey)),
      "chacha20poly1305-ietf/seal binds its associated data exactly as libsodium does");
    assert(bytesEqual((await prim("chacha20poly1305-ietf/open", aead(ad, sealed))).subarray(1), msg), "…and open takes it back");
    assertEqual((await prim("chacha20poly1305-ietf/open", aead(U(1, 2, 4), sealed)))[0], 0,
      "a different associated data does not open");
    let shortAead = false;
    try { await prim("chacha20poly1305-ietf/open", concatBytes([npub, aeadKey, U(0, 0, 0, 9), msg])); } catch { shortAead = true; }
    assert(shortAead, "associated data longer than the call is mis-framed, not a failed open");
    // node/sign is scoped, never raw (§12.2): it signs DOMAIN_guest ‖ scope ‖ msg.
    // node/verify applies the same scope on the host, so a guest checks a signature by
    // naming the key, never by rebuilding the host's prefix.
    const DOMAIN_GUEST = new TextEncoder().encode("seedkernel-guest-sig-v1\0");
    const sig = await seam("node/sign", msg);
    const preimage = concatBytes([DOMAIN_GUEST, scopeBytes, msg]);
    assert(sodium.crypto_sign_verify_detached(sig, preimage, id.publicKey), "node/sign signs DOMAIN_guest ‖ scope ‖ msg under the node identity");
    assert(!sodium.crypto_sign_verify_detached(sig, msg, id.publicKey), "node/sign never signs the raw message (scoped, not raw)");
    assertEqual((await seam("node/verify", concatBytes([id.publicKey, sig, msg])))[0], 1, "node/verify accepts what node/sign signed — the same scope, host-applied");
    assertEqual((await seam("node/verify", concatBytes([otherKey.publicKey, sig, msg])))[0], 0, "node/verify rejects the signature under a different key");
    assertEqual((await seam("node/verify", concatBytes([id.publicKey, sig, U(9, 9)])))[0], 0, "node/verify rejects a forged message");
    // A mis-framed call is not a failed verification: too few bytes for [pk][sig] throws,
    // since 0 would be a verdict on bytes nothing checked. The bound is exactly the fixed
    // prefix; an empty message is valid.
    const emptySig = await seam("node/sign", new Uint8Array(0));
    assertEqual((await seam("node/verify", concatBytes([id.publicKey, emptySig])))[0], 1, "node/verify takes an empty message — 96 bytes is a whole call");
    let verifyThrew = false;
    try { await seam("node/verify", concatBytes([id.publicKey, sig.slice(0, 63)])); } catch { verifyThrew = true; }
    assert(verifyThrew, "node/verify refuses a short payload rather than answering 0 (mis-framed ≠ invalid)");
    let rawVerifyRefused = false;
    try { await prim("ed25519/verify", new Uint8Array(0)); } catch { rawVerifyRefused = true; }
    assert(rawVerifyRefused, "crypto/ed25519/verify is host-internal — guests use scoped node/verify");
    for (const removed of ["xchacha20/xor", "ml-kem-768/keypair", "ml-kem-768/encaps", "ml-kem-768/decaps"]) {
      let refused = false;
      try { await prim(removed, new Uint8Array(0)); } catch { refused = true; }
      assert(refused, `crypto/${removed} is not host vocabulary — pure transforms ship in their consumer's bundle`);
    }
    assertEqual((await prim("random", U(0, 0, 0, 16))).length, 16, "crypto/random returns n bytes");
    for (const removed of ["clock/now", "node/random"]) {
      let refused = false;
      try { await seam(removed, U(0, 0, 0, 4)); } catch { refused = true; }
      assert(refused, `${removed} is not host vocabulary — time is an intrinsic, entropy is crypto/random`);
    }

    // fs.* over the raw backend
    const fk = new TextEncoder().encode("dead.blk"), fv = U(7, 7, 7);
    await seam("fs/put", concatBytes([U(0, 0, 0, fk.length), fk, fv]));
    const got = await seam("fs/get", fk);
    assert(got[0] === 1 && bytesEqual(got.slice(1), fv), "fs/put + fs/get round-trips under an opaque key");
    assertEqual((await seam("fs/get", new TextEncoder().encode("missing")))[0], 0, "fs/get of an absent key → [0]");
    const szPresent = await seam("fs/size", fk);
    assertEqual(new DataView(szPresent.buffer, szPresent.byteOffset).getUint32(0, false), fv.length, "fs/size returns the value's byte length");
    const szAbsent = await seam("fs/size", new TextEncoder().encode("missing"));
    assertEqual(new DataView(szAbsent.buffer, szAbsent.byteOffset).getUint32(0, false), 0xffffffff, "fs/size of an absent key → -1 (0xFFFFFFFF)");

    // Every name, crypto included, answers a Promise the guest awaits, so a forgotten
    // `await` reads a Promise instead of bytes for every name alike.
    assert(prim("blake2b", concatBytes([U(32, 0), msg])) instanceof Promise, "a catalog primitive answers a Promise like every name");
    assert(seam("fs/size", fk) instanceof Promise, "fs/size returns a Promise");
    assert(prim("random", U(0, 0, 0, 1)) instanceof Promise, "crypto/random returns a Promise");

    // The cross-realm call: a declared local service is another realm, reached on a later
    // turn, so it is a Promise like fs. There is no `net` host service; the network is a
    // bundle that claims the service `_net`, and this seam's routing reaches it (§12.10).
    const crossed = seam("_net", U(1, 2, 3));
    assert(crossed instanceof Promise, "a local service id returns a Promise (the callee runs on a later turn)");
    assertEqual([...await crossed], [9, 9], "…and resolves with what the callee's handle returned");
    let unclaimed = false;
    try { await seam("_nobody", U()); } catch { unclaimed = true; }
    assert(unclaimed, "a local service id no realm claims is refused by name, not left pending");
    // A name is what the manifest declared, not what its spelling suggests: an id with a
    // `/` (valid for any claim, §12.10) routes to its claimant, not to the host table
    // where it would fail as an unknown host name.
    assertEqual([...await seam("chat/v1", U(1))], [9, 9],
      "a declared local service id carrying a `/` still routes to the claiming realm");

    // A bare name reaches this app's module by its manifest name, through the same
    // `host.call` as every other name (§12.2). The seam decides whose modules, never the
    // caller.
    assertEqual([...await seam("echo", U(8, 9))], [8, 9], "a bare name invokes this app's module");
    let noSuch = false;
    try { await seam("nosuchmodule", U(1)); } catch { noSuch = true; }
    assert(noSuch, "a bare name this app never installed is refused, like any unknown name");
  } finally { /* nothing host-side to tear down: the seam holds no transport */ }

  console.log("  OK\n");
}

// ──── Test: the author allowlist policy (§12.5) ────

async function testPolicy() {
  console.log("Test: shell install policy — closed author sets gate bundle loads");
  const { parsePolicy } = await imp("build/host/policy.js");

  const good = testAuthor();
  const bad = testAuthor();

  // Build a signed bundle from each author; loadBundle accepts/rejects by predicate.
  const { ModuleTable } = await imp("build/host/module-table.js");
  const { testHost, loadBundle } = await import("./fixtures.mjs");
  const tryLoad = async (policyJson, author, links) => {
    const host = testHost(new ModuleTable());
    const { blob } = authorBundle(sodium, author, {
      app: "mod", version: 1,
      modules: [{ name: "fwd", wasm: forwarderBytes }],
      guestSource: GUEST_TEXT, guestRequires: links ? ["link"] : [],
    });
    const admit = parsePolicy(policyJson);
    let landed = false;
    try { await loadBundle(host, blob, admit); landed = true; } catch { /* author not in policy */ }
    return landed;
  };

  // ── author allowlist ───────────────────────────────────────────────────
  const okAuthor = await tryLoad(JSON.stringify({ authors: [toHex(good.id)] }), good);
  assert(okAuthor, "install by an allowed author is accepted");

  const badAuthor = await tryLoad(JSON.stringify({ authors: [toHex(good.id)] }), bad);
  assert(!badAuthor, "install by an author not on the allowlist is rejected");

  const goodHex = toHex(good.id);
  const empty = parsePolicy(JSON.stringify({ authors: [] }));
  assert(!(await empty({ author: good.id })), "an empty author set denies every app");
  for (const value of ["{ not json", "{}", "[]", "null",
    JSON.stringify({ authors: ["zz".repeat(32)] }),
    JSON.stringify({ authors: [123] }),
    JSON.stringify({ authorss: [goodHex] }),
    JSON.stringify({ authors: [goodHex], grants: { link: [goodHex] } })]) {
    let threw = false;
    try { parsePolicy(value); } catch { threw = true; }
    assert(threw, `invalid policy is refused: ${value}`);
  }

  console.log("  OK\n");
}

// ─── Test: node/sign's scope is the slot's: the app scope for an app slot, the ──────
// ─── link scope for the link slot, on every install path ─────────────────────────────
// `slotSignScope` depends only on admitted facts (the node's identity, the manifest, and
// whether it requires link), so it cannot drift. Tested through a real shell because the
// property is about where a signed manifest becomes a realm, and because in-place update
// is the path that could lose it: a transport that changed scope on upgrade would keep
// running while every handshake with a non-upgraded peer failed as an unexplained
// authentication error.
async function testSigningScopeFollowsSlot() {
  console.log("Test: node/sign is the slot's scope — app scope for an app, link scope for the link slot, on every load path");
  const { admitAll } = await imp("build/host/policy.js");
  const { slotSignScope } = await imp("build/host/guest-seam.js");

  const linkAuthor = testAuthor(), appAuthor = testAuthor();
  const identity = generateKeyPair();
  const linkScope = new Uint8Array(0);
  let seam;
  // `linkAuthor` signs the boot transport, so the link probe below installs by replacing
  // it; the app author's bundle never requires `link`.
  const shell = await bootTestShell({
    identity,
    createRealm: async ({ hostCall }) => {
      seam = withTestBudget(hostCall);
      return { call: async () => new Uint8Array(), dispose() {} };
    },
    transportAuthor: linkAuthor,
    admit: admitAll,
  });
  const blob = (author, app, version, requires) => authorBundle(sodium, author, {
    app, version, modules: [], guestSource: GUEST_TEXT, guestRequires: requires,
  }).blob;
  const DOMAIN_GUEST = new TextEncoder().encode("seedkernel-guest-sig-v1\0");
  const DOMAIN_LINK = new TextEncoder().encode("seedkernel-link-scope-v1\0");
  const preimage = (domain, scope, msg) => concatBytes([domain, scope, msg]);
  const signs = (sig, domain, scope, msg) =>
    sodium.crypto_sign_verify_detached(sig, preimage(domain, scope, msg), identity.publicKey);
  const msg = new Uint8Array([5, 4, 3]);
  const linkApp = guestSignScope("linkprobe");
  try {
    // The link slot's scope is the link scope: channel authentication comes from the slot,
    // not from a second sign name.
    await shell.install(blob(linkAuthor, "linkprobe", 1, ["node", "link"]), {
      replaces: shell.resolve("_fixture-transport"),
      localConfig: { networkKey: "7a".repeat(32) },
    });
    const v1 = await seam("node/sign", msg);
    assert(signs(v1, DOMAIN_LINK, linkScope, msg),
      "the link slot's node/sign signs under DOMAIN_link_scope");
    assert(!signs(v1, DOMAIN_GUEST, linkApp, msg),
      "…and never under the transport author's app scope — the slot's scope is what the name means");
    assertEqual((await seam("node/verify", concatBytes([identity.publicKey, v1, msg])))[0], 1,
      "node/verify on the link slot checks under the same link scope");

    // In-place update: the installed slot is replaced.
    await shell.install(blob(linkAuthor, "linkprobe", 2, ["node", "link"]), {
      replaces: "linkprobe",
      localConfig: { networkKey: "7b".repeat(32) },
    });
    const v2 = await seam("node/sign", msg);
    assert(signs(v2, DOMAIN_LINK, linkScope, msg),
      "an in-place update of the link slot keeps the SAME link scope — an upgrade cannot re-scope a node");
    assert(bytesEqual(v1, v2), "changing transport config does not change the host's signing scope");

    // The other case, on a shell that already has a link occupant: an ordinary app signs
    // under its own scope, with the same sign names.
    await shell.install(blob(appAuthor, "plainapp", 1, ["node"]));
    const app = await seam("node/sign", msg);
    assert(signs(app, DOMAIN_GUEST, guestSignScope("plainapp"), msg),
      "an ordinary app's node/sign signs under DOMAIN_guest ‖ app");
    assert(!signs(app, DOMAIN_LINK, linkScope, msg),
      "…and cannot reach the link slot's link scope");
    let refused = false;
    try { await seam("link/sign", msg); } catch { refused = true; }
    assert(refused, "there is no link/sign name — the sign pair is one names pair per slot");

    // Both cases come from the one exported constructor, so a caller building a scope by
    // hand gets what the slot got.
    assert(bytesEqual(slotSignScope({ identity }, "linkprobe", true).scope, linkScope),
      "slotSignScope gives the link slot the link scope");
    assert(bytesEqual(slotSignScope({ identity }, "plainapp", false).scope,
      guestSignScope("plainapp")), "slotSignScope gives an app slot its label");
  } finally { shell.close(); }
  console.log("  OK\n");
}

// ─── Test: the manifest carries no seam version (§12.2, §12.4) ──────────

async function testGuestAbi() {
  console.log("Test: the seam needs no version word — it is async all the way down");

  const author = testAuthor();
  const mk = (guest) => signTestBundle(sodium, author,
    { app: "abi", version: 1, modules: [], guest });

  // A guest declares its required services and nothing else: with every name answering a
  // Promise, there is no calling convention to version.
  const verified = verifyTestBundle(sodium, mk({ requires: [] }));
  assert(verified !== null, "a manifest with no seam version verifies");
  assert(!("abi" in verified.manifest.guest), "the verified manifest carries no abi field");

  // Every bundle declares a guest (§12.4), and a manifest without one gets its own error.
  let noGuest = "";
  try { verifyTestBundle(sodium, signTestBundle(sodium, author,
    { app: "abi", version: 1, modules: [] })); } catch (e) { noGuest = e.message; }
  assert(noGuest.includes("every app is a guest"), `a manifest without a guest is refused by name (got: ${noGuest})`);

  // `requires` names host services (§12.2) and local service ids. A method name asks for
  // finer access than the seam enforces (it checks a `host.call` by the method's service),
  // so it is refused with the fix in the message.
  {
    let refused = "";
    try { verifyTestBundle(sodium, mk({ requires: ["fs/get"] })); }
    catch (e) { refused = e.message; }
    assert(refused.includes('declare the SERVICE "fs"'),
      `a manifest requiring the method "fs/get" is refused, naming the service to declare instead (got: ${refused})`);

    assert(verifyTestBundle(sodium, mk({ requires: ["fs", "_backup"] })) !== null,
      "a host service and a local service id sit in the one requires list");
    let crypto = "";
    try { verifyTestBundle(sodium, mk({ requires: ["crypto/blake2b"] })); }
    catch (e) { crypto = e.message; }
    assert(crypto.includes("host method"),
      `a local id in the ungated crypto/ namespace is refused, so it cannot shadow a host transform (got: ${crypto})`);
  }
  // The service, by exact name, is what a manifest requires; the guest still calls its
  // methods.
  assert(verifyTestBundle(sodium, mk({ requires: ["fs"] })) !== null,
    "a service, by exact name, is what a manifest may require");

  // A local id matching this bundle's own module name is refused: each `host.call` name
  // means one thing (guest-seam.ts). A local id spelled like a host method is refused for
  // the same reason.
  {
    const withModule = (requires) => signTestBundle(sodium, author, {
      app: "abi", version: 1,
      modules: [{ name: "codec" }],
      guest: { requires },
    });
    let refused = "";
    try { verifyTestBundle(sodium, withModule(["codec"])); } catch (e) { refused = e.message; }
    assert(refused.includes("codec") && refused.includes("module"),
      `a local service id colliding with this bundle's own module name is refused (got: ${refused})`);
    assert(verifyTestBundle(sodium, withModule([])) !== null,
      "…and the same module name is fine when nothing calls a service by it too");
    let shadow = "";
    try { verifyTestBundle(sodium, withModule(["fs/get"])); } catch (e) { shadow = e.message; }
    assert(shadow.includes('"fs" service') || shadow.includes('SERVICE "fs"'),
      `a local id spelled like a host method is refused (got: ${shadow})`);
  }

  // Any other bare or slashed name is a valid local service id (§12.10): whether anything
  // claims it is checked at call time, never at the manifest.
  assert(verifyTestBundle(sodium, mk({ requires: ["_backup", "reporting/v2"] })) !== null,
    "an arbitrary local service id verifies; nothing claiming it yet is not a manifest error");

  console.log("  OK\n");
}

// ─── Test: safe-js zero-authority JS confinement (§12.3) ─────────────────
// Zero-authority guest JS over a single host-call seam, with stand-in seams: nothing
// reachable by construction, the async seam and byte boundary, control flow, and realm
// isolation.

async function testSafeJs() {
  console.log("Test: safe-js — zero-authority JS confinement (§12.3)");

  // 1. Nothing reachable: the guest cannot name fs/net/Bun/process/fetch/require, and
  //    dynamic import() is unavailable (no module loader).
  {
    const DANGER = ["Bun", "process", "require", "fetch", "Buffer", "WebAssembly", "globalThis"];
    const probeSrc = `
      function handle() {
        const names = ${JSON.stringify(DANGER)};
        const out = new Uint8Array(names.length);
        for (let i = 0; i < names.length; i++) {
          try { out[i] = (typeof globalThis[names[i]] === "undefined") ? 0 : 1; }
          catch { out[i] = 2; }
        }
        return out;
      }
    `;
    const realm = await createSafeRealm({ source: probeSrc, hostCall: async () => new Uint8Array() });
    const res = await realm.call(new Uint8Array());
    for (let i = 0; i < DANGER.length - 1; i++) {
      assertEqual(res[i], 0, `${DANGER[i]} is unreachable in the realm`);
    }
    assert(res[DANGER.length - 1] === 1, "globalThis exists (the realm's own, no authority)");
    realm.dispose();
  }
  {
    const src = `
      async function handle() {
        try { await import("node:fs"); return new Uint8Array([1]); }
        catch { return new Uint8Array([0]); }
      }
    `;
    const realm = await createSafeRealm({ source: src, hostCall: async () => new Uint8Array() });
    const res = await realm.call(new Uint8Array());
    assertEqual(res[0], 0, "import('node:fs') rejects — no path out of the realm");
    realm.dispose();
  }

  // 2. The seam: a host handler may answer synchronously or with a Promise; the guest
  //    awaits either. Bytes round-trip across the copy boundary both ways.
  {
    let hostCalls = 0;
    const hostCall = (name, payload) => {
      hostCalls++;
      if (name === "inc") return payload.map((b) => (b + 1) & 0xff);                          // answers synchronously
      if (name === "slow") return sleep(3).then(() => payload.map((b) => (b + 1) & 0xff));     // answers later
      return new Uint8Array();
    };
    const src = `
      function handle(a) {
        const sel = a[0], arg = a.subarray(1);
        if (sel === 1) return host.call("inc", arg);                  // returned Promise, awaited by the preamble
        if (sel === 2) return (async () => await host.call("slow", arg))();  // awaited in the guest
        throw new Error("no such sel " + sel);
      }
    `;
    const realm = await createSafeRealm({ source: src, hostCall });
    const input = new Uint8Array([0, 1, 2, 254, 255]);
    const U = (...xs) => new Uint8Array(xs);
    const sync = await realm.call(U(1, ...input));
    assertEqual([...sync], [1, 2, 3, 255, 0], "sync name: bytes crossed in and back with no promise");
    const asyncR = await realm.call(U(2, ...input));
    assertEqual([...asyncR], [1, 2, 3, 255, 0], "net-like name: await host.call resolves the real Promise");
    assert(hostCalls === 2, "the host seam was invoked for each call");
    const again = await realm.call(U(1, 10));
    assertEqual([...again], [11], "realm is reusable across calls");
    realm.dispose();
  }

  // 3. Control flow runs as ordinary async guest JS, including a concurrent fan-out with
  //    the guest's own Promise.all, which real promises at the seam make possible.
  {
    const hostCall = (name, payload) => {
      const peer = payload[0];
      if (name === "offer") return sleep(1).then(() => new Uint8Array([peer % 2 === 0 ? 1 : 0]));
      if (name === "have") return sleep(1).then(() => new Uint8Array([peer % 3 === 0 ? 1 : 0]));
      return new Uint8Array();
    };
    const src = `
      async function handle(arg) {
        const count = arg[0], peerCount = arg[1];
        // Fan out OFFERs concurrently with the guest's own Promise.all.
        const offers = await Promise.all(
          Array.from({ length: peerCount }, (_, p) => host.call("offer", new Uint8Array([p]))),
        );
        const placed = [];
        for (let p = 0; p < peerCount && placed.length < count; p++) {
          if (offers[p][0] === 1) placed.push(p);
        }
        const haves = await Promise.all(
          Array.from({ length: peerCount }, (_, p) => host.call("have", new Uint8Array([p]))),
        );
        const holders = haves.filter((h) => h[0] === 1).length;
        return new Uint8Array([placed.length, holders, ...placed]);
      }
    `;
    const realm = await createSafeRealm({ source: src, hostCall });
    const res = await realm.call(new Uint8Array([3, 10]));
    assertEqual(res[0], 3, "loop placed exactly `count` blocks on distinct peers");
    assertEqual([...res.slice(2)], [0, 2, 4], "placement followed peer order and the accept rule");
    assertEqual(res[1], 4, "concurrent have/want fan-out (Promise.all) collected the right holders");
    realm.dispose();
  }

  // 4. Realm isolation: a poisoned guest cannot reach a sibling's global.
  {
    const a = await createSafeRealm({
      source: `globalThis.SECRET = 42; function handle() { return new Uint8Array([globalThis.SECRET ?? 0]); }`,
      hostCall: async () => new Uint8Array(),
    });
    const b = await createSafeRealm({
      source: `function handle() { return new Uint8Array([globalThis.SECRET ?? 0]); }`,
      hostCall: async () => new Uint8Array(),
    });
    const ra = await a.call(new Uint8Array());
    const rb = await b.call(new Uint8Array());
    assertEqual(ra[0], 42, "realm A sees its own global");
    assertEqual(rb[0], 0, "realm B does not see realm A's global");
    a.dispose();
    b.dispose();
  }

  console.log("  OK\n");
}

// ─── Test: one entry seam, serialized per realm (§12.3) ─────────────────
// One way in, `call`, which may yield. Each invocation runs to completion before the next
// begins because of the realm's FIFO queue (host/realm-queue.ts).

async function testRealmSerialization() {
  console.log("Test: one entry seam, serialized per realm (§12.3)");

  // 1. A synchronous entrypoint over a synchronous seam round-trips, and the realm is
  //    reusable; the result still resolves through a promise.
  {
    let calls = 0;
    const hostCall = (name, payload) => { calls++; return name === "inc" ? payload.map((b) => (b + 1) & 0xff) : new Uint8Array(); };
    const realm = await createSafeRealm({
      source: `function handle(arg) { return host.call("inc", arg); }`,
      hostCall,
    });
    const out = await realm.call(new Uint8Array([0, 9, 255]));
    assertEqual([...out], [1, 10, 0], "sync host.call round-trips through the copy boundary");
    assertEqual([...(await realm.call(new Uint8Array([41])))], [42], "the realm is reusable across calls");
    assertEqual(calls, 2, "the synchronous seam was invoked once per call");
    realm.dispose();
  }

  // 2. An invocation that arrives while another is waiting mid-await waits in the queue
  //    instead of interleaving. Worth the head-of-line cost: two invocations interleaving
  //    at every await would be impossible for a guest author to reason about.
  {
    let release;
    const gate = new Promise((r) => { release = r; });
    const hostCall = (name, payload) => {
      if (name === "park") return gate.then(() => new Uint8Array([42]));   // waits until released
      if (name === "inc") return payload.map((b) => (b + 1) & 0xff);       // answers at once (holder path)
      return new Uint8Array();
    };
    const realm = await createSafeRealm({
      source: `function handle(a) {
                 if (a[0] === 1) return (async () => await host.call("park", new Uint8Array()))();
                 if (a[0] === 2) return host.call("inc", a.subarray(1)); // holder path
                 throw new Error("no such sel " + a[0]);
               }`,
      hostCall,
    });
    const order = [];
    const initP = realm.call(new Uint8Array([1])).then((r) => { order.push("init"); return r; });
    const heldP = realm.call(new Uint8Array([2, 7])).then((r) => { order.push("hold"); return r; });

    // Give the holder every chance to jump the queue before the initiator is released.
    for (let i = 0; i < 10; i++) await Promise.resolve();
    assertEqual(order.length, 0, "the holder did not run while the initiator was parked");

    release();
    assertEqual([...(await initP)], [42], "the parked initiator resumed and settled");
    assertEqual([...(await heldP)], [8], "and the holder ran after it, on its own budget");
    assertEqual(order.join(","), "init,hold", "the queue preserved acceptance order");
    realm.dispose();
  }

  // 3. Still nothing reachable: the one seam is the same zero-authority sandbox.
  {
    const realm = await createSafeRealm({
      source: `function handle() { return new Uint8Array([typeof globalThis.process === "undefined" ? 0 : 1, typeof globalThis.fetch === "undefined" ? 0 : 1]); }`,
      hostCall: async () => new Uint8Array(),
    });
    const r = await realm.call(new Uint8Array());
    assertEqual([...r], [0, 0], "process / fetch are unreachable from an entrypoint");
    realm.dispose();
  }

  // 4. Disposing a realm while an invocation waits mid-await (the normal state of a node
  //    waiting on the network) fails the waiting caller and frees the context without
  //    taking the wasm module with it: the engine asserts an empty gc object list when a
  //    runtime is freed, so a handle the waiting call still held would abort the module.
  {
    const realm = await createSafeRealm({
      source: `async function handle() { await host.call("park", new Uint8Array()); }`,
      hostCall: (name) => (name === "park" ? new Promise(() => {}) : new Uint8Array()),  // never settles
    });
    const parked = realm.call(new Uint8Array());
    for (let i = 0; i < 10; i++) await Promise.resolve();   // let it reach its await
    realm.dispose();

    let msg = "";
    try { await parked; } catch (e) { msg = e.message; }
    assertEqual(msg, "guest realm disposed", "the parked invocation is failed by dispose, not stranded");
    let after = "";
    try { await realm.call(new Uint8Array()); } catch (e) { after = e.message; }
    assertEqual(after, "guest realm disposed", "a call accepted after dispose is refused, not run");

    // A realm built after the teardown shows the module survived it.
    const next = await createSafeRealm({
      source: `function handle(arg) { return arg; }`,
      hostCall: async () => new Uint8Array(),
    });
    assertEqual([...(await next.call(new Uint8Array([7])))], [7],
      "the engine is still alive after the parked realm's context was freed");
    next.dispose();
  }

  console.log("  OK\n");
}

// ─── Test: seam gating ───────────────────────────────────────────────────

async function testSeamGating() {
  console.log("Test: the guest seam enforces the manifest's declared requires + allocation caps");

  const id = generateKeyPair();
  const mk = (names) => withTestBudget(createGuestSeam({
    sodium,
    requires: names,
    backends: { ...testBackends(), node: appSignScope(id, "probe") },
    callLocal: TEST_CALL_LOCAL,
    modules: { names: new Set(), call: async () => ({ bytes: null, ms: 0 }) },
  }));
  const U = (...xs) => new Uint8Array(xs);
  let threw = false;

  // Host crypto transforms need no declaration: `crypto/` reaches nothing, so there is
  // nothing to gate. A seam for a bundle declaring no names still hashes.
  const timerOnly = mk(["timer"]);
  assertEqual((await timerOnly("crypto/blake2b", U(32, 0, 1, 2))).length, 32,
    "crypto/blake2b resolves for a bundle declaring no crypto name — a pure transform is not a grant");
  threw = false;
  try { await timerOnly("crypto/no-such-primitive", U(1)); } catch { threw = true; }
  assert(threw, "an unknown crypto name is refused by name (this host cannot serve it)");
  // A bare name looks up the calling bundle's own modules, scoped to the app the seam was
  // built for. This seam has no such module, so it has no route.
  threw = false;
  try { await timerOnly("echo", U(1, 120)); } catch { threw = true; }
  assert(threw, "a module name this seam was not built with reaches nothing");

  // Access is by service, not method: declaring `timer` resolves `timer/clear`, and an
  // undeclared service is still refused beside it.
  threw = false;
  try { await timerOnly("node/sign", U(1)); } catch { threw = true; }
  assert(threw, "an undeclared service (node) is refused by the seam");
  threw = false;
  try { await timerOnly("fs/delete", U(120)); } catch { threw = true; }
  assert(threw, "an undeclared service (fs) is refused by the seam");
  threw = false;
  try { await timerOnly("timer/clear", U()); } catch { threw = true; }
  assert(!threw, "timer/clear resolves under the declared service");

  // A manifest declares whole services: declaring `node` wires every `node/*` method,
  // `node/verify` as well as `node/sign` (§12.2).
  const nodeOnly = mk(["node"]);
  assertEqual((await nodeOnly("node/sign", U(1, 2))).length, 64, "node/sign resolves under the declared service");
  const nodeSig = await nodeOnly("node/sign", U(3));
  assertEqual((await nodeOnly("node/verify", concatBytes([id.publicKey, nodeSig, U(3)])))[0], 1, "…and so does node/verify, the SAME declared service");
  threw = false;
  try { await nodeOnly("fs/get", U(120)); } catch { threw = true; }
  assert(threw, "a different, undeclared service (fs) is still refused beside the declared one");

  // Declaring a method's name is not declaring its service: `node/sign` is not a service,
  // so it is read as a local service id nothing claims and no `node` handler is wired
  // (install would also refuse the manifest).
  const methodNameOnly = mk(["node/sign"]);
  threw = false;
  try { await methodNameOnly("node/sign", U(1, 2)); } catch { threw = true; }
  assert(threw, "declaring a method's exact name, not its service, grants nothing");

  // Guest-controlled allocation caps. Tests that use every host service declare them all
  // explicitly; omitting requires entirely throws (§12.2).
  const open = mk(ALL_HOST_SERVICES);
  let omitted = false;
  try { mk(undefined); } catch { omitted = true; }
  assert(omitted, "omitting requires throws rather than granting every name");
  // A declared service this node cannot provide fails the seam, so the install fails.
  let unbacked = "";
  try {
    createGuestSeam({ sodium, requires: ["fs"], backends: { ...testBackends(), fs: undefined },
      callLocal: TEST_CALL_LOCAL, modules: { names: new Set(), call: async () => ({ bytes: null, ms: 0 }) } });
  } catch (e) { unbacked = e.message; }
  assert(unbacked.includes('requires "fs"'), `a declared fs on a diskless node is refused at construction (got: ${unbacked})`);
  // Entropy needs no declaration: a seam declaring nothing can still get it.
  const none = mk([]);
  assertEqual((await none("crypto/random", U(0, 0, 4, 0))).length, 1024, "crypto/random under the cap works, with nothing declared");
  threw = false;
  try { await none("crypto/random", U(0xff, 0xff, 0xff, 0xff)); } catch { threw = true; }
  assert(threw, "crypto/random over the cap is refused");

  // Names are checked at install, not at first use: an unknown name in a manifest refuses
  // the bundle (verifyTestBundle), and the seam also answers "no such name".
  threw = false;
  try { await open("transform/do", U()); } catch { threw = true; }
  assert(threw, "`transform` is gone from the vocabulary — a manifest naming it is refused");

  console.log("  OK\n");
}

async function testCallModuleGuards() {
  console.log("Test: ModuleTable.callModule resolves by name, or null when unbound (§4)");

  const { makeHost } = await import("./fixtures.mjs");
  const { host } = await makeHost();
  const guards = "guards";

  // An unbound module resolves to null, distinct from an empty response, and so does a
  // module under an app that was never installed.
  assert(await host.callModule(guards, "missing", new Uint8Array([1])) === null,
    "callModule returns null for an unbound module");
  assert(await host.callModule("nope", "echo", new Uint8Array([1])) === null,
    "callModule returns null for an app that installed nothing");

  // An installed module is reached by name. A confined guest reaches the same module
  // through the guest seam by its bare name (§12.2).
  await installMod(host, guards, "echo", forwarderBytes);
  const r = await host.callModule(guards, "echo", new Uint8Array([5]));
  assertEqual([...r], [5], "callModule reaches an installed module");

  // A 0-length response is a valid empty answer, not the null of an unbound name, so a
  // caller can tell "module ran and returned nothing" from "no such module".
  const empty = await host.callModule(guards, "echo", EMPTY);
  assert(empty !== null && empty.length === 0,
    "an empty response is an empty array, distinct from null");

  // The worker copies a result out before wiping scratch. This probe's second call
  // returns the first call's old span without rewriting it, so anything left behind in
  // the long-lived instance would come back here.
  const scrubber = await new JsModuleLoader().build([{
    name: "probe", wasm: readFileSync(join(root, "build/scratch-probe.wasm")),
  }]);
  const secret = new Uint8Array(64).fill(0xa5);
  assert((await scrubber.call("probe", secret)).bytes.length === 0, "scratch probe records a secret-bearing request");
  const residue = (await scrubber.call("probe", Uint8Array.of(0))).bytes;
  assert(residue.length === secret.length && residue.every((b) => b === 0),
    "the JS module worker erases staged requests before the next call");
  const secretResult = (await scrubber.call("probe", Uint8Array.of(1))).bytes;
  assert(secretResult.length === secret.length && secretResult.every((b) => b === 0xa5),
    "scratch probe returns a secret-bearing response longer than its request");
  const resultResidue = (await scrubber.call("probe", Uint8Array.of(0))).bytes;
  assert(resultResidue.length === secret.length && resultResidue.every((b) => b === 0),
    "the JS module worker erases copied responses before the next call");
  scrubber.dispose();

  console.log("  OK\n");
}

// ─── Test: a module call is bounded (§4.3) ────────────────────────────────────────
// The JS platform's WebAssembly has no fuel or timeout, so a module call in the host
// thread that never returned would wedge the node for good (a restart would hit it again
// from the same inbound frame). The worker-per-module table prevents that: a spinning
// module answers empty at its deadline, the host thread stays alive, and a fresh instance
// serves the next call.
async function testModuleCallBound() {
  console.log("Test: a spinning module is killed at its deadline and respawned (§4.3)");

  const { ModuleTable } = await imp("build/host/module-table.js");
  const { SPIN_WASM, SPIN_OR_ECHO_WASM } = await import("./fixtures/spin-wasm.mjs");
  const { testHost } = await import("./fixtures.mjs");
  const spinKey = "spin";

  // The default table bound is generous and set by the deployment. A guest's call carries
  // its own deadline: the guest's remaining segment.
  const host = testHost(new ModuleTable({ deadlineMs: 60_000 }));
  await host.bindAll(spinKey, [{ name: "spin", wasm: SPIN_OR_ECHO_WASM }]);
  assert(host.isBound(spinKey, "spin"), "the spinning module binds (its memory is bounded at admission)");

  // The host thread is never blocked: timers keep firing while the module spins in its
  // worker. Running the call in this thread would let a spinner wedge everything,
  // including the transport.
  let heartbeats = 0;
  const beats = setInterval(() => heartbeats++, 25);

  const t0 = Date.now();
  // A 120 ms bound. Null at the table, as for a trap, which the guest seam turns into a
  // rejection (§12.2).
  const r = await host.callModule(spinKey, "spin", new Uint8Array([1]), 120);
  const spent = Date.now() - t0;
  clearInterval(beats);

  assert(r === null, "the spin answers like a trap — null at the table, a rejection at the seam");
  assert(spent >= 100 && spent < 3000, `it is killed near its bound, not eventually (${spent}ms)`);
  assert(heartbeats > 0, "the host thread was alive the whole time the module spun");

  // A fresh instance serves the next call to the same module: the kill ended the old
  // worker, and that call loads a new one with clean state, without reinstalling.
  const echo = await host.callModule(spinKey, "spin", new Uint8Array([0, 9]), 1000);
  assertEqual([...echo], [0, 9], "the killed module answers on a fresh worker");

  // Two calls to the same module cannot run at once: the table keeps one in flight per
  // module (§4.3), so a spinner burns one core for one bound.
  const host2 = testHost(new ModuleTable());
  await host2.bindAll(spinKey, [{ name: "spin", wasm: SPIN_OR_ECHO_WASM }]);
  const t1 = Date.now();
  const [a, b] = await Promise.all([
    host2.callModule(spinKey, "spin", new Uint8Array([1]), 80),
    host2.callModule(spinKey, "spin", new Uint8Array([1]), 80),
  ]);
  const serial = Date.now() - t1;
  assert(a === null && b === null,
    "both spins answered like traps, at their own deadlines");
  assert(serial >= 140 && serial < 5000, `the two calls ran one after the other (${serial}ms)`);
  // The same module still answers after two kills in a row: the queued call loaded the
  // worker the second spin ran on, and the next call loads another.
  const after = await host2.callModule(spinKey, "spin", new Uint8Array([0, 3]), 1000);
  assertEqual([...after], [0, 3], "the module answers on a fresh worker after two kills");
  host2.removeApp(spinKey);

  // An unbounded call is an explicit operator opt-out: Infinity disables the bound, and
  // the worker spins until the app is dropped. The host stays responsive, and dropping
  // the app settles the in-flight call as empty instead of leaving it hanging.
  const host3 = testHost(new ModuleTable({ deadlineMs: Infinity }));
  await host3.bindAll(spinKey, [{ name: "spin", wasm: SPIN_WASM }]);
  let beats3 = 0;
  const beats3Timer = setInterval(() => beats3++, 25);
  const forever = host3.callModule(spinKey, "spin", new Uint8Array(), Infinity);
  await sleep(60);
  clearInterval(beats3Timer);
  assert(beats3 > 0, "host alive with an unbounded spin in flight");
  host3.removeApp(spinKey);
  const dropped = await forever;
  assert(dropped === null, "removing the app settles the in-flight spin as a trap would");

  console.log("  OK\n");
}

// ─── Test: the guest's module call runs under the guest's own budget ─────────────
//
// "Charged to the calling guest's budget" (§4.3): the realm computes the caller's
// remaining execution segment at the moment of the call and gives it to the module as the
// call's deadline. A guest that has spent most of its budget gets a module call killed
// far sooner than the deployment's default bound.
async function testModuleCallChargedToGuestBudget() {
  console.log("Test: a module call is charged to the calling guest's remaining segment (§4.3)");

  const { ModuleTable } = await imp("build/host/module-table.js");
  const { SPIN_WASM } = await import("./fixtures/spin-wasm.mjs");
  const { createGuestSeam } = await imp("build/host/guest-seam.js");
  const { createSafeRealm } = await imp("build/host/safe-js.js");
  const { testHost } = await import("./fixtures.mjs");

  const host = testHost(new ModuleTable({ deadlineMs: 60_000 }));
  const spinKey = "app";
  await host.bindAll(spinKey, [{ name: "spin", wasm: SPIN_WASM }]);
  const seam = createGuestSeam({
    sodium,
    requires: ALL_HOST_SERVICES,
    backends: testBackends(),
    callLocal: TEST_CALL_LOCAL,
    modules: {
      names: new Set(["spin"]),
      call: (n, p, deadlineMs) => host.slots.get(spinKey)?.call(n, p, deadlineMs) ?? Promise.resolve({ bytes: null, ms: 0 }),
    },
  });
  // The realm's budget is 5 s, but the guest burns most of it before calling the module:
  // the call must then be killed near what remains, not at the table's 60 s.
  const realm = await createSafeRealm({
    source: `async function handle() {
      const t0 = Date.now();
      while (Date.now() - t0 < 4900) { /* burn the segment */ }
      return await host.call("spin", new Uint8Array());
    }`,
    hostCall: seam,
    deadlineMs: 5000,
  });
  const t0 = Date.now();
  let firstFailure = "";
  try { await realm.call(new Uint8Array()); }
  catch (e) { firstFailure = e.message; }
  const spent = Date.now() - t0;
  realm.dispose();
  assert(firstFailure.includes("deadline"),
    "the module's bounded empty answer cannot arrive after the enclosing handoff expired");
  // The burn is ~4.9s, so the whole call is ~5s; the module died at the ~100ms that
  // remained, not at the table's 60s default. A broken deadline flow would hang this
  // call for a minute.
  assert(spent >= 4800 && spent < 8000,
    `the call died with the guest's remaining budget, not the table's (${spent}ms)`);

  // The other half of "charged": the module's CPU time is billed to the segment that
  // called it, and a segment with nothing left refuses the next call. Both halves are
  // needed: the guest waits while the module runs, so its own spend advances by
  // microseconds per turn, and QuickJS's interrupt is checked per bytecode, of which this
  // guest runs almost none between calls.
  const looper = await createSafeRealm({
    source: `async function handle() {
      for (;;) await host.call("spin", new Uint8Array());
    }`,
    hostCall: seam,
    deadlineMs: 1000,
  });
  const t1 = Date.now();
  let killed = "";
  try { await looper.call(new Uint8Array()); }
  catch (e) { killed = e.message; }
  const looped = Date.now() - t1;
  looper.dispose();
  assert(killed.includes("budget exhausted") || killed.includes("deadline"),
    `a guest looping on a spinning module is refused, not endless (ran ${looped}ms, got: ${killed || "no throw"})`);
  // ~1 s of module burn spends the 1 s budget, and the next turn throws. The upper bound
  // is what fails if either half is dropped.
  assert(looped >= 900 && looped < 6000,
    `the guest died once the module burn added up to its budget (${looped}ms)`);

  console.log("  OK\n");
}

// ─── Test: the seam is always async, and a forgotten await cannot read bytes ─────
//
// Every name, crypto included, answers a Promise, so `host.call` never returns bytes in
// the calling turn. A guest that forgets the await reads a Promise instead of bytes; this
// test checks that for each name.
async function testPreviousAbiRefused() {
  console.log("Test: every host.call answers a Promise — no name sits on a sync line");

  const NAMES = ["crypto/blake2b", "crypto/random"];
  // A well-formed argument per name, so each probe settles by resolving.
  const ARGS = [[32, 0, 0, 0], [0, 0, 0, 4]];
  // One byte per probed name: 1 when the un-awaited call handed back a thenable.
  const source = `
    const names = ${JSON.stringify(NAMES)}, args = ${JSON.stringify(ARGS)};
    function handle() {
      const out = new Uint8Array(names.length);
      for (let i = 0; i < names.length; i++) {
        const r = host.call(names[i], new Uint8Array(args[i]));
        out[i] = typeof r.then === "function" ? 1 : 0;
      }
      return out;
    }`;
  const realm = await createSafeRealm({
    source,
    hostCall: createGuestSeam({
      sodium,
      requires: ALL_HOST_SERVICES,
      backends: testBackends(),
      callLocal: TEST_CALL_LOCAL,
      modules: { names: new Set(), call: async () => ({ bytes: null, ms: 0 }) },
    }),
  });
  const out = await realm.call(new Uint8Array(0));
  assert(out.length === NAMES.length, `one verdict per probed name (got ${out.length})`);
  for (let i = 0; i < NAMES.length; i++) {
    assert(out[i] === 1, `${NAMES[i]} answered a Promise, not inline bytes`);
  }
  await realm.dispose();

  console.log("  OK\n");
}

async function testSafeRealmConcurrency() {
  console.log("Test: concurrent call()s on one safe-js realm retain their own arguments");

  // Concurrent callers queue at the realm boundary. Each entry passes its own argument
  // handle synchronously, before the first await, and retains those bytes while parked.
  const realm = await createSafeRealm({
    source: `async function handle(a) { return await host.call("echo", a); }`,
    hostCall: (_name, p) => sleep(10).then(() => p),
  });
  try {
    const [r1, r2] = await Promise.all([
      realm.call(new Uint8Array([1])),
      realm.call(new Uint8Array([2])),
    ]);
    assertEqual([...r1], [1], "first concurrent call returns its own bytes");
    assertEqual([...r2], [2], "second concurrent call returns its own bytes");
  } finally {
    realm.dispose();
  }

  console.log("  OK\n");
}

// ─── Test: a deferred invocation keeps its own deadline ─────────────────────────────
//
// `__deferred` hands the realm to the next entry and nothing else: it "transfers queue
// occupancy and never time custody" (§12.2). A host call that settles after
// another invocation has entered therefore resumes under, and can only fail, the
// invocation that made it. A realm with one clock for whoever entered last would lend a
// waiting invocation that entry's remainder, fail every waiting caller when one overruns,
// and bill a module's CPU time to the wrong one. native/guest_test.go checks case 1 on the
// native realm; case 2 is JS-only, since a native module runs inside the calling segment.
async function testDeferredKeepsItsDeadline() {
  console.log("Test: a deferred invocation resumes under its own deadline, not a later entry's (§12.3)");

  // `park` waits until the test settles it by tag; `remaining` records the remainder it was handed.
  const parkingRealm = async (source, deadlineMs) => {
    const parked = new Map();
    const remaining = new Map();
    const realm = await createSafeRealm({
      source,
      deadlineMs,
      hostCall: (name, tag, budget) => {
        if (name === "remaining") { remaining.set(tag[0], budget.remainingMs); return tag; }
        return new Promise((resolve, reject) => parked.set(tag[0], { resolve, reject, budget }));
      },
    });
    const bothParked = async () => { while (parked.size < 2) await sleep(0); };
    return { realm, parked, remaining, bothParked };
  };
  const outcome = (call) => call.then(() => "answered", (err) => err.message);

  // 1. Invocation 1 (1 s) waits, then 2 (the realm's 5 s) enters and waits behind it. 1 is
  //    resumed by a rejection and 2 by an answer, so both settlement paths are covered.
  {
    const { realm, parked, remaining, bothParked } = await parkingRealm(`async function handle(tag) {
      globalThis.__deferred = true;
      try { await host.call("park", tag); } catch {}
      await host.call("remaining", tag);
      if (tag[0] === 1) for (;;) {}
      return tag;
    }`, 5000);
    try {
      const short = outcome(realm.call(Uint8Array.of(1), 1000));
      const long = outcome(realm.call(Uint8Array.of(2)));
      await bothParked();
      parked.get(1).reject(new Error("refused"));
      assert(await short !== "answered", "the resumed spin is interrupted");
      assert(remaining.get(1) <= 1000,
        `invocation 1 resumed under its own 1 s, not the later entry's 5 s (${remaining.get(1)} ms left)`);
      parked.get(2).resolve(EMPTY);
      assertEqual(await long, "answered", "the interrupt failed only the invocation it resumed");
      assert(remaining.get(2) > 1000, `invocation 2 kept its own remainder (${remaining.get(2)} ms left)`);
    } finally {
      realm.dispose();
    }
  }

  // 2. A module's CPU time is billed to the invocation that called it (§4.3), even when
  //    it is billed while another holds the realm: a full allowance exhausts 1, never 2.
  {
    const { realm, parked, bothParked } = await parkingRealm(`async function handle(tag) {
      globalThis.__deferred = true;
      await host.call("park", tag);
      return await host.call("remaining", tag);
    }`, 1000);
    try {
      const billed = outcome(realm.call(Uint8Array.of(1)));
      const other = outcome(realm.call(Uint8Array.of(2)));
      await bothParked();
      parked.get(1).budget.charge(1000);
      parked.get(2).resolve(EMPTY);
      assertEqual(await other, "answered", "another invocation's bill left this one's budget alone");
      parked.get(1).resolve(EMPTY);
      assert(await billed !== "answered", "the bill exhausted the invocation it was charged to");
    } finally {
      realm.dispose();
    }
  }

  console.log("  OK\n");
}

async function testDetachedAnswerIsANewTurn() {
  console.log("Test: a detached call's answer resumes as a new turn, not under a spent invocation (§12.3)");

  // `deliver` detaches and never answers, so its own handoff deadline (the invocation's
  // 100 ms) settles it; `remaining` records the remainder its continuation was given.
  const remaining = [];
  const realm = await createSafeRealm({
    source: `function handle(tag) {
      host.call("deliver", tag).then(() => {}, () => {})
        .then(() => host.call("remaining", tag)).catch(() => {});
      return tag;
    }`,
    deadlineMs: 5000,
    hostCall: (name, tag, budget) => {
      if (name === "remaining") { remaining.push(budget.remainingMs); return Promise.resolve(tag); }
      budget.detach?.();
      return new Promise(() => {});
    },
  });
  try {
    await realm.call(Uint8Array.of(1), 100);
    for (let waited = 0; remaining.length === 0 && waited < 2000; waited += 10) await sleep(10);
    assert(remaining.length === 1 && remaining[0] > 1000,
      `the answer resumed under a fresh turn, not the invocation's spent 100 ms (${JSON.stringify(remaining)})`);
  } finally {
    realm.dispose();
  }

  console.log("  OK\n");
}

async function testOwnTurns() {
  console.log("Test: an ownTurns realm runs on its own ceiling; a caller's deadline bounds only its wait (§12.3)");

  // `wait` answers when the test says, after the caller's 50 ms are long gone; `remaining`
  // records the remainder the turn still had then.
  let release;
  const remaining = [];
  const realm = await createSafeRealm({
    source: `async function handle(tag) {
      try { await host.call("wait", tag); await host.call("remaining", tag); } catch {}
      return tag;
    }`,
    deadlineMs: 5000,
    ownTurns: true,
    hostCall: (name, tag, budget) => {
      if (name === "remaining") { remaining.push(budget.remainingMs); return Promise.resolve(tag); }
      return new Promise((resolve) => { release = resolve; });
    },
  });
  try {
    const caller = realm.call(Uint8Array.of(1), 50).then(() => "answered", (err) => err.message);
    assert(/deadline/.test(await caller), "the caller's own deadline still bounds its wait");
    await sleep(100);
    release(EMPTY);
    for (let waited = 0; remaining.length === 0 && waited < 2000; waited += 10) await sleep(10);
    assert(remaining.length === 1 && remaining[0] > 1000,
      `the turn ran on the realm's own 5 s, not the caller's 50 ms (${JSON.stringify(remaining)})`);
  } finally {
    realm.dispose();
  }

  console.log("  OK\n");
}

// ─── Test: a standard handshake is buildable on the host names (Noise XX vectors) ───
// The host's crypto/ names must expose their algorithms' whole standard interface, or a
// replacement transport could not ship as a bundle (services/domains.ts). Published
// Noise_XX vectors, replayed byte for byte through a seam with no services declared: the
// same script native/guestseam_test.go runs against the Go primitives.
async function testNoiseVectors() {
  console.log("Test: the published Noise XX vectors replay through the crypto/ names alone");
  await import("./noise-vectors.js");
  const { vectors } = JSON.parse(readFileSync(join(root, "tests", "fixtures", "noise-xx-vectors.json"), "utf8"));
  const seam = withTestBudget(createGuestSeam({
    sodium,
    requires: [],
    backends: {},
    callLocal: TEST_CALL_LOCAL,
    modules: { names: new Set(), call: async () => ({ bytes: null, ms: 0 }) },
  }));
  const { ran, failures } = await globalThis.runNoiseVectors((name, bytes) => seam(name, bytes), vectors);
  assertEqual(ran, 2, "both vectors ran");
  assertEqual(failures, [], "every handshake message, handshake hash and transport message matches");
  console.log("  OK\n");
}

// ─── Run ────────────────────────────────────────────────────────────────

await testGuestSeam();
await testNoiseVectors();
await testPolicy();
await testSigningScopeFollowsSlot();
await testGuestAbi();
await testSafeJs();
await testRealmSerialization();
await testSeamGating();
await testCallModuleGuards();
await testModuleCallBound();
await testModuleCallChargedToGuestBudget();
await testPreviousAbiRefused();
await testSafeRealmConcurrency();
await testDeferredKeepsItsDeadline();
await testDetachedAnswerIsANewTurn();
await testOwnTurns();

summary("Results");
