// realm-guest.test.mjs — the guest seam and realm lifecycle (§12.2, §12.3, §4.3): the
// link-slot binding, privilege derivation from `guest.requires`, node/sign scoping,
// safe-js confinement, realm serialization, seam gating, and module-call budgeting. Split
// out of the former single-file run.mjs; bundle-install.test.mjs covers the bundle/manifest
// verify → admit → install lifecycle, crypto.test.mjs the manifest-suite and ACVP suites.
//
// Positive-path bundle fixtures go through `authorBundle` (host/bundle-author.ts) rather
// than hand-rolled `signManifest` + `packBundle` — see bundle-install.test.mjs's header for
// why a handful of cases keep the manual form instead.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { testkit } from "./testkit.mjs";
import {
  sodium, generateKeyPair, JsModuleLoader, root,
  toHex, concatBytes, appKeyFor, verifyManifest,
  signManifest, packBundle, authorBundle, gHash, GUEST_TEXT, GUEST_BYTES, GUEST,
  testAuthor, bootTestShell, appKey, imp, MemoryFs,
  createGuestSeam, guestSignScope, appSignScope, ALL_HOST_SERVICES, TEST_TIMERS, TEST_CALLS,
  createSafeRealm, callerOf, readOp, writeOp, forwarderBytes, installMod, makeHost, EMPTY,
} from "./fixtures.mjs";
import { bytesEqual } from "./bytes.mjs";

const { ok, assertEqual, summary, sleep } = testkit({ verbose: false });
const assert = ok;

// ─── Test: the raw-link binding has ONE owner (§12.10) ───────────────────────
// The driver has one event sink, so a second link-capable slot cannot be a composition: it
// would take the node's sockets while the incumbent kept its claims and its realm, leaving
// a node that looks installed and answers nothing. Refused instead, on the same rule as a
// contested claim — and the incumbent's OWN next version still replaces it in place.
async function testOneRawLinkOwner() {
  console.log("Test: a second link-capable identity is refused the raw-link binding (§12.10)");
  const { admitAll } = await imp("build/host/policy.js");

  const author = testAuthor();
  const blob = (app, version, requires) => authorBundle(sodium, author, {
    app, version, modules: [], guestSource: GUEST_TEXT, guestRequires: requires,
  }).blob;
  // Both candidates are this author's, so the pin admits both and what refuses the
  // second is the binding rule under test rather than an earlier gate.
  const shell = await bootTestShell({
    createRealm: async () => ({ async call() { return new Uint8Array(); }, dispose() { } }),
    pinAuthor: author,
    admit: admitAll,
  });
  try {
    await shell.loadBundleBlob(blob("transport", 1, ["link"]));
    // A link-capable bundle that claims nothing — the initiator shape. Same privilege, so
    // the same binding, so it must not land quietly.
    let refused = "";
    try { await shell.loadBundleBlob(blob("dialer", 1, ["link"])); } catch (e) { refused = String(e); }
    assert(/binding is already held by/.test(refused),
      `a second link-capable identity is refused: ${refused || "no error"}`);
    // A bundle reaching no `link` name is unaffected — the binding is the privilege's, not
    // a global lock on loading.
    await shell.loadBundleBlob(blob("app", 1, ["clock"]));
    // The holder's own next version replaces it in place: an upgrade is not a contest.
    await shell.loadBundleBlob(blob("transport", 2, ["link"]));
    // And uninstalling the holder frees it for anyone.
    shell.uninstall(appKey(author.id, "transport"));
    await shell.loadBundleBlob(blob("dialer", 1, ["link"]));
  } finally { shell.close(); }
  console.log("  OK\n");
}

// ─── Test: guest-side fan-out over the cross-realm call (Promise.all) ────────────
// Fan-out is not a host op: with real promises at the seam, a confined guest scatters a
// distinct request per peer itself with Promise.all over `_net`. Driven here through the
// seam's single-peer cross-realm call, concurrently, so the round trips overlap in one realm.

async function testGuestSeam() {
  console.log("Test: guest seam — host transforms, authorities and private modules (step 7)");

  const id = generateKeyPair();
  const otherKey = generateKeyPair();
  const fs = new MemoryFs();
  // The routing a local service id resolves through — the shell's job in production, a
  // stub here so the seam is tested for what it does: gate the name, then hand the
  // payload to whatever claims the id. `_net` and `chat/v1` are claimed; `_nobody` is not.
  const claimed = new Set(["_net", "chat/v1"]);
  const calls = { call: (idName) => (claimed.has(idName) ? Promise.resolve(U(9, 9)) : null) };
  // THIS realm's declared local services (§12.10) — what tells them apart from a bare
  // module name at the dispatch. `chat/v1` is here because a local service id is an ordinary
  // claim: it may carry a `/` exactly like a wire protocol id.
  const localServices = new Set(["_net", "_nobody", "chat/v1"]);

  // A module reachable by name, for the catalog's app-module half.
  const { host } = await makeHost();
  const testKey = appKey(id.publicKey, "testapp");
  await installMod(host, testKey, "echo", forwarderBytes);

  // A host-derived signing scope binds the guest's node/sign name to a bundle namespace
  // (§12.2); a real node derives it from the manifest's (author, app).
  const signScope = appSignScope(id, id.publicKey, "testapp");
  const scopeBytes = guestSignScope(id.publicKey, "testapp");
  const seam = createGuestSeam({
    platform: { sodium, identity: id, now: () => Date.now() },
    grants: { names: ALL_HOST_SERVICES, localServices, signScope, fs, calls, timers: TEST_TIMERS },
    // Scoped to one app, exactly as the shell scopes it: a bare name is a module
    // inside this app's map and cannot reach out of it.
    modules: {
      names: new Set(["echo"]),
      call: (name, p) => host.slots.get(testKey)?.call(name, p) ?? Promise.resolve({ bytes: null, ms: 0 }),
    },
  });
  const U = (...xs) => new Uint8Array(xs);

  try {
    // Primitives are reached BY NAME through the `crypto/` prefix: there is no op
    // number per algorithm, so adding one is a catalog entry and the seam never learns
    // what a cipher suite is.
    const prim = (name, argBytes) => seam(`crypto/${name}`, argBytes);
    const msg = U(1, 2, 3, 4, 5);
    assert(bytesEqual(await prim("blake2b-256", msg), sodium.crypto_generichash(32, msg)), "crypto/blake2b-256, by name");
    // node/sign is scoped, never raw (§12.2): it signs DOMAIN_guest ‖ scope ‖ msg.
    // node/verify applies the SAME scope host-side, so a guest checks a signature by
    // naming the key, never by reconstructing the prefix the host owns.
    const DOMAIN_GUEST = new TextEncoder().encode("seedkernel-guest-sig-v1\0");
    const sig = await seam("node/sign", msg);
    const preimage = concatBytes([DOMAIN_GUEST, scopeBytes, msg]);
    assert(sodium.crypto_sign_verify_detached(sig, preimage, id.publicKey), "node/sign signs DOMAIN_guest ‖ scope ‖ msg under the node identity");
    assert(!sodium.crypto_sign_verify_detached(sig, msg, id.publicKey), "node/sign never signs the raw message (scoped, not raw)");
    assertEqual((await seam("node/verify", concatBytes([id.publicKey, sig, msg])))[0], 1, "node/verify accepts what node/sign signed — the same scope, host-applied");
    assertEqual((await seam("node/verify", concatBytes([otherKey.publicKey, sig, msg])))[0], 0, "node/verify rejects the signature under a different key");
    assertEqual((await seam("node/verify", concatBytes([id.publicKey, sig, U(9, 9)])))[0], 0, "node/verify rejects a forged message");
    // A mis-framed call is not a failed verification: too few bytes to hold [pk][sig]
    // throws, where 0 would have been a verdict about bytes nothing checked. The bound
    // is exactly the fixed prefix — an empty message is a legitimate question.
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
    assert(bytesEqual(await seam("node/identity", U()), id.publicKey), "node/identity = the node pubkey");
    assertEqual((await seam("node/random", U(0, 0, 0, 16))).length, 16, "node/random returns n bytes");
    assertEqual((await seam("clock/now", U())).length, 8, "clock/now returns a u64");

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

    // There is no sync/async line and nothing to version: every name — a catalog
    // primitive included — answers a Promise the guest awaits. A forgotten `await`
    // reads a Promise where bytes were expected for ALL names alike, which is why no
    // manifest field is needed to catch it any more.
    assert(prim("blake2b-256", msg) instanceof Promise, "a catalog primitive answers a Promise like every name");
    assert(seam("fs/size", fk) instanceof Promise, "fs/size returns a Promise");
    assert(seam("clock/now", U()) instanceof Promise, "clock/now returns a Promise");

    // The CROSS-REALM call: a name in THIS realm's declared local services is another
    // realm, reached on a later turn, so it is a Promise like fs. There is no `net`
    // domain — the network is a bundle that declares the service `_net`, and this seam's
    // routing answers it (§12.10).
    const crossed = seam("_net", U(1, 2, 3));
    assert(crossed instanceof Promise, "a local service id returns a Promise (the callee runs on a later turn)");
    assertEqual([...await crossed], [9, 9], "…and resolves with what the callee's handle returned");
    let unclaimed = false;
    try { await seam("_nobody", U()); } catch { unclaimed = true; }
    assert(unclaimed, "a local service id no realm claims is refused by name, not left pending");
    // The declaration is asked BEFORE the charset, so an id spelled with a `/` — legal
    // for any claim (§12.10) — reaches the routing rather than the host table, where it
    // would have died as an unknown host name.
    assertEqual([...await seam("chat/v1", U(1))], [9, 9],
      "a declared local service id carrying a `/` still routes to the claiming realm");

    // A bare name reaches this app's module by its LOGICAL name, in the same `host.call`
    // shape as every other name (§12.2). The app key is the seam's, never the caller's.
    assertEqual([...await seam("echo", U(8, 9))], [8, 9], "a bare name invokes this app's module");
    let noSuch = false;
    try { await seam("nosuchmodule", U(1)); } catch { noSuch = true; }
    assert(noSuch, "a bare name this app never installed is refused, like any unknown name");
  } finally { /* nothing host-side to tear down: the seam holds no transport */ }

  console.log("  OK\n");
}

// ──── Test: channel identity pinning (transport §12.6) ────

async function testPolicy() {
  console.log("Test: shell install policy — closed author sets gate bundle loads");
  const { parsePolicy } = await imp("build/host/policy.js");

  const good = testAuthor();
  const bad = testAuthor();

  // Build a signed bundle from each author; loadBundle accepts/rejects by predicate.
  const { ModuleTable } = await imp("build/host/module-table.js");
  const { testHost, loadBundle, LINK_CTX, APP_CTX } = await import("./fixtures.mjs");
  const tryLoad = async (policyJson, author, links) => {
    const host = testHost(new ModuleTable());
    const { blob } = authorBundle(sodium, author, {
      app: "mod", version: 1,
      modules: [{ name: "fwd", wasm: forwarderBytes }],
      guestSource: GUEST_TEXT, guestRequires: links ? ["link"] : [],
    });
    const admit = parsePolicy(policyJson);
    let landed = false;
    try { await loadBundle(host, blob, admit, links ? LINK_CTX : APP_CTX); landed = true; } catch { /* author not in policy */ }
    return landed;
  };

  // ── author allowlist ───────────────────────────────────────────────────
  const okAuthor = await tryLoad(JSON.stringify({ authors: [toHex(good.id)] }), good);
  assert(okAuthor, "install by an allowed author is accepted");

  const badAuthor = await tryLoad(JSON.stringify({ authors: [toHex(good.id)] }), bad);
  assert(!badAuthor, "install by an author not on the allowlist is rejected");

  // ── the transport is a GRANTED CAPABILITY, not a kind of bundle (§12.5) ────
  // The `link` privilege carries raw links and network-scoped signing, so the ordinary
  // author list must NOT admit one even for an author it already trusts with apps.
  const goodHex = toHex(good.id);
  const appOnly = JSON.stringify({ authors: [goodHex] });
  const withTransport = JSON.stringify({ authors: [goodHex], grants: { link: [goodHex] } });

  const linkDenied = await tryLoad(appOnly, good, true);
  assert(!linkDenied, "an author trusted for apps does NOT thereby hold `link`");
  const linkAllowed = await tryLoad(withTransport, good, true);
  assert(linkAllowed, "a grants.link entry admits that author to the transport");
  const strangerLink = await tryLoad(withTransport, bad, true);
  assert(!strangerLink, "an author outside the `link` grant is refused it");
  const appStillOk = await tryLoad(withTransport, good, false);
  assert(appStillOk, "adding a grant does not disturb ordinary app admission");

  // The two answers are independent: a grant alone admits no unprivileged bundle.
  const transportOnly = JSON.stringify({ grants: { link: [goodHex] } });
  const appUnderTransportList = await tryLoad(transportOnly, good, false);
  assert(!appUnderTransportList, "a `link` grant is not a licence to load — `authors` still decides that");

  // ── parse validation ───────────────────────────────────────────────────
  let threw = false;
  try { parsePolicy("{ not json"); } catch { threw = true; }
  assert(threw, "malformed policy JSON throws (fails the boot loudly)");
  threw = false;
  try { parsePolicy(JSON.stringify({ authors: [] })); } catch { threw = true; }
  assert(threw, "an empty author set is rejected");
  threw = false;
  try { parsePolicy(JSON.stringify({ authors: [goodHex], grants: { link: [] } })); } catch { threw = true; }
  assert(threw, "an empty grant list is rejected (omit the key to grant none)");
  // A key the host does not know is refused at the top level too, not just under `grants`:
  // ignoring it is how a mistyped file boots looking configured and silently holds nothing.
  threw = false;
  try { parsePolicy(JSON.stringify({ authorss: [goodHex], grants: { link: [goodHex] } })); } catch { threw = true; }
  assert(threw, "a mistyped top-level key is refused rather than ignored");
  // The privilege NAMES come from the catalog, which is the whole reason the key is a
  // capability rather than free-form text.
  threw = false;
  try { parsePolicy(JSON.stringify({ grants: { links: [goodHex] } })); } catch { threw = true; }
  assert(threw, "a grant naming no privilege this host has is refused by name");
  // `route` is gone: delivery is one of the `link` privilege's own names (`link/deliver`),
  // and a policy file written for the separate grant is a file this host does not mean —
  // refused at the boot rather than read as an empty grant.
  threw = false;
  try { parsePolicy(JSON.stringify({ grants: { route: [goodHex] } })); } catch { threw = true; }
  assert(threw, "`grants.route` is no longer a privilege key — refused by name, kept nobody");
  threw = false;
  try { parsePolicy(JSON.stringify({})); } catch { threw = true; }
  assert(threw, "a policy listing neither authors nor grants is refused");

  console.log("  OK\n");
}

// ─── Test: the requires decide which privileges are in play (§12.5) ────────
// One install path, no `role` field: what a bundle must be granted is read off
// `guest.requires` alone. The derivation cannot be pushed the wrong way — naming a
// `link/*` name puts `link` in the set and nothing takes it out — so the most permissive
// `authors` list expressible (`admitAll`) still buys an author no sockets; otherwise every
// policy test above is a lock on an open door. Driven through the assembly, because the
// derivation is the shell's — the policy tests above compose verifyBundle → admit →
// installBundle by hand and would not see it.
async function testRequiresPickThePrivileges() {
  console.log("Test: guest.requires decides which privileges a bundle must be granted");
  const { admitAll, denyAll, byPrivilege } = await imp("build/host/policy.js");

  const author = testAuthor();
  const blobWithRequires = (requires) => authorBundle(sodium, author, {
    app: "mod", version: 1,
    modules: [{ name: "fwd", wasm: forwarderBytes }],
    // The transport claims the local service id it is reached by (§12.10); an ordinary
    // app claims nothing here.
    ...(requires.includes("link") ? { services: ["_net"] } : {}),
    guestSource: GUEST_TEXT, guestRequires: requires,
  }).blob;
  // ONE predicate, with the capability set as an argument (`byPrivilege`) rather than a
  // choice between predicates. The pin names this author, so every candidate reaches the
  // predicate whose choice is being counted — a pin refusing first would zero every count.
  const mkTestShell = (base, link) => bootTestShell({
    createRealm: async () => ({ call: async () => new Uint8Array(), dispose() {} }),
    pinAuthor: author,
    admit: byPrivilege({ base, grants: { link } }),
  });
  const load = async (shell, requires) => {
    try { await shell.loadBundleBlob(blobWithRequires(requires)); return null; }
    catch (e) { return String(e); }
  };

  // 1. Which predicate was ASKED, counted rather than inferred from the outcome: a
  //    transport's outcome also depends on the driver standing, which the stub guest
  //    cannot do.
  {
    let appAsked = 0, transportAsked = 0;
    const shell = await mkTestShell(() => { appAsked++; return true; }, () => { transportAsked++; return true; });
    try {
      await load(shell, ["fs", "clock"]);
      assert(appAsked === 1 && transportAsked === 0, "a bundle reaching no privilege is governed by the base predicate");
      appAsked = transportAsked = 0;
      await load(shell, ["link"]);
      assert(transportAsked === 1 && appAsked === 0, "a bundle naming the `link/*` names is governed by the `link` grant alone");
    } finally { shell.close(); }
  }

  // 2. The direction that matters: admitAll for apps, denyAll for the transport. An
  //    author trusted for every app there is still cannot land raw links.
  {
    const shell = await mkTestShell(admitAll, denyAll);
    try {
      const err = await load(shell, ["link"]);
      assert(err !== null && /rejected by admission/.test(err),
        "a permissive author list does not admit a bundle naming the `link/*` names");
      assert(await load(shell, ["fs", "clock"]) === null, "the same shell still lands an ordinary app");
    } finally { shell.close(); }
  }

  // 3. A privilege is ONE thing, so there are no halves to claim: `link` beside ordinary
  //    app services is still governed by the `link` grant alone, never the base.
  //    Otherwise a bundle could reach sockets while falling through to the unprivileged
  //    list by mixing in an ordinary service.
  {
    const requires = ["fs", "link"];
    let appAsked = 0, linkAsked = 0;
    const shell = await mkTestShell(() => { appAsked++; return true; }, () => { linkAsked++; return true; });
    try {
      await load(shell, requires);
      assert(linkAsked === 1 && appAsked === 0,
        `${JSON.stringify(requires)} reaches the \`link\` grant, not the base`);
    } finally { shell.close(); }
  }
  console.log("  OK\n");
}

// ─── Test: node/sign is the one sign name; its scope is the slot's — the app scope for ──
// ─── an app slot, the network scope for the link slot, on EVERY load path ──────────────
// `slotSignScope` is a function of admitted facts — the node's identity, the manifest and
// the privileges it reaches — which is the whole reason it cannot drift. Driven through a
// real shell because the property is about the point where a signed manifest becomes a
// realm, and because the path that could silently lose it is the in-place UPDATE: a
// transport that re-scoped itself on upgrade would keep serving while every handshake
// with an un-upgraded peer failed as an authentication error naming nothing.
async function testSigningScopeFollowsSlot() {
  console.log("Test: node/sign is the slot's scope — app scope for an app, network scope for the link slot, on every load path");
  const { byPrivilege, admitAll } = await imp("build/host/policy.js");
  const { slotSignScope } = await imp("build/host/guest-seam.js");

  const linkAuthor = testAuthor(), appAuthor = testAuthor();
  const identity = generateKeyPair();
  const networkKey = new Uint8Array(32).fill(0x7a);
  let seam;
  // The pin is `linkAuthor`'s: it is the only author here whose bundle reaches `link`,
  // and the app author's never does, so one pin covers both loads.
  const shell = await bootTestShell({
    identity, networkKey,
    createRealm: async ({ hostCall }) => {
      seam = hostCall;
      return { call: async () => new Uint8Array(), dispose() {} };
    },
    pinAuthor: linkAuthor,
    admit: byPrivilege({ base: admitAll, grants: { link: admitAll } }),
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
  const linkApp = guestSignScope(linkAuthor.id, "linkprobe");
  try {
    // The link slot's one scope is the NETWORK scope: the channel AUTH is a fact of the
    // slot, not a second name.
    await shell.loadBundleBlob(blob(linkAuthor, "linkprobe", 1, ["node", "link"]));
    const v1 = await seam("node/sign", msg);
    assert(signs(v1, DOMAIN_LINK, networkKey, msg),
      "the link slot's node/sign signs under DOMAIN_link_scope ‖ networkKey");
    assert(!signs(v1, DOMAIN_GUEST, linkApp, msg),
      "…and never under the transport author's app scope — the slot's scope is what the name means");
    assertEqual((await seam("node/verify", concatBytes([identity.publicKey, v1, msg])))[0], 1,
      "node/verify on the link slot checks under the same network scope");

    // The path a lease would be dropped on: the standing slot is replaced in place.
    await shell.loadBundleBlob(blob(linkAuthor, "linkprobe", 2, ["node", "link"]));
    const v2 = await seam("node/sign", msg);
    assert(signs(v2, DOMAIN_LINK, networkKey, msg),
      "an in-place update of the link slot keeps the SAME network scope — an upgrade cannot re-scope a node");

    // And the other arm, on a shell that already has a link occupant: an ordinary app
    // signs under its own scope, and there is only one pair of sign names — nothing under
    // a second name to reach.
    await shell.loadBundleBlob(blob(appAuthor, "plainapp", 1, ["node"]));
    const app = await seam("node/sign", msg);
    assert(signs(app, DOMAIN_GUEST, guestSignScope(appAuthor.id, "plainapp"), msg),
      "an ordinary app's node/sign signs under DOMAIN_guest ‖ author ‖ app");
    assert(!signs(app, DOMAIN_LINK, networkKey, msg),
      "…and cannot reach the link slot's network scope");
    let refused = false;
    try { await seam("link/sign", msg); } catch { refused = true; }
    assert(refused, "there is no link/sign name — the sign pair is one names pair per slot");

    // The two arms are the one exported constructor, so a caller building a scope by hand
    // agrees with what the slot got.
    assert(bytesEqual(slotSignScope({ identity, networkKey }, linkAuthor.id, "linkprobe", ["link"]).scope, networkKey),
      "slotSignScope gives the link slot the network scope");
    assert(bytesEqual(slotSignScope({ identity, networkKey }, appAuthor.id, "plainapp", []).scope,
      guestSignScope(appAuthor.id, "plainapp")), "slotSignScope gives an app slot author ‖ app");
  } finally { shell.close(); }
  console.log("  OK\n");
}

// ─── Test: the manifest carries no seam version (§12.2, §12.4) ──────────

async function testGuestAbi() {
  console.log("Test: the seam needs no version word — it is async all the way down");

  const author = testAuthor();
  const guestText = "function handle() { return new Uint8Array([1]); }";
  const guestBytes = new TextEncoder().encode(guestText);
  const mk = (guest) => signManifest(sodium, author,
    { app: "abi", version: 1, modules: [], guest });
  const hash = toHex(gHash(guestBytes));

  // A guest declares only its hash and its requires. There is no `abi` field left to
  // get wrong or forget — the one failure the version existed to refuse (a name read
  // on the wrong side of a sync/async line) is structurally impossible when every
  // name answers a Promise.
  const verified = verifyManifest(sodium, mk({ hash, requires: [] }));
  assert(verified !== null, "a manifest with no seam version verifies");
  assert(!("abi" in verified.manifest.guest), "the verified manifest carries no abi field");

  // Every bundle declares a guest (§12.4), and a manifest without one is refused BY NAME:
  // it is what a bundle written against the retired module-only format produces.
  let noGuest = "";
  try { verifyManifest(sodium, signManifest(sodium, author,
    { app: "abi", version: 1, modules: [] })); } catch (e) { noGuest = e.message; }
  assert(noGuest.includes("every app is a guest"), `a manifest without a guest is refused by name (got: ${noGuest})`);

  // `requires` is the HOST's list and nothing else: a closed vocabulary of SERVICES
  // (§12.2), since each one is a privilege an operator grants. A finer method name asks for
  // a grant finer than the seam can enforce — the seam gates a `host.call` by the method's
  // SERVICE — and a local service id belongs in the other list entirely. Both are refused,
  // each naming the fix.
  {
    let refused = "";
    try { verifyManifest(sodium, mk({ hash, requires: ["fs/get"] })); }
    catch (e) { refused = e.message; }
    assert(refused.includes('declare the SERVICE "fs"'),
      `a manifest requiring the method "fs/get" is refused, naming the service to declare instead (got: ${refused})`);

    let local = "";
    try { verifyManifest(sodium, mk({ hash, requires: ["_backup"] })); }
    catch (e) { local = e.message; }
    assert(local.includes("guest.calls"),
      `a local service id in guest.requires is refused, naming the list it belongs in (got: ${local})`);
  }
  // …and the SERVICE, by exact name, is what a manifest may require — the guest still
  // calls the finer-grained method; being undeclarable at that granularity is not being
  // unavailable.
  assert(verifyManifest(sodium, mk({ hash, requires: ["fs"] })) !== null,
    "a service, by exact name, is what a manifest may require");

  // A called id colliding with this bundle's OWN module name is refused: the seam's
  // dispatch resolves a declared local service before this bundle's modules, so a
  // collision would silently shadow the module (guest-seam.ts). A called id spelled like a
  // host method is refused for the mirror reason.
  {
    const withModule = (calls) => signManifest(sodium, author, {
      app: "abi", version: 1,
      modules: [{ name: "codec", hash: "aa" }],
      guest: { hash, requires: [], calls },
    });
    let refused = "";
    try { verifyManifest(sodium, withModule(["codec"])); } catch (e) { refused = e.message; }
    assert(refused.includes("codec") && refused.includes("module"),
      `a called local service id colliding with this bundle's own module name is refused (got: ${refused})`);
    assert(verifyManifest(sodium, withModule([])) !== null,
      "…and the same module name is fine when nothing calls a service by it too");
    let shadow = "";
    try { verifyManifest(sodium, withModule(["fs/get"])); } catch (e) { shadow = e.message; }
    assert(shadow.includes('"fs" service'),
      `a called id spelled like a host method is refused (got: ${shadow})`);
  }

  // Any OTHER bare or slashed name is a legitimate LOCAL service id (§12.10): the
  // vocabulary is open on that half, since whether anything actually claims it is answered
  // at the call, never at the manifest.
  assert(verifyManifest(sodium, mk({ hash, requires: [], calls: ["_backup", "reporting/v2"] })) !== null,
    "an arbitrary called local service id verifies; nothing claiming it yet is not a manifest error");

  console.log("  OK\n");
}

// ─── Test: safe-js zero-authority JS confinement (§2.1) ─────────────────
// Run zero-authority guest JS over a single host-call seam. Three load-bearing properties,
// over stand-in seams: airtight by construction, the async seam + byte boundary, and realm
// isolation.

async function testSafeJs() {
  console.log("Test: safe-js — zero-authority JS confinement (§2.1)");

  // 1. Airtight: the guest cannot name fs/net/Bun/process/fetch/require, and
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

  // 2. The seam: a sync name returns bytes directly (no yield); a net-like name returns a
  //    real Promise the guest awaits. Bytes round-trip across the copy boundary both ways.
  {
    let hostCalls = 0;
    const hostCall = (name, payload) => {
      hostCalls++;
      if (name === "inc") return payload.map((b) => (b + 1) & 0xff);                          // sync name — bytes directly
      if (name === "slow") return sleep(3).then(() => payload.map((b) => (b + 1) & 0xff));     // net-like name — a Promise
      return new Uint8Array();
    };
    const src = `
      function handle(a) {
        const sel = a[0], arg = a.subarray(1);
        if (sel === 1) return host.call("inc", arg);                  // sync name: host.call returns bytes, no await
        if (sel === 2) return (async () => await host.call("slow", arg))();  // net-like name: a genuinely awaited Promise
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

  // 3. Orchestration control-flow shapes run as ordinary async guest JS, including a
  //    concurrent fan-out with the guest's own Promise.all over a net-like name — the
  //    real-promise seam is what makes this possible in one realm.
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
        // Fan out OFFERs concurrently — the guest's own Promise.all, no host sendMany.
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
// One way in, `call`, which may yield. That one invocation runs to completion before the
// next begins is the realm's own FIFO queue (host/realm-queue.ts) rather than a property
// of the host's call stack — which is what a synchronous entry used to give for free.

async function testRealmSerialization() {
  console.log("Test: one entry seam, serialized per realm (§12.3)");

  // 1. A synchronous entrypoint over a synchronous seam still round-trips, and the
  //    realm is reusable — it just resolves through a promise like everything else.
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

  // 2. An invocation accepted while another is parked mid-await waits for the queue
  //    rather than interleaving. Worth its head-of-line cost: two frames resuming into
  //    each other at every await is state no guest author can reason about.
  {
    let release;
    const gate = new Promise((r) => { release = r; });
    const hostCall = (name, payload) => {
      if (name === "park") return gate.then(() => new Uint8Array([42]));   // parks until released
      if (name === "inc") return payload.map((b) => (b + 1) & 0xff);       // sync — holder path
      return new Uint8Array();
    };
    const realm = await createSafeRealm({
      source: `function handle(a) {
                 if (a[0] === 1) return (async () => await host.call("park", new Uint8Array()))();
                 if (a[0] === 2) return host.call("inc", a.subarray(1)); // sync — holder path
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

  // 3. Still airtight — the one seam is the same zero-authority sandbox.
  {
    const realm = await createSafeRealm({
      source: `function handle() { return new Uint8Array([typeof globalThis.process === "undefined" ? 0 : 1, typeof globalThis.fetch === "undefined" ? 0 : 1]); }`,
      hostCall: async () => new Uint8Array(),
    });
    const r = await realm.call(new Uint8Array());
    assertEqual([...r], [0, 0], "process / fetch are unreachable from an entrypoint");
    realm.dispose();
  }

  // 4. Disposing a realm while an invocation is parked mid-await — the ordinary state of
  //    a node whose initiator waits on the network — fails the parked caller and frees
  //    the context WITHOUT taking the wasm module with it: the engine asserts an empty gc
  //    object list when a runtime is freed, and a parked call releases its handle from a
  //    `finally` that runs as a microtask after dispose() returns, so freeing the context
  //    in the same turn aborts the whole module. Hence the deferred teardown, pinned here.
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

    // A realm built after the deferred teardown has run proves the module survived it.
    await sleep(1);
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

// ─── Test: PR-review hardening — seam gating, guarded callModule, ───────
// ─── sender-bound responses, WS fragmentation, redial after failure ──────

async function testSeamGating() {
  console.log("Test: the guest seam enforces the manifest's declared requires + allocation caps");

  const id = generateKeyPair();
  const stubTransport = { request: async (_peer, _proto, _payload) => new Uint8Array() };
  const mk = (names) => createGuestSeam({
    platform: { sodium, identity: id, now: () => Date.now(), peers: () => [] },
    grants: { names, signScope: appSignScope(id, new Uint8Array(32), "probe"), transport: stubTransport, fs: new MemoryFs(), calls: TEST_CALLS, timers: TEST_TIMERS },
    modules: { names: new Set(), call: async () => ({ bytes: null, ms: 0 }) },
  });
  const U = (...xs) => new Uint8Array(xs);
  let threw = false;

  // A residual HOST TRANSFORM is exempt from the gate by rule: `crypto/` reaches
  // nothing, so there is nothing to grant. A seam built for a bundle declaring NO
  // names still hashes.
  const clockOnly = mk(["clock"]);
  assertEqual((await clockOnly("crypto/blake2b-256", U(1, 2))).length, 32,
    "crypto/blake2b-256 resolves for a bundle declaring no crypto name — a pure transform is not a grant");
  threw = false;
  try { await clockOnly("crypto/no-such-primitive", U(1)); } catch { threw = true; }
  assert(threw, "an unknown crypto name is refused by name (this host cannot serve it)");
  // A bare name is the asking bundle's own module map — code it already holds, scoped by
  // the app key the seam was built with — so it passes the gate under an empty requires
  // set. This seam's `hasModule` says no, so it is refused for NOT EXISTING rather than
  // for not being declared, and the message is the assertion.
  let gateMsg = "";
  try { await clockOnly("echo", U(1, 120)); } catch (e) { gateMsg = e.message; }
  assert(gateMsg.includes("no module by that name"),
    `a bare name passes the gate ungated and fails only on existence (got: ${gateMsg})`);

  // Grants are gated by SERVICE, not by method: declaring `clock` resolves `clock/now`,
  // and a different, undeclared service is still refused beside it.
  threw = false;
  try { await clockOnly("node/sign", U(1)); } catch { threw = true; }
  assert(threw, "an undeclared service (node) is refused by the seam");
  threw = false;
  try { await clockOnly("fs/delete", U(120)); } catch { threw = true; }
  assert(threw, "an undeclared service (fs) is refused by the seam");
  threw = false;
  try { await clockOnly("clock/now", U()); } catch { threw = true; }
  assert(!threw, "clock/now resolves under the declared service");

  // The unit a manifest grants is the WHOLE service: declaring `node` grants every
  // `node/*` method — `node/identity` beside `node/sign` included — because there was
  // never a finer boundary anyone held (§12.2).
  const nodeOnly = mk(["node"]);
  assertEqual((await nodeOnly("node/sign", U(1, 2))).length, 64, "node/sign resolves under the declared service");
  assertEqual((await nodeOnly("node/identity", U())).length, 32, "…and so does node/identity, the SAME declared service");
  threw = false;
  try { await nodeOnly("fs/get", U(120)); } catch { threw = true; }
  assert(threw, "a different, undeclared service (fs) is still refused beside the declared one");

  // Declaring the method's exact STRING is not declaring its service: the gate checks
  // `serviceOf(name)` against the declared set, so a manifest naming `node/sign` (rather
  // than `node`) grants nothing at all — `requires` speaks in services.
  const methodNameOnly = mk(["node/sign"]);
  threw = false;
  try { await methodNameOnly("node/sign", U(1, 2)); } catch { threw = true; }
  assert(threw, "declaring a method's exact name, not its service, grants nothing");

  // Guest-controlled allocation caps. Tests that exercise the full catalog name every
  // host service explicitly; omitting grants.names entirely still throws (§12.2).
  const open = mk(ALL_HOST_SERVICES);
  let omitted = false;
  try { mk(undefined); } catch { omitted = true; }
  assert(omitted, "omitting grants.names throws rather than granting every name");
  assertEqual((await open("node/random", U(0, 0, 4, 0))).length, 1024, "node/random under the cap works");
  threw = false;
  try { await open("node/random", U(0xff, 0xff, 0xff, 0xff)); } catch { threw = true; }
  assert(threw, "node/random over the cap is refused");

  // The vocabulary is closed at LOAD, not at first use: an unknown name in a manifest is
  // a refused bundle (verifyManifest), and the seam answers "no such name" besides.
  threw = false;
  try { await open("transform/do", U()); } catch { threw = true; }
  assert(threw, "`transform` is gone from the vocabulary — a manifest naming it is refused");

  console.log("  OK\n");
}

async function testCallModuleGuards() {
  console.log("Test: ModuleTable.callModule resolves by name, or null when unbound (§4)");

  const { makeHost } = await import("./fixtures.mjs");
  const { host } = await makeHost();
  const { publicKey: pk } = generateKeyPair();
  const guards = appKey(pk, "guards");

  // An unbound module resolves to null, distinct from an empty response — and so does a
  // module under an app that was never installed: neither is a thing that exists.
  assert(await host.callModule(guards, "missing", new Uint8Array([1])) === null,
    "callModule returns null for an unbound module");
  assert(await host.callModule(appKey(pk, "nope"), "echo", new Uint8Array([1])) === null,
    "callModule returns null for an app that installed nothing");

  // An installed module is reached by name. A confined guest reaches the same module
  // through the guest seam by its bare name (§12.2).
  await installMod(host, guards, "echo", forwarderBytes);
  const r = await host.callModule(guards, "echo", new Uint8Array([5]));
  assertEqual([...r], [5], "callModule reaches an installed module");

  // A 0-length response is a valid EMPTY answer, not the null of an unbound name, so a
  // caller can tell "module ran, said nothing" from "nothing there".
  const empty = await host.callModule(guards, "echo", EMPTY);
  assert(empty !== null && empty.length === 0,
    "an empty response is an empty array, distinct from null");

  // The worker copies a result out before erasing scratch. This probe's second call
  // returns the first call's old span without rewriting it, so any staged secret left in
  // the long-lived instance would come straight back here.
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

// ─── Test: a module call is bounded — the §4.3 compute residual, closed ──────────
// The JS platform's WebAssembly exposes no fuel or timeout, so a module call in the host
// thread that never returned would wedge the node irrecoverably — a restart would
// re-trigger it from the same inbound frame. The worker-per-module table closes that: a
// spinning module answers EMPTY at its deadline, the host thread stays alive, and a fresh
// instance serves the next call.
async function testModuleCallBound() {
  console.log("Test: a spinning module is killed at its deadline and respawned (§4.3)");

  const { ModuleTable } = await imp("build/host/module-table.js");
  const { SPIN_WASM } = await import("./fixtures/spin-wasm.mjs");
  const { testHost } = await import("./fixtures.mjs");
  const { publicKey: pk } = generateKeyPair();
  const spinKey = appKey(pk, "spin");

  // The default table bound is generous; a bounded host is the deployment's number. The
  // call's OWN deadline is what a guest's call carries — the guest's remaining segment.
  const host = testHost(new ModuleTable({ deadlineMs: 60_000 }));
  await host.bindAll(spinKey, [{ name: "spin", wasm: SPIN_WASM }]);
  assert(host.isBound(spinKey, "spin"), "the spinning module binds (its memory is bounded at admission)");

  // The host thread is never blocked: timers keep firing while the module spins in its
  // worker. Running the call in this thread would let a spinner wedge everything,
  // transport included.
  let heartbeats = 0;
  const beats = setInterval(() => heartbeats++, 25);

  const t0 = Date.now();
  // A 120 ms bound. Null at the table — exactly what a trap produces — which the guest
  // seam reads as empty BYTES, so nothing downstream changes.
  const r = await host.callModule(spinKey, "spin", new Uint8Array([1]), 120);
  const spent = Date.now() - t0;
  clearInterval(beats);

  assert(r === null, "the spin answers like a trap — null at the table, empty bytes at the seam");
  assert(spent >= 100 && spent < 3000, `it is killed near its bound, not eventually (${spent}ms)`);
  assert(heartbeats > 0, "the host thread was alive the whole time the module spun");

  // A fresh instance serves the next call: the kill terminated the old worker and a
  // respawn stands a new one in, statics gone.
  await host.bindAll(spinKey, [{ name: "spin", wasm: forwarderBytes }]);
  const echo = await host.callModule(spinKey, "spin", new Uint8Array([9]), 1000);
  assertEqual([...echo], [9], "a module called again after a kill-and-respawn still runs");

  // Two calls to the SAME module cannot run at once: the table keeps one in flight per
  // module (§3, "one transform at a time"), so a spinner burns one core for one bound.
  const host2 = testHost(new ModuleTable());
  await host2.bindAll(spinKey, [{ name: "spin", wasm: SPIN_WASM }]);
  const t1 = Date.now();
  const [a, b] = await Promise.all([
    host2.callModule(spinKey, "spin", new Uint8Array(), 80),
    host2.callModule(spinKey, "spin", new Uint8Array(), 80),
  ]);
  const serial = Date.now() - t1;
  assert(a === null && b === null,
    "both spins answered like traps, at their own deadlines");
  assert(serial >= 140 && serial < 5000, `the two calls ran one after the other (${serial}ms)`);
  // …and the module still answers after two kills in a row, on ONE worker: the respawn a
  // kill starts and the respawn the queued call would start are the same load
  // (`ModuleTable.respawn`), and two loads per kill would leak an idle never-terminated
  // worker (invisible: an unref'd worker is absent from `getActiveResourcesInfo`).
  await host2.bindAll(spinKey, [{ name: "spin", wasm: forwarderBytes }]);
  const after = await host2.callModule(spinKey, "spin", new Uint8Array([3]), 1000);
  assertEqual([...after], [3], "the module answers on its one respawned worker after two kills");
  host2.removeApp(spinKey);

  // An unbounded call is an operator's explicit opt-out: Infinity disables the bound,
  // and the worker then spins until the app is dropped — the host stays responsive, and
  // dropping the app settles the in-flight call as empty rather than stranding it.
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
// "Charged to the calling guest's budget" (§4.3) made literal: the realm computes the
// caller's remaining execution segment at the moment of the call and hands it to the
// module as the call's deadline. A guest that has already spent most of its budget gets
// a module call killed far sooner than the deployment's default bound.
async function testModuleCallChargedToGuestBudget() {
  console.log("Test: a module call is charged to the calling guest's remaining segment (§4.3)");

  const { ModuleTable } = await imp("build/host/module-table.js");
  const { SPIN_WASM } = await import("./fixtures/spin-wasm.mjs");
  const { createGuestSeam } = await imp("build/host/guest-seam.js");
  const { createSafeRealm } = await imp("build/host/safe-js.js");
  const { testHost } = await import("./fixtures.mjs");
  const id = generateKeyPair();

  const host = testHost(new ModuleTable({ deadlineMs: 60_000 }));
  const spinKey = appKey(id.publicKey, "app");
  await host.bindAll(spinKey, [{ name: "spin", wasm: SPIN_WASM }]);
  const seam = createGuestSeam({
    platform: { sodium, identity: id, now: () => Date.now() },
    grants: { names: ALL_HOST_SERVICES, calls: TEST_CALLS, timers: TEST_TIMERS },
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
  // The burn is ~4.9s, so the whole call is ~5s; the module itself died at the ~100ms
  // that remained, NOT at the table's 60s default — a broken deadline flow would hang
  // this call for a minute instead.
  assert(spent >= 4800 && spent < 8000,
    `the call died with the guest's remaining budget, not the table's (${spent}ms)`);

  // The other half of "charged": what a module BURNS is billed back to the segment that
  // called it, and a segment with nothing left refuses the next call. Both halves are
  // needed — the guest is parked while the module runs, so its own spend advances by
  // microseconds per turn, and QuickJS's interrupt is consulted per bytecode, of which
  // this guest executes almost none between parks.
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
// There is no seam version to refuse a guest written against the old calling convention,
// because there is no old convention left to be written against: every name — crypto
// included — answers a Promise. The invariant worth pinning is the one the version used
// to buy: `host.call` NEVER resolves to bytes in the calling turn. A guest that forgets
// the await reads a Promise where bytes were expected, and this test makes that shape
// loud instead of silent.
async function testPreviousAbiRefused() {
  console.log("Test: every host.call answers a Promise — no name sits on a sync line");

  const NAMES = ["crypto/blake2b-256", "clock/now", "node/identity", "node/random"];
  // One byte per probed name: 1 when the un-awaited call handed back a thenable.
  const source = `
    const names = ${JSON.stringify(NAMES)};
    function handle() {
      const out = new Uint8Array(names.length);
      for (let i = 0; i < names.length; i++) {
        const r = host.call(names[i], new Uint8Array(4));
        out[i] = typeof r.then === "function" ? 1 : 0;
      }
      return out;
    }`;
  const realm = await createSafeRealm({
    source,
    hostCall: createGuestSeam({
      platform: { sodium, identity: generateKeyPair(), now: () => 1 },
      grants: { names: ALL_HOST_SERVICES, calls: TEST_CALLS, timers: TEST_TIMERS },
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
  console.log("Test: concurrent call()s on one safe-js realm interleave without __arg clobber");

  // No Asyncify, so overlapping initiator calls are allowed to run concurrently. Each
  // call stages __arg and consumes it synchronously (before the first await) during its
  // evalCode, so a second call staging __arg can never corrupt the first's captured arg —
  // no host-side serialization needed.
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

// ─── Run ────────────────────────────────────────────────────────────────

await testOneRawLinkOwner();
await testGuestSeam();
await testPolicy();
await testRequiresPickThePrivileges();
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

summary("Results");
