// guest-seam — THE seam (exported as `seedkernel-wasm/guest-seam`): the one
// implementation of `host.call(name, bytes)` a realm is wired with, and therefore the
// whole of a guest's view of the host. There is no "bridge" object standing between the
// shell and the guest with a foot on each side; there is a realm, and there is the
// function it calls out through. The shell owns admission, the module table, realm
// lifecycle and dispatch (shell-core.ts); this file owns what a realm may *utter*.
//
// It is a pure function of three things, and the split is the ownership:
//
//   platform — per NODE:  crypto (sumo), the node identity, the clock.
//   grants   — per REALM: exactly what this realm may reach — the names its manifest
//              declared, the scope its signatures are bound to, and the backends behind
//              the gated names (fs, sockets, timers, and the routing a `_`-led id
//              resolves through).
//              Nothing is reachable that is not wired here, which is the whole of §1's
//              capability-by-non-wiring: a realm holding no `rawNet` cannot acquire one.
//   modules  — per APP:   this bundle's own WASM modules, by their logical names.
//
// Every name is application-neutral — the seam has no idea it is hosting storage (or
// chat, or anything). All structure — content addressing, descriptor envelopes, the
// HAVE/OFFER/STORE wire format, Reed–Solomon, the nonce convention — is the guest's
// business, built on top of these.
//
// This is what lets the seedkernel shell run an arbitrary signed guest: it wires a seam
// from host primitives it already holds (README §12.2). A host-side caller that holds
// the same primitives wires the identical seam, so output orchestrated through the
// confined guest is byte-compatible with a host-side reference path.
import { concatBytes, writeU32BE, readU32BE, enc, dec } from "../core/util.js";
import { DOMAIN_GUEST, DOMAIN_CHANNEL, AUTHORITY_CALLS, PRIMITIVE_NAMES, isGrant, isReservedProtocol, type PrimitiveName, type CapabilityName } from "../core/domains.js";
import { type Fs } from "../core/fs.js";

/** What `node/sign` signs under — and what `node/verify` checks against — derived by
 *  the host from which admission point the asking bundle came through, never from
 *  anything the guest says (§12.2).
 *
 *  **The host prefixes; it does not parse.** It signs `domain ‖ scope ‖ msg` where `msg`
 *  is opaque bytes the guest chose and the host never reads, and it verifies the same
 *  preimage for the key a caller names. The guarantee — this key signs channel
 *  transcripts and never app data, an app's data and never another app's — rides
 *  entirely on the prefix, which is what domain separation is for. A host that instead
 *  validated the *fields* of what it signed would have pinned one protocol's design
 *  into the core and bought nothing: a hostile transport already holds everything the
 *  transport touches.
 *
 *  `key` is part of the scope because the admission point supplies it too — the node's
 *  one identity, whichever slot asks (core/subkeys.ts), so a signature a peer receives
 *  verifies under the peer id the handshake already authenticated. `node/verify` takes the
 *  verifying key from its argument bytes, so only the `domain` and `scope` halves bind a
 *  verification — a guest can check a signature under its own bundle's namespace, never
 *  another's. */
export interface SignScope {
    /** Domain tag — `DOMAIN_guest` for an app, `DOMAIN_channel` for the transport. */
    domain: Uint8Array;
    /** Scope bytes under the domain: `author ‖ app` for an app, the network key for the
     *  transport. */
    scope: Uint8Array;
    /** The keypair that signs. */
    key: {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    };
}

/** The libsodium surface the crypto names use — structural so any sumo build
 *  (the host's bundled `libsodium-wrappers-sumo`) satisfies it. */
export interface SeamCrypto {
    crypto_generichash(hashLength: number, message: Uint8Array): Uint8Array;
    crypto_stream_xchacha20_xor(message: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;
    crypto_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
    crypto_sign_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
    randombytes_buf(n: number): Uint8Array;
    crypto_aead_chacha20poly1305_ietf_encrypt(message: Uint8Array, additional_data: Uint8Array | null, secret_nonce: Uint8Array | null, public_nonce: Uint8Array, key: Uint8Array): Uint8Array;
    crypto_aead_chacha20poly1305_ietf_decrypt(secret_nonce: Uint8Array | null, ciphertext: Uint8Array, additional_data: Uint8Array | null, public_nonce: Uint8Array, key: Uint8Array): Uint8Array;
    crypto_scalarmult(sk: Uint8Array, pk: Uint8Array): Uint8Array;
    ml_kem768_keypair_from_seed(seed: Uint8Array): {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    };
    ml_kem768_encaps(pk: Uint8Array, coins: Uint8Array): {
        ciphertext: Uint8Array;
        sharedSecret: Uint8Array;
    } | null;
    ml_kem768_decaps(sk: Uint8Array, ct: Uint8Array): Uint8Array | null;
}

/** Reach another realm by a RESERVED protocol id (`_`-led, core/domains.ts) — the one
 *  cross-realm call, and the same mechanism the host uses to dispatch an inbound frame.
 *
 *  There is no transport-shaped interface here and no `net` domain, because the network
 *  is not a host service: it is a bundle that claims `_net`, reached exactly as an app
 *  claiming `chat-v1` is reached. What the caller sends is opaque to the host, and what
 *  it gets back is whatever the callee's `handle` returned. The host's whole contribution
 *  is attribution — it prepends the CALLER's app key, as it prepends the sender's key
 *  inbound — and resolution: which realm claims this id right now.
 *
 *  `null` when nothing claims the id, which the seam turns into a refusal by name rather
 *  than a promise that never settles. The shell satisfies this (`shell-core.ts`), and it
 *  answers `_host` itself rather than routing it (§12.10). */
export interface SeamCalls {
    call(id: string, payload: Uint8Array): Promise<Uint8Array> | null;
}

/** The RAW net capability (README §12.1) — the socket-side twin of `Fs`, and the whole
 *  of what the platform contributes to the network.
 *
 *  Every method is bytes over an opaque link id the host minted. There is no peer, no
 *  ordering above the channel's own, no framing and no attribution: those are state
 *  machines over whole messages, which the endpoints can implement and therefore do
 *  (the transport bundle). What has no substitute is moving the bytes.
 *
 *  **Nothing here may re-enter the guest realm.** The transport calls these from
 *  inside an entrypoint, so anything that would call back into the realm has to reach it
 *  on a later turn — which every implementation does anyway, because a socket does not
 *  deliver during the write that provoked it. */
export interface RawNet {
    /** Open a link to an opaque destination name, returning the link id — or 0 when the
     *  host has no route for it, which a caller treats exactly as a fabric dropping a
     *  frame. The host resolves the name in the address book it was configured with; the
     *  caller learns no route it could dial for itself — only which wire codec applies
     *  to the link the host has ALREADY opened (`framing`) and, for a dialed WebSocket,
     *  the authority to put in its `Host` header (socket-seam.ts `RawLink`). */
    open(dest: Uint8Array): { linkId: number; framing: number; authority: string };
    /** Write whole bytes to a link. Silently dropped if the link is already gone —
     *  a caller cannot distinguish that from the far end vanishing mid-write anyway. */
    send(linkId: number, bytes: Uint8Array): void;
    /** Tear a link down. `graceful` asks the channel to flush already-written bytes
     *  first (socket-seam.ts `RawLink.close`). */
    close(linkId: number, graceful: boolean): void;
    /** Bytes written to this link that are not yet on the wire (socket-seam.ts
     *  `RawLink.buffered`). Optional: a host whose channels cannot say omits it,
     *  and the transport's stall clock degrades to a plain deadline. */
    buffered?(linkId: number): number;
}

/** The platform's event loop, as the one thing a zero-authority realm cannot do for
 *  itself: there is no `setTimeout` in a fresh QuickJS context. `id` is the guest's own,
 *  so the host keeps no name of its own for a deadline.
 *
 *  **The implementer bounds how many deadlines a guest may hold at once**, because the
 *  table of live timers is its memory to spend — the same rule that puts an inbound
 *  flood cap with whoever holds the descriptor. */
export interface HostTimers {
    /** Arm (or re-arm) `id` to fire the guest's `timer` entrypoint in `ms`. Refuse, by
     *  throwing, past whatever bound the implementation sets on live timers. */
    arm(id: number, ms: number): void;
    clear(id: number): void;
}

/** Per-NODE facts every realm on this host shares. Nothing here is a grant — a realm
 *  holds these because it is running on this node at all — so nothing here is gated. */
export interface SeamPlatform {
    sodium: SeamCrypto;
    /** This node's node keypair (README §12.1): IDENTITY returns its pk. Which key
     *  SIGN uses is `grants.signScope.key`, chosen by the slot — not this. */
    identity: {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    };
    /** Wall clock (ms). Defaults to Date.now. */
    now?: () => number;
}

/** Per-REALM: exactly what THIS realm may reach. The set of names it may utter, the
 *  scope its signatures are bound to, and the backends behind the gated names.
 *
 *  Two mechanisms, and both are here because they are the same decision seen twice: a
 *  name outside `names` is refused, and a backend that was never wired cannot be reached
 *  whatever the manifest says. The second is the load-bearing one (README §1,
 *  capability-by-non-wiring) — a realm handed no `rawNet` cannot acquire one at any point
 *  in the process's life — and the first is what makes an undeclared name a refusal by
 *  name rather than a null backend surfacing later as a confusing failure. */
export interface SeamGrants {
    /** The allowed names, EXACTLY the manifest's declared `guest.requires` (README
     *  §12.2). Any `host.call` naming an authority outside this set is refused — so
     *  a guest reaches exactly what its bundle declared, name by name, and nothing
     *  else. Names that are not authorities (`isGrant`) pass regardless: they are
     *  never grants. Required: pass `UNRESTRICTED_NAMES` to opt out deliberately (a
     *  host-side caller that holds the primitives anyway). */
    names: Iterable<string> | typeof UNRESTRICTED_NAMES;
    /** What SIGN signs and VERIFY checks under, derived by the host from the asking
     *  bundle's slot (`appSignScope` / `transportSignScope`). Both bind every
     *  signature to `domain ‖ scope ‖ msg` and read none of `msg`; without a scope
     *  both are unavailable, because guest signing and scoped verification are never
     *  raw. A host-side caller that never exposes them may omit it. */
    signScope?: SignScope;
    /** Raw-byte fs backend, already scoped to this app's keyspace by the shell
     *  (`scopedFs`). Optional: a node that only initiates never reads it. */
    fs?: Fs;
    /** The RAW net capability — sockets behind opaque link ids. Wired ONLY for a bundle
     *  that reaches the `link` privilege: a confined module holds no ambient authority by
     *  construction, so nothing else can ever reach a descriptor no matter what has already
     *  been installed (README §1, capability-by-non-wiring). */
    rawNet?: RawNet;
    /** The platform's event loop, for a guest that declares `timer`. */
    timers?: HostTimers;
    /** The cross-realm call: how a `_`-led name in `names` is answered. Wired for every
     *  realm, because reaching one is a grant like any other and the gate above is what
     *  decides who holds it — a realm declaring no reserved id can utter none, whatever is
     *  wired. Absent only for a host-side caller with no routing to resolve against. */
    calls?: SeamCalls;
}

/** Per-APP: this bundle's OWN WASM modules, by the logical names its manifest declared.
 *
 *  Not a grant and not gated — the code was installed and verified with the guest, so
 *  calling one reaches nothing the guest does not already hold. The shell binds the app
 *  key when it wires the seam (`ModuleTable`), so what arrives here is already scoped:
 *  there is no logical→table map to pass and no opt-out sentinel, because the guest's
 *  namespace and the app's module map are the same map. "A guest reaches only its own
 *  modules" is the shape rather than a lookup that could be omitted. */
export interface SeamModules {
    /** Reach one of this app's modules. A guest calls it through the SAME `host.call` as
     *  everything else, by the bare logical name (§12.2); the dispatch knows a bare name
     *  is one of these because no host name is bare. */
    call: (name: string, payload: Uint8Array) => Uint8Array | null;
    /** Whether this app declares a module by that name. It exists to keep ONE error
     *  surface over the unified catalog: an unknown name is refused whichever half it
     *  would have come from. It cannot be read off `call`, whose `null` also means a trap
     *  or an oversized payload — a module that FAILS still answers empty, as it always
     *  has, and only a name that was never installed is a refusal. */
    has: (name: string) => boolean;
}

/** Everything the seam needs, in the three groups that own it. */
export interface GuestSeamDeps {
    platform: SeamPlatform;
    grants: SeamGrants;
    modules: SeamModules;
}

/** What the seam IS — the host half of `host.call`, and what `createGuestSeam` below
 *  returns. `name` addresses a host capability by its opaque name; `payload` and the
 *  return are opaque bytes, exactly like the table's `callModule(name, payload) -> bytes`.
 *  A sync name returns bytes directly; a round-tripping one — `net/send` and every
 *  `fs/*` — returns a Promise the guest awaits (§12.2).
 *
 *  It is declared HERE, beside the names it can carry, rather than in the realm that
 *  runs against it: a realm factory (safe-js.ts, native-shim.ts) is a *consumer* of the
 *  seam, and the signature of what this file produces is not a consumer's to own. Both
 *  factories import it from here, so the dependency runs one way. */
export type HostCall = (name: string, payload: Uint8Array) => Promise<Uint8Array> | Uint8Array;

/** The version of the seam defined below — re-exported so a reader of the seam finds it
 *  beside them, and so `seedkernel-wasm/guest-seam` is the import a bundle builder
 *  reaches for (it is stamping "which host contract is this guest written against",
 *  which is this file's subject). It is DECLARED in domains.ts, with the suite ids, so
 *  the loader can check a manifest's `guest.abi` without importing the seam —
 *  see the note there. Anything that changes what an existing name returns bumps it. */
export { GUEST_ABI_VERSION, SUPPORTED_GUEST_ABIS, PRIMITIVE_NAMES } from "../core/domains.js";
/** The `crypto/` members of the catalog — the template literal over `PRIMITIVE_NAMES`,
 *  so the vocabulary a manifest is checked against and the table the seam dispatches
 *  through cannot drift: adding a primitive to one without the matching key in the
 *  other is a type error. */
type CryptoName = `crypto/${PrimitiveName}`;
/** The keys the dispatch table must cover — every authority (`CapabilityName`, the keys
 *  of `AUTHORITY_CALLS` in domains.ts) and every crypto primitive. The table literal is
 *  typed against this union, so the names are written in exactly ONE place: a name added
 *  to the vocabulary without a handler here is a compile error, and so is a handler whose
 *  name the loader would refuse.
 *
 *  **Every one of them contains a `/`, and that is load-bearing** (§12.2). A bundle's
 *  module names are held to `[A-Za-z0-9_-]` by the manifest (bundle.ts), so they cannot
 *  spell one of these — which is what lets a guest call its own modules by their bare
 *  logical name through the same `host.call` and lets the dispatch tell the two apart by
 *  the name alone. The construction check below holds the invariant on the host side;
 *  `PRIMITIVE_NAMES` gets it from the `crypto/` template literal, and `AUTHORITY_CALLS`
 *  is hand-written, which is exactly the half that needs checking. */
type HandlerKey = CapabilityName | CryptoName;
/** The same union as a runtime list, for the construction check below — the compiled-JS
 *  half of the one-file rule, where `HandlerKey` is not present to enforce anything.
 *  Derived here, next to the table it describes, because it is nobody else's business:
 *  the loader's vocabulary is `AUTHORITY_CALLS` alone (a manifest never names the rest). */
const HANDLER_KEYS: readonly string[] = [
    ...Object.keys(AUTHORITY_CALLS),
    ...PRIMITIVE_NAMES.map((p) => `crypto/${p}`),
];
/** One catalog entry's implementation: argument bytes in, response bytes out (or a
 *  Promise of them, for the round-tripping `net/send` and `fs/*` names). */
type SeamHandler = (payload: Uint8Array) => Uint8Array | Promise<Uint8Array>;
/** The primitive half of the catalog (§12.1): a flat name→transform map. Every entry
 *  is a pure function of its argument bytes — no host key, no entropy, no state — so
 *  nothing gates it, and a new algorithm is a catalog entry rather than an op number
 *  or an ABI rev (a host that lacks one refuses the load by name, bundle.ts). */
function cryptoCatalog(sodium: SeamCrypto): Record<CryptoName, SeamHandler> {
    return {
        "crypto/blake2b-256": (a) => sodium.crypto_generichash(32, a),
        "crypto/ed25519/verify": (a) => {
            const pk = a.slice(0, 32), sig = a.slice(32, 96), msg = a.slice(96);
            try {
                return sodium.crypto_sign_verify_detached(sig, msg, pk) ? ONE : ZERO;
            }
            catch {
                return ZERO;
            }
        },
        "crypto/xchacha20/xor": (a) => sodium.crypto_stream_xchacha20_xor(a.slice(56), a.slice(0, 24), a.slice(24, 56)),
        "crypto/chacha20poly1305-ietf/seal": (a) => sodium.crypto_aead_chacha20poly1305_ietf_encrypt(a.slice(44), null, null, a.slice(0, 12), a.slice(12, 44)),
        "crypto/chacha20poly1305-ietf/open": (a) => {
            try {
                const pt = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, a.slice(44), null, a.slice(0, 12), a.slice(12, 44));
                return concatBytes([ONE, pt]);
            }
            catch {
                return ZERO;
            }
        },
        // [sk 32][pk 32] -> [ok u8][shared 32]. ok=0 is a low-order point, which libsodium
        // refuses rather than returning an all-zero shared secret. Against the X25519 base
        // point (9 ‖ 0×31) this is also the public-key derivation, so no separate name.
        "crypto/x25519/dh": (a) => {
            try {
                return concatBytes([ONE, sodium.crypto_scalarmult(a.slice(0, 32), a.slice(32, 64))]);
            }
            catch {
                return ZERO;
            }
        },
        // ── ML-KEM-768 (FIPS 203), from mlkem768.wasm on every target (kem.ts,
        // native/mlkem.go). Derandomized, so the entries stay pure functions of their
        // arguments and the entropy grant stays in `node/random` where it belongs.
        //
        // [seed 64] -> [pk 1184][sk 2400]. The seed is FIPS 203's `d ‖ z`; a caller
        // supplies 64 bytes of node/random.
        "crypto/ml-kem-768/keypair": (a) => {
            const kp = sodium.ml_kem768_keypair_from_seed(a.slice(0, 64));
            return concatBytes([kp.publicKey, kp.privateKey]);
        },
        // [pk 1184][coins 32] -> [ok u8][ct 1088][ss 32]. ok=0 is a public key that
        // fails the modulus check of §7.2 — the same shape x25519/dh uses for a
        // low-order point, and for the same reason: a peer's key is not the caller's to
        // trust, so "unusable" has to be answerable without an exception.
        "crypto/ml-kem-768/encaps": (a) => {
            const r = sodium.ml_kem768_encaps(a.slice(0, 1184), a.slice(1184, 1216));
            return r ? concatBytes([ONE, r.ciphertext, r.sharedSecret]) : ZERO;
        },
        // [sk 2400][ct 1088] -> [ok u8][ss 32]. ok=0 is a SECRET KEY that fails the hash
        // check of §7.3, never a bad ciphertext: ML-KEM answers those with a shared
        // secret derived from the key's own z, in constant time, and distinguishing that
        // from success is the oracle implicit rejection exists to deny.
        "crypto/ml-kem-768/decaps": (a) => {
            const ss = sodium.ml_kem768_decaps(a.slice(0, 2400), a.slice(2400, 3488));
            return ss ? concatBytes([ONE, ss]) : ZERO;
        },
    };
}
/** The guest-side ABI preamble: `host.call(name, bytes)` over the single seam,
 *  `register`/`__invoke` for entrypoint dispatch, and the call envelope those
 *  invocations carry (`callerOf`, `readOp`, `writeOp`). Pure JS — it names no
 *  authority, so evaluating it in a zero-authority realm grants nothing; it only gives
 *  the guest a shape to call through.
 *
 *  `register` is a generic mechanism, not an open vocabulary. The SHELL invokes exactly
 *  two names — `handle` (an app's one inbound/op entrypoint, reached by `dispatch` and
 *  by the host's own `invoke` loopback, the op travelling in the payload) and `timer`
 *  (a fired deadline). A guest that registers anything else is writing an entrypoint
 *  nothing will ever call; its local ops belong in `handle`'s payload, so an app has one
 *  op vocabulary instead of a per-entrypoint one.
 *
 *  Which is why the ENVELOPE is here too. A fixed entrypoint vocabulary only moves the
 *  vocabulary problem if the shape that replaced it is left for each app to invent: the
 *  op name, the caller prefix and the host's zero id are one contract, so they are
 *  written once — here, next to the `register` they are the argument of, and mirrored by
 *  `opCall`/`opHeader` below for the host side of the same bytes.
 *
 *  ONE definition for every target: a bundle
 *  ships a single `guest.js` that runs byte-identical on the node/browser host (safe-js.ts)
 *  and inside the native loader's confined realm (guest.go). The preamble is therefore a
 *  contract between the runtime and signed content, not a host implementation detail — a
 *  per-target copy is a wire format maintained in two places.
 *
 *  HOST CONTRACT — a host embedding this must inject one function:
 *
 *    __host_call(name: string, callId, payload: ArrayBuffer) -> ArrayBuffer | null
 *
 *  Returning bytes completes a **sync** name (the primitive catalog, clock, the bundle's
 *  own modules, the raw-link names) inline. Returning `null` means the host started an
 *  **async** name under `callId` — every `fs/*`, and every `_`-led cross-realm call — and
 *  the guest parks a Promise here, which the host later settles with
 *  `__netResolve(callId, bytes)` or `__netReject(callId, msg)`. `null` is RESERVED for
 *  that — a sync name that ever returned null/undefined would be read as async and leave
 *  a Promise pending forever.
 *
 *  The async half is deliberately plain ECMAScript rather than a host-created deferred:
 *  the guest builds its own Promise, so the seam needs no promise primitive from the
 *  embedding engine. That is what lets one preamble serve both a host holding
 *  quickjs-emscripten's `newPromise()` and one driving quickjs-ng over wazero, which has
 *  no such primitive. `defer()` is the same idea pointed the other way — the guest builds
 *  the promise its own ENTRYPOINT answers with — and needs nothing of the engine either. */
export function guestPreamble(): string {
    return GUEST_PREAMBLE;
}
const GUEST_PREAMBLE = `
"use strict";
let __callSeq = 0;
const __pending = Object.create(null);
globalThis.__netResolve = (callId, bytes) => {
  const p = __pending[callId];
  if (!p) return;
  delete __pending[callId];
  p.resolve(new Uint8Array(bytes));
};
globalThis.__netReject = (callId, msg) => {
  const p = __pending[callId];
  if (!p) return;
  delete __pending[callId];
  p.reject(new Error(msg));
};
globalThis.host = {
  // A sync name resolves to its bytes directly; a net or fs name returns a real Promise,
  // so a guest's 'await host.call(...)' covers both (awaiting a plain value is a no-op)
  // and a fan-out is just 'await Promise.all(peers.map(p => host.call("net/send", ...)))'.
  // The name is the seam: a guest asks for a capability by NAME — "fs/get",
  // "net/send", "crypto/blake2b-256" — never by a number. A name with no "/" is one of
  // the bundle's OWN modules, called by the logical name its manifest declared ("ws",
  // "codec"): one call shape over host primitives, host authorities and app modules,
  // because a module name cannot spell a host name (§12.2).
  //
  // The payload is normalized to a plain ArrayBuffer — never a view — because that is the
  // narrower of the two hosts' readers: the native loader reads a view or a buffer alike,
  // but quickjs-emscripten's getArrayBuffer accepts only a true ArrayBuffer. A subarray is
  // copied to its own buffer so the host never sees more bytes than the caller passed.
  call(name, bytes) {
    const callId = ++__callSeq;
    const ab = bytes instanceof ArrayBuffer
      ? bytes
      : (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength)
        ? bytes.buffer
        : bytes.slice().buffer;
    const r = __host_call(name, callId, ab);
    if (r !== null) return new Uint8Array(r);          // sync name — bytes directly
    return new Promise((resolve, reject) => { __pending[callId] = { resolve, reject }; }); // net / fs
  },
};
globalThis.__entries = Object.create(null);
globalThis.register = (name, fn) => { globalThis.__entries[name] = fn; };
// ── the call envelope (§12.2) ───────────────────────────────────────────────
//
// One entrypoint means one argument shape, and these are it — declared HERE, in the
// preamble, because the shape is a contract between the runtime and signed content
// rather than an app's private convention. Before this, every app re-derived the same
// three lines (an 'is the caller all zeros' scan, a length-prefixed name read, the
// same written backwards for a cross-realm call), and they drifted: one program read
// the op as a name and another as a byte its host had to agree on.
//
//   handle(arg)  =  [caller 32][body …]
//
// 'callerOf' splits that, and 'fromHost' is the one distinction the HOST makes for the
// guest: the id is the host's to write, so 32 zero bytes means the host itself (no app
// key derives it, shell-core.ts) and anything else is a peer's key or a co-resident
// app's. What is IN the body is the app's business — a peer's frame is whatever the
// app's protocol says, and only a call from the host or from another realm carries the
// op envelope below.
globalThis.callerOf = (arg) => {
  const caller = arg.subarray(0, 32);
  let fromHost = true;
  for (let i = 0; i < 32; i++) { if (caller[i] !== 0) { fromHost = false; break; } }
  return { fromHost, caller, body: arg.subarray(32) };
};
// [opLen u8][op ascii][args …] — the op envelope, read. The discriminator is a NAME,
// never a tag byte: collapsing many entrypoints onto one call must not smuggle in a
// number two sides have to agree on, and an op a program does not implement then fails
// loud by name. Malformed framing throws rather than reading a truncated name, which a
// caller would see as an unimplemented op.
globalThis.readOp = (body) => {
  const n = body.length > 0 ? body[0] : -1;
  if (n < 0 || body.length < 1 + n) throw new Error("guest: malformed op envelope");
  let op = "";
  for (let i = 0; i < n; i++) op += String.fromCharCode(body[1 + i]);
  return { op, args: body.subarray(1 + n) };
};
// The same, written — for a guest calling ANOTHER realm ('host.call("_net", …)'),
// where the host prepends the caller id and the envelope is the guest's to write.
// ASCII by construction: an op name is a literal in guest source, and charCodeAt keeps
// this free of a TextEncoder no fresh realm is guaranteed to have.
globalThis.writeOp = (op, args) => {
  const out = new Uint8Array(1 + op.length + args.length);
  out[0] = op.length;
  for (let i = 0; i < op.length; i++) out[1 + i] = op.charCodeAt(i) & 0xff;
  out.set(args, 1 + op.length);
  return out;
};
// Set by defer() and read by the host once the invocation's synchronous segment ends —
// see the note on defer below. Cleared per invocation, never by the guest.
globalThis.__deferred = false;
// Answer on a LATER TURN, without holding the realm. Returns { promise, settle, fail }:
// the entrypoint returns the promise, and whatever runs next in this realm settles it.
//
// It exists for the one guest that cannot await its own answer: the transport reaches
// its reply by reading bytes off a link, and reading those bytes is another invocation
// of this same realm. Awaiting inside the frame would hold the queue against the very
// event that settles it. A guest using this is asserting that it never parks — its
// entrypoints run to completion and its outstanding answers are plain promise objects,
// so a second invocation entering meanwhile cannot observe a half-updated frame,
// because there is no frame left to be half-updated.
globalThis.defer = () => {
  let settle, fail;
  const promise = new Promise((res, rej) => { settle = res; fail = rej; });
  globalThis.__deferred = true;
  return { promise, settle, fail };
};
function __norm(out) {
  if (out instanceof ArrayBuffer) return out;
  if (out instanceof Uint8Array) {
    return (out.byteOffset === 0 && out.byteLength === out.buffer.byteLength) ? out.buffer : out.slice().buffer;
  }
  throw new Error("guest: entrypoint must return Uint8Array | ArrayBuffer");
}
globalThis.__invoke = (name, argBuf) => {
  const fn = globalThis.__entries[name];
  if (typeof fn !== "function") throw new Error("guest: no entrypoint '" + name + "'");
  // Cleared HERE rather than by the host, so the flag describes exactly this
  // invocation and a guest cannot leave it set for the next one.
  globalThis.__deferred = false;
  // A synchronous entrypoint (a holder's 'handle' answering from memory) returns bytes
  // directly; an async entrypoint (a 'handle' that awaits the network) returns a guest
  // promise the host settles. __norm normalizes both to an ArrayBuffer.
  const out = fn(new Uint8Array(argBuf));
  return out && typeof out.then === "function" ? out.then(__norm) : __norm(out);
};
`;
// ── the call envelope, host side ────────────────────────────────────────────
//
// The mirror of `callerOf`/`readOp` in the preamble above, and deliberately in the same
// file: these two functions and those three write and read the SAME bytes, so a change
// to the layout is one edit rather than a search for everyone who open-coded it. Before
// they existed the layout was hand-written at five call sites across three repositories
// — the CLI, the transport driver, a storage node, a browser shell and a guest building
// a cross-realm call — and one of them had drifted to an op BYTE.
/** The host's own caller id: 32 zero bytes, "the host itself". No app key derives it
 *  (an app's id is a hash of its key, shell-core.ts) and no peer key is it, so a guest
 *  reading `callerOf(arg).fromHost` is reading an unforgeable fact. */
export const HOST_CALLER_ID = new Uint8Array(32);
/** `[caller 32][opLen u8][op]` — the header of one call, without its arguments. For a
 *  caller that concatenates its own fields behind it and would otherwise copy the whole
 *  payload a second time to put a header in front (transport-host.ts `Args`, which
 *  builds this once per op and reuses it on the inbound frame path). */
export function opHeader(op: string, caller: Uint8Array = HOST_CALLER_ID): Uint8Array {
    const name = enc.encode(op);
    // ASCII, because the guest reads it back with charCodeAt (no fresh realm is
    // guaranteed a TextDecoder) and because a length in BYTES that a guest counts in
    // UTF-16 code units is a framing bug waiting for its first non-ASCII op.
    if (name.length !== op.length || name.length > 255)
        throw new Error(`guest-seam: op name ${JSON.stringify(op)} must be 1..255 ASCII bytes`);
    const out = new Uint8Array(caller.length + 1 + name.length);
    out.set(caller, 0);
    out[caller.length] = name.length;
    out.set(name, caller.length + 1);
    return out;
}
/** `[caller 32][opLen u8][op][args]` — one whole call, as an app's `handle` reads it
 *  (`callerOf` then `readOp`). The default caller is the host's own id, which is what
 *  `Shell.invoke` writes; the transport driver passes its own. */
export function opCall(op: string, args: Uint8Array, caller: Uint8Array = HOST_CALLER_ID): Uint8Array {
    const head = opHeader(op, caller);
    return concatBytes([head, args]);
}
/** `[opLen u8][op][args]` read back — the host-side twin of the preamble's `readOp`,
 *  for the shell reading a guest's cross-realm call to its own `_host` id. Same bytes,
 *  same failure: malformed framing throws rather than yielding a truncated name that
 *  the caller would then see reported as an unimplemented op. */
export function readOp(payload: Uint8Array): { op: string; args: Uint8Array } {
    const n = payload.length > 0 ? payload[0] : -1;
    if (n < 0 || payload.length < 1 + n)
        throw new Error("guest-seam: malformed op envelope");
    return { op: dec.decode(payload.subarray(1, 1 + n)), args: payload.subarray(1 + n) };
}
/** The authority catalog — declared in core/domains.ts and re-exported so a reader of the
 *  seam finds it beside the names it governs. A bundle's signed manifest declares the
 *  authorities its guest holds (its `requires`), the loader checks them against this table
 *  before anything is trusted, and the shell passes them to the seam as the exact set it
 *  enforces (`grants.names`). Fine-grained and human-auditable: "this app reaches
 *  `node/sign` + `fs/get`", not a prefix that grows every op ever added under it.
 *
 *  **Grants are the authorities plus the reserved ids; `crypto/*` and a bundle's own
 *  modules are not.** `node/sign` is a signing oracle under the node identity,
 *  `node/identity` hands out the node's public key, `node/random` reaches the OS entropy
 *  source, `link/*` reaches a socket — each a grant over something the host owns. A `_`-led
 *  id is a grant over something another REALM owns, which is why it is declared in the same
 *  list: `_net` in a manifest's requires says "this app talks to the network", and it is
 *  the only place that says so. The `crypto/` primitives are functions of their arguments,
 *  so a guest holding them computes only what it could have computed with code of its own,
 *  and a manifest that had to ask before hashing a byte string would be describing an
 *  authority that does not exist. A bare name — one of the asking bundle's own modules — is
 *  exempt for the same reason: that code was installed and verified with the guest, so
 *  calling it reaches nothing the guest does not already hold, and its scope (one app's
 *  map) is the shape, not a grant.
 *
 *  Neither exemption is a parse of the name for AUTHORITY: the gate asks `isGrant`, which
 *  is membership in this table or the one-character reservation the format already
 *  enforces — so the manifest never mentions the rest of the seam at all. */
export { AUTHORITY_CALLS, PRIVILEGES, NET_PROTOCOL, SHELL_PROTOCOL } from "../core/domains.js";
/** The host-derived scope the node/sign name binds every guest signature to (README §12.2):
 *  `author_pk ‖ app_len u8 ‖ app`, from the admitted manifest's `(author, app)`.
 *  Never guest-supplied — a guest can only sign within its own bundle's namespace,
 *  and two bundles derive disjoint scopes. Every node running the same bundle derives
 *  the same bytes, which is what makes the scoped signatures portable across a cohort.
 *  `node/verify` applies the same scope, so a guest checks signatures without ever
 *  reconstructing host-owned bytes. */
export function guestSignScope(author: Uint8Array, app: string): Uint8Array {
    const appBytes = enc.encode(app);
    if (appBytes.length > 255)
        throw new Error("guest-seam: app name too long for a scope (>255 bytes)");
    const out = new Uint8Array(author.length + 1 + appBytes.length);
    out.set(author, 0);
    out[author.length] = appBytes.length;
    out.set(appBytes, author.length + 1);
    return out;
}
/** An ordinary app's signing scope: `DOMAIN_guest ‖ author ‖ app`, signed by the guest
 *  subkey. Two bundles derive disjoint scopes, and every node running the same bundle
 *  derives the same bytes — which is what makes scoped signatures portable across a
 *  cohort. */
export function appSignScope(key: {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}, author: Uint8Array, app: string): SignScope {
    return { domain: DOMAIN_GUEST, scope: guestSignScope(author, app), key };
}
/** The transport slot's signing scope: `DOMAIN_channel ‖ networkKey`, signed by the node's
 *  CHANNEL key (its peer identity). The suffix — a handshake transcript — is the slot
 *  occupant's business and the host does not look at it. An absent network key is the
 *  public network's zero key, said explicitly (§12.6). */
export function transportSignScope(key: {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}, networkKey?: Uint8Array): SignScope {
    return { domain: DOMAIN_CHANNEL, scope: (networkKey ?? new Uint8Array(32)).slice(), key };
}
// ── Opting out of gating, explicitly ────────────────────────────────────────
//
// `grants.names` governs how far a guest reaches, and the absent value must NOT mean
// permissive: a mistake there is a capability escalation — full authority is what a new
// call site gets by forgetting a field, in a runtime whose admission policy is otherwise
// deny-all (policy.ts). So `grants.names` is required, and the permissive case is a value
// a caller has to name. There IS a legitimate permissive caller — a host-side orchestrator
// that already holds every primitive the seam wraps, so gating it protects nothing — and
// this sentinel is for it. A symbol rather than a string or `null`: a symbol cannot arrive
// from parsed config or be produced by a manifest, so the only way to reach the permissive
// branch is to import the constant and mean it.
//
// Module scoping needs no such case: `modules.call` is bound to one app's module map
// (ModuleTable), so there is no wider namespace an omitted argument could open onto and
// nothing to opt out of.
/** Run without name gating: every authority resolves. For a host-side
 *  caller that already holds the primitives; never for a bundle's guest, whose reach is
 *  its manifest `requires` and nothing else (§12.2). */
export const UNRESTRICTED_NAMES = Symbol("seedkernel.seam.unrestricted-names");
// Host-side allocation bounds for guest-controlled sizes. The realm's own
// 64 MiB memory limit does not cover host allocations the guest requests, so
// the seam caps them itself (a confined guest must not be able to size a
// host buffer past these).
const MAX_RANDOM_BYTES = 1 << 20; // 1 MiB per node/random call
const ONE = new Uint8Array([1]);
const ZERO = new Uint8Array([0]);
const NONE = new Uint8Array(0);
function u64be(value: number): Uint8Array {
    const out = new Uint8Array(8);
    writeU32BE(out, 0, Math.floor(value / 0x100000000));
    writeU32BE(out, 4, value >>> 0);
    return out;
}
/** The host half of the catalog — the ONE table of names a host call may utter, built
 *  from the platform (crypto, identity, peers, clock) and the grants (the backends
 *  behind the gated names). It IS the seam ABI (§12.2): the HOST names a guest can call
 *  are the keys of the table it builds — no second list, no numbers, never a wire value.
 *  The bundle's own modules are the catalog's other source of names, resolved past the
 *  end of this table by the dispatch because they are the app's rather than the host's.
 *
 *  A function of its two arguments and nothing else, which is the point of the split:
 *  the same platform and grants produce the same table, so this is the whole of what a
 *  realm may *utter*, and `createGuestSeam` below is nothing but the gate in front of it.
 *
 *  The `crypto/*` entries (the primitive catalog, keys typed `crypto/${PrimitiveName}`)
 *  reach nothing a guest does not already hold, so they are ungated by a rule; every
 *  other name is an authority, gated by EXACT membership in the manifest's declared
 *  requires. `link/*` is the platform's whole contribution to the network — a byte duplex
 *  behind opaque link ids — and it is the transport's alone; what the transport PROVIDES
 *  back is not in this table at all, because it is not a host service but a realm an app
 *  reaches by the id it claims (`NET_PROTOCOL`). */
function hostCatalog(platform: SeamPlatform, grants: SeamGrants): Record<string, SeamHandler> {
    const { sodium, identity } = platform;
    const now = platform.now ?? (() => Date.now());
    const fs = () => {
        if (!grants.fs)
            throw new Error("guest-seam: fs.* used but no fs backend wired");
        return grants.fs;
    };
    const rawNet = () => {
        if (!grants.rawNet)
            throw new Error("guest-seam: link.* used but no raw net is wired (only the transport slot holds sockets)");
        return grants.rawNet;
    };
    const timers = () => {
        if (!grants.timers)
            throw new Error("guest-seam: timer.* used but no timer backend wired");
        return grants.timers;
    };
    // Null-prototype, so the table holds exactly what is written here: a plain object
    // literal would answer `handlers["toString"]` (and "constructor", "valueOf", …) with
    // an inherited function, which the dispatch below would then CALL. The gate happens
    // to refuse those — `isGrant("toString")` is false, so it falls straight through to
    // a lookup — but a lookup that can resolve to something nobody put
    // in the table is the wrong shape for this file, and the construction check below
    // walks own keys, so it could never see them.
    const handlers: Record<string, SeamHandler> = Object.assign(Object.create(null), {
        // ── the primitive seam (§12.2): a function of bytes the guest already holds ──
        // Ungated by a rule rather than by omission — computation the guest could have
        // done with code of its own, so there is nothing to grant (§12.1). The bundle's
        // own modules are the other ungated half, and they are not in this table at all:
        // they are the app's, resolved per seam at the bottom of this function.
        ...cryptoCatalog(sodium),
        // ── authorities: each reaches something no confined guest can hold ──────────
        // node/sign and node/verify are scoped, never raw: both apply `domain ‖ scope`
        // to the message with the key the asking bundle's slot selected (see
        // `SignScope` above), so a guest checks signatures without ever reconstructing
        // host-owned bytes.
        "node/sign": (payload) => {
            const s = grants.signScope;
            if (!s)
                throw new Error("guest-seam: node/sign needs a slot-derived scope (signing is never raw)");
            return sodium.crypto_sign_detached(concatBytes([s.domain, s.scope, payload]), s.key.privateKey);
        },
        // node/verify — [pk 32][sig 64][msg …] → [ok u8]. Scoped like node/sign: the
        // host verifies `domain ‖ scope ‖ msg` under the caller-named key, so the
        // caller supplies the key but never the scope. The key's own signature binds
        // it to this bundle's namespace — a signature made under any other scope
        // (or an app key, a channel transcript) answers [0] here.
        //
        // A payload too short to hold both throws rather than answering [0]: that is a
        // guest that mis-framed the call, not a signature that failed, and the two
        // must not arrive as the same answer — [0] is a verdict about bytes that were
        // actually checked. Only the check itself is caught, and an empty `msg` is a
        // legitimate question, so the bound is exactly the fixed prefix.
        "node/verify": (payload) => {
            const s = grants.signScope;
            if (!s)
                throw new Error("guest-seam: node/verify needs a slot-derived scope (verification is never raw)");
            if (payload.length < 96)
                throw new Error("guest-seam: node/verify takes [pk 32][sig 64][msg ..]");
            try {
                return sodium.crypto_sign_verify_detached(payload.slice(32, 96), concatBytes([s.domain, s.scope, payload.slice(96)]), payload.slice(0, 32)) ? ONE : ZERO;
            }
            catch {
                return ZERO;
            }
        },
        "node/identity": () => identity.publicKey.slice(),
        "node/random": (payload) => {
            const n = readU32BE(payload, 0);
            if (n > MAX_RANDOM_BYTES)
                throw new Error("guest-seam: node/random size over cap");
            return sodium.randombytes_buf(n);
        },
        // ── fs: raw bytes under an opaque key. Every one of these round-trips, so
        // each returns a Promise and the guest reads it with `await` — the seam is
        // what is async, not the backend (§12.1). ──────────────────────────────────
        "fs/get": (payload) => fs().get(dec.decode(payload)).then((v) => (v ? concatBytes([ONE, v]) : ZERO)),
        "fs/put": (payload) => {
            const klen = readU32BE(payload, 0);
            const key = dec.decode(payload.slice(4, 4 + klen));
            return fs().put(key, payload.slice(4 + klen)).then(() => NONE);
        },
        "fs/list": (payload) => {
            const prefix = payload.length ? dec.decode(payload) : undefined;
            return fs().list(prefix).then((keys) => {
                const head = new Uint8Array(4);
                writeU32BE(head, 0, keys.length);
                const parts = [head];
                for (const k of keys) {
                    const kb = enc.encode(k);
                    const kh = new Uint8Array(4);
                    writeU32BE(kh, 0, kb.length);
                    parts.push(kh, kb);
                }
                return concatBytes(parts);
            });
        },
        "fs/delete": (payload) => fs().delete(dec.decode(payload)).then(() => NONE),
        "fs/size": (payload) => fs().size(dec.decode(payload)).then((sz) => {
            const out = new Uint8Array(4);
            writeU32BE(out, 0, sz < 0 ? 0xffffffff : sz);
            return out;
        }),
        "fs/stat": () => fs().stat().then((s) => concatBytes([u64be(s.used), u64be(s.available)])),
        // ── clock ─────────────────────────────────────────────────────────────────
        "clock/now": () => u64be(now()),
        // ── raw net: bytes over an opaque link id, the socket-side twin of `fs` ──
        //
        // The WHOLE of what the platform contributes to the network (§12.1): a link
        // id the host mints and the guest never interprets, bytes in and bytes out.
        // No peer, no protocol id, no correlation — those are the transport's own, and an
        // app reaches them by calling the id the transport claims, not by a name here.
        // Inbound bytes arrive the other way, as ordinary invocations of the transport's
        // `handle`.
        "link/open": (payload) => {
            const link = rawNet().open(payload);
            const authority = enc.encode(link.authority);
            const out = new Uint8Array(9 + authority.length);
            writeU32BE(out, 0, link.linkId);
            out[4] = link.framing;
            writeU32BE(out, 5, authority.length);
            out.set(authority, 9);
            return out;
        },
        "link/send": (payload) => {
            rawNet().send(readU32BE(payload, 0), payload.slice(4));
            return NONE;
        },
        "link/close": (payload) => {
            rawNet().close(readU32BE(payload, 0), payload[4] === 1);
            return NONE;
        },
        "link/stat": (payload) => {
            const out = new Uint8Array(4);
            writeU32BE(out, 0, rawNet().buffered?.(readU32BE(payload, 0)) ?? 0);
            return out;
        },
        // ── timers: the platform's event loop ─────────────────────────────────────
        "timer/arm": (payload) => {
            // How many deadlines one guest may hold at once is bounded by the BACKEND,
            // not here: the table of live timers is the backend's memory to spend, and a
            // limit protecting a resource belongs to whoever owns the resource.
            timers().arm(readU32BE(payload, 0), readU32BE(payload, 4));
            return NONE;
        },
        "timer/clear": (payload) => {
            timers().clear(readU32BE(payload, 0));
            return NONE;
        },
    } satisfies Record<HandlerKey, SeamHandler>);
    // The one-file rule, checked at construction: every name this table dispatches
    // through is a `HandlerKey` — an authority the loader knows (`AUTHORITY_CALLS`) or a
    // primitive (`PRIMITIVE_NAMES`). A key outside that set would be a name no manifest
    // could ever reach, and an authority the loader knows but the table lacks would
    // answer "no such name" at the guest's first call.
    //
    // The second half is the namespace invariant (`HandlerKey`): a host name contains a
    // `/` and a module name cannot, which is the whole of how the dispatch below tells
    // them apart. `crypto/*` gets it from its template literal; `AUTHORITY_CALLS` is
    // hand-written, so a future bare `"ping"` would silently shadow every app's module of
    // that name. It is refused here instead.
    //
    // The `satisfies` above is the compile-time half of the one-file rule (a missing
    // authority is a type error); this walk is the runtime half, holding on the COMPILED
    // JS the native target evaluates (§12.9) where the types are gone — and it is the one
    // check a typo'd EXTRA key would trip.
    for (const name of Object.keys(handlers)) {
        if (!HANDLER_KEYS.includes(name)) {
            throw new Error(`guest-seam: "${name}" is not a host-call name — it is no authority (AUTHORITY_CALLS) and no primitive (PRIMITIVE_NAMES)`);
        }
        if (!name.includes("/")) {
            throw new Error(`guest-seam: host-call name "${name}" has no "/" — a bare name is a bundle's own module (§12.2), so this would shadow one`);
        }
    }
    return handlers;
}
/** Wire the one `host.call` implementation a realm runs against. Most names resolve
 *  *synchronously* (returns bytes); the ones that genuinely round-trip — `net/send` and
 *  every `fs/*` — return a Promise the guest `await`s. Which side of that line a name
 *  sits on is the ABI (§12.2), which is what `guest.abi` versions.
 *
 *  One seam serves both roles. The **holder** path awaits like the initiator does — it
 *  answers from local fs, and fs is not answerable in the same turn on a target whose
 *  storage backend is asynchronous — so the two are the same shape, and what keeps one
 *  entrypoint invocation from interleaving with the next is the realm's serialization
 *  queue (realm-queue.ts) rather than anything here.
 *
 *  The constructor is the gate plus the dispatch — nothing else. The closed set of
 *  names comes from `hostCatalog` above (which also runs the one-file rule at
 *  construction), so the only decision made here is the one the shell made when it
 *  built `grants`: `allowed` and the name-based dispatch that follows from it. */
export function createGuestSeam(deps: GuestSeamDeps): HostCall {
    const { platform, grants, modules } = deps;
    // Checked at runtime, not only in the types: the native target evaluates the COMPILED
    // JS of this file inside QuickJS (§12.9), where a TypeScript signature is not present
    // to enforce anything. A gate that only holds on one of two targets is not a gate, so
    // an absent value throws here rather than resolving to the permissive branch.
    if (grants.names === undefined) {
        throw new Error("guest-seam: grants.names is required — pass the manifest's declared requires, or UNRESTRICTED_NAMES to opt out");
    }
    // null means "the caller named the sentinel" — never "the caller forgot".
    const allowed = grants.names === UNRESTRICTED_NAMES ? null : new Set(grants.names);
    const handlers = hostCatalog(platform, grants);
    return (name, payload) => {
        // The gate covers authorities, and a granted authority is an EXACT-name check:
        // the name itself must be one of the manifest's declared requires — an
        // undeclared `node/identity` is refused even beside a declared `node/sign`.
        // What counts as an authority is `isGrant` — membership in the catalog's
        // authority table (domains.ts) — never a prefix read off the name: `crypto/*`
        // is a fixed host-side catalog of functions of bytes the guest already holds,
        // so gating it would make a guest ask permission to compute a function of
        // bytes it already has.
        if (allowed && isGrant(name) && !allowed.has(name)) {
            throw new Error("guest-seam: " + name + " not declared by the bundle manifest requires");
        }
        // ONE catalog, three sources of names, told apart by the name itself (§12.2). A
        // `/` says a host name: the table lookup IS the dispatch, and an unknown name
        // (or a primitive this host does not carry) reads `undefined` and is refused.
        if (name.includes("/")) {
            const fn = handlers[name];
            if (!fn)
                throw new Error("guest-seam: no such name " + name);
            return fn(payload);
        }
        // A leading `_` says a RESERVED protocol id: another realm, reached by the same
        // call the host dispatches an inbound frame with (core/domains.ts). Gated above
        // like any authority — it is in `requires` — and refused by name when nothing
        // claims it, rather than parked on a promise no one will ever settle. The answer
        // is whatever the callee's `handle` returned, on a later turn: the callee never
        // runs inside this guest's frame, which is what keeps the call graph a graph.
        if (isReservedProtocol(name)) {
            if (!grants.calls)
                throw new Error("guest-seam: " + name + " is a cross-realm call and this seam has no routing wired");
            const answer = grants.calls.call(name, payload);
            if (!answer)
                throw new Error("guest-seam: no realm claims " + name);
            return answer;
        }
        // A bare name is one of THIS bundle's own modules, by the logical name from its
        // manifest (README §5.1) — which is the name it is bound under inside this app's
        // module map, so there is nothing to resolve and no scoping to apply. The app key
        // was fixed when the shell wired this seam, so no name reaches another app at
        // all. Ungated like `crypto/*`: its own bundle's code is a pure transform the
        // guest already holds, installed and verified with it, so calling one reaches
        // nothing the guest does not have.
        //
        // A name the app never installed is a *typo* and is refused by name, the same as
        // an unknown host name — that uniformity is what the unified catalog buys. A
        // module that runs and FAILS is a different event and keeps its old answer: empty
        // bytes, which is also what a module returning nothing says.
        if (!modules.has(name))
            throw new Error("guest-seam: no such name " + name + " (this bundle installs no module by that name)");
        return modules.call(name, payload) ?? NONE;
    };
}
