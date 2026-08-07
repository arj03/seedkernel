// cap-bridge — the capability counterpart to `safe-js` (exported as
// `seedkernel-wasm/cap-bridge`). Given a safe-js realm, it services the guest's
// single `host.call(name, bytes)` seam from the host's *primitive* capabilities
// and nothing else: crypto primitives (sumo), raw net (bytes over an opaque link id)
// and the structured net the mounted transport builds on it, fs (raw bytes under an
// opaque key), an installed-module call, timers, clock, and identity. Every name is
// application-neutral — the bridge has no idea it is
// hosting storage (or chat, or anything). All structure — content addressing,
// descriptor envelopes, the HAVE/OFFER/STORE wire format, Reed–Solomon, the
// nonce convention — is the guest's business, built on top of these primitives.
//
// This is what lets the seedkernel shell run an arbitrary signed guest: it
// constructs a cap-bridge from host primitives it already holds (README
// §12.2). A host-side caller that holds the same primitives constructs the
// identical bridge, so output orchestrated through the confined guest is
// byte-compatible with a host-side reference path.
import { toHex, fromHex, concatBytes, writeU32BE, readU32BE, enc, dec } from "../core/util.js";
import { DOMAIN_GUEST, DOMAIN_CHANNEL, AUTHORITY_CALLS, PRIMITIVE_NAMES, isGrant, type PrimitiveName, type CapabilityName } from "../core/domains.js";
import { type PeerId } from "../core/net.js";
import { type Fs } from "../core/fs.js";
import { type SafeRealmBridge } from "./safe-js.js";

/** What `node/sign` signs under — derived by the host from which admission point the
 *  asking bundle came through, never from anything the guest says (§12.2).
 *
 *  **The host prefixes; it does not parse.** It signs `domain ‖ scope ‖ msg` where `msg`
 *  is opaque bytes the guest chose and the host never reads. The guarantee — this key
 *  signs channel transcripts and never app data, an app's data and never another app's —
 *  rides entirely on the prefix, which is what domain separation is for. A host that
 *  instead validated the *fields* of what it signs would have pinned one protocol's
 *  design into the core and bought nothing: a hostile transport already holds everything
 *  the transport touches.
 *
 *  `key` is part of the scope because the admission point picks it too: an app signs with
 *  the guest subkey, the mounted transport with the node's channel key. */
export interface SignScope {
    /** Domain tag — `DOMAIN_guest` for an app, `DOMAIN_channel` for the mounted transport. */
    domain: Uint8Array;
    /** Scope bytes under the domain: `author ‖ app` for an app, the network key for the
     *  mounted transport. */
    scope: Uint8Array;
    /** The keypair that signs. */
    key: {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    };
}

/** The facts a guest learns about the bundle it is running as, all of them derived by
 *  the runtime at admission from the signed manifest. The app key never appears here —
 *  the guest reaches its modules by logical name through module/call, against the key its
 *  bridge already holds. */
export interface BundleFacts {
    /** The manifest `app`. */
    app: string;
    /** The manifest author's public key — the key the signature verified under. */
    author: Uint8Array;
}

/** The libsodium surface the crypto names use — structural so any sumo build
 *  (the host's bundled `libsodium-wrappers-sumo`) satisfies it. */
export interface CapSodium {
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

/** The request/response transport the net/send name drives. The mounted transport's driver
 *  (`TransportHost`) satisfies it. A confined guest fans out itself with `Promise.all`
 *  over `net/send`, so the bridge needs only single-peer request/response — no
 *  host-side scatter-gather. */
export interface CapTransport {
    request(to: PeerId, proto: Uint8Array, payload: Uint8Array): Promise<Uint8Array>;
}

/** The RAW net capability (README §12.1) — the socket-side twin of `Fs`, and the whole
 *  of what the platform contributes to the network.
 *
 *  Every method is bytes over an opaque link id the host minted. There is no peer, no
 *  ordering above the channel's own, no framing and no attribution: those are state
 *  machines over whole messages, which the endpoints can implement and therefore do
 *  (the transport bundle). What has no substitute is moving the bytes.
 *
 *  **Nothing here may re-enter the guest realm.** The mounted transport calls these from
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

/** What the transport slot's occupant hands back — the structured face the platform does
 *  not have and every app consumes (§12.6).
 *
 *  This is the provision half of the split: the mounted transport reads raw bytes off links
 *  and reports *attributed* traffic here, where the host binds it to the promises apps
 *  are awaiting and to the protocol bindings that route inbound requests. Like `RawNet`,
 *  no method may re-enter the realm synchronously — `deliver` in particular answers
 *  through the `respond` entrypoint on a later turn, which is also what keeps an
 *  asynchronous app handler possible. */
export interface TransportSink {
    /** An inbound request from `from`, already attributed by the mounted transport. */
    deliver(corr: number, noReply: boolean, from: Uint8Array, proto: Uint8Array, payload: Uint8Array): void;
    /** Settle an app's outbound request: `ok` ⇒ `payload` is the response, otherwise it is
     *  a utf8 failure message. */
    settle(corr: number, ok: boolean, payload: Uint8Array): void;
    /** A link authenticated as `pk`. Returns false when the WHITELIST refuses the peer. The
     *  predicate lives here and is not handed to the slot to apply to itself, because a
     *  predicate the occupant applies to itself gates nothing against a hostile one.
     *
     *  `conceal` says a refusal must be SILENT. The accepting end asks at msg3 — after it
     *  has verified the caller and before it has said anything about itself — so an
     *  immediate close there is exactly the oracle the four-message ordering exists to
     *  remove (§12.6.2, CHANNEL §10 invariant 5). The dialing end asks at msg4, having
     *  already named itself at msg3, and so has nothing left to conceal. */
    linkAuth(linkId: number, pk: Uint8Array, conceal: boolean): boolean;
    /** A peer's first link came up (`up`) or its last one went down. */
    peerEdge(up: boolean, pk: Uint8Array): void;
    /** The answer to a `ready` entrypoint call. */
    ready(ok: boolean): void;
    /** A link the host handed over (`openLink`) tore down, with the occupant's reason
     *  code — relayed to whoever passed the channel in, never interpreted. */
    linkDown(linkId: number, reason: number): void;
}

/** Everything a cap-bridge needs — all host primitives, zero app knowledge. */
export interface CapBridgeDeps {
    sodium: CapSodium;
    /** This node's node keypair (README §12.1): IDENTITY returns its pk. Which key
     *  SIGN uses is `signScope.key`, chosen by the slot — not this. */
    identity: {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    };
    /** What SIGN signs under, derived by the host from the asking bundle's slot
     *  (`appSignScope` / `transportSignScope`). SIGN binds every signature to
     *  `domain ‖ scope ‖ msg` and reads none of `msg`; without a scope SIGN is
     *  unavailable, because guest signing is never raw. A host-side caller that never
     *  exposes SIGN may omit it. */
    signScope?: SignScope;
    /** Reach one of THIS app's WASM modules by its logical name — the shell binds the app
     *  key when it builds the bridge (`ModuleTable.callModule`), so what arrives here is
     *  already scoped and a guest naming a module it does not have resolves to nothing.
     *
     *  There is no logical→table map to pass and no opt-out sentinel guarding it. The
     *  guest's namespace and the app's module map are the same map, so "a guest reaches
     *  only its own modules" is the shape rather than a lookup that could be omitted. */
    callModule: (name: string, payload: Uint8Array) => Uint8Array | null;
    /** The request/response transport the net/send name drives. `TransportHost` satisfies
     *  it. A confined guest fans out itself with `Promise.all` over `net/send`, so the
     *  bridge needs only single-peer request/response — no host-side scatter-gather.
     *
     *  Optional ONLY for a bundle that never declares the `net` domain — the transport
     *  bundle itself (whose net/send would loop back into itself) is that caller.
     *  net/send without a transport throws rather than resolving to nothing. */
    transport?: CapTransport;
    /** The RAW net capability — sockets behind opaque link ids. Wired ONLY for the bundle
     *  claiming the transport slot: a confined module holds no ambient authority by
     *  construction, so nothing else can ever reach a descriptor no matter what has already
     *  been installed (README §1, capability-by-non-wiring). */
    rawNet?: RawNet;
    /** The platform's event loop, for a guest that declares `timer`. */
    timers?: HostTimers;
    /** Where the transport slot's occupant reports its structured output. Wired with
     *  `rawNet` and for the same bundle. */
    transportSink?: TransportSink;
    /** The peers this node can reach (its cohort / connected set). */
    peers: () => PeerId[];
    /** Raw-byte fs backend. Optional: a node that only initiates never reads it. */
    fs?: Fs;
    /** Wall clock (ms). Defaults to Date.now. */
    now?: () => number;
    /** The allowed names, EXACTLY the manifest's declared `guest.requires` (README
     *  §12.2). The bridge refuses any `host.call` naming an authority outside it — so
     *  a guest reaches exactly what its bundle declared, name by name, and nothing
     *  else. Names that are not authorities (`isGrant`) pass regardless: they are
     *  never grants. Required: pass `UNRESTRICTED_NAMES` to opt out deliberately (a
     *  host-side caller that holds the primitives anyway). */
    allowedNames: Iterable<string> | typeof UNRESTRICTED_NAMES;
}

/** The version of the seam defined below — re-exported so a reader of the seam finds it
 *  beside them, and so `seedkernel-wasm/cap-bridge` is the import a bundle builder
 *  reaches for (it is stamping "which host contract is this guest written against",
 *  which is this file's subject). It is DECLARED in domains.ts, with the suite ids, so
 *  the loader can check a manifest's `guest.abi` without importing the guest bridge —
 *  see the note there. Anything that changes what an existing name returns bumps it. */
export { GUEST_ABI_VERSION, SUPPORTED_GUEST_ABIS, PRIMITIVE_NAMES } from "../core/domains.js";
/** The `crypto/` members of the catalog — the template literal over `PRIMITIVE_NAMES`,
 *  so the vocabulary a manifest is checked against and the table the bridge dispatches
 *  through cannot drift: adding a primitive to one without the matching key in the
 *  other is a type error. */
type CryptoCapName = `crypto/${PrimitiveName}`;
/** The keys the dispatch table must cover — every authority (`CapabilityName`, the keys
 *  of `AUTHORITY_CALLS` in domains.ts), the bundle's own module map, and every crypto
 *  primitive. The table literal is typed against this union, so the names are written in
 *  exactly ONE place: a name added to the vocabulary without a handler here is a compile
 *  error, and so is a handler whose name the loader would refuse. */
type HandlerKey = CapabilityName | CryptoCapName | "module/call";
/** The same union as a runtime list, for the construction check below — the compiled-JS
 *  half of the one-file rule, where `HandlerKey` is not present to enforce anything.
 *  Derived here, next to the table it describes, because it is nobody else's business:
 *  the loader's vocabulary is `AUTHORITY_CALLS` alone (a manifest never names the rest). */
const HANDLER_KEYS: readonly string[] = [
    ...Object.keys(AUTHORITY_CALLS),
    "module/call",
    ...PRIMITIVE_NAMES.map((p) => `crypto/${p}`),
];
/** One catalog entry's implementation: argument bytes in, response bytes out (or a
 *  Promise of them, for the round-tripping `net/send` and `fs/*` names). */
type CapHandler = (payload: Uint8Array) => Uint8Array | Promise<Uint8Array>;
/** The primitive half of the catalog (§12.1): a flat name→transform map. Every entry
 *  is a pure function of its argument bytes — no host key, no entropy, no state — so
 *  nothing gates it, and a new algorithm is a catalog entry rather than an op number
 *  or an ABI rev (a host that lacks one refuses the load by name, bundle.ts). */
function cryptoCatalog(sodium: CapSodium): Record<CryptoCapName, CapHandler> {
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
/** The guest-side ABI preamble: `host.call(name, bytes)` over the single seam, plus
 *  `register`/`__invoke` for entrypoint dispatch. Pure JS — it names no authority, so
 *  evaluating it in a zero-authority realm grants nothing; it only gives the guest a
 *  shape to call through.
 *
 *  ONE definition for every target, for the same reason `bundlePreamble` is one: a bundle
 *  ships a single `guest.js` that runs byte-identical on the node/browser host (safe-js.ts)
 *  and inside the native loader's confined realm (guest.go). The preamble is therefore a
 *  contract between the runtime and signed content, not a host implementation detail — a
 *  per-target copy is a wire format maintained in two places.
 *
 *  HOST CONTRACT — a host embedding this must inject one function:
 *
 *    __host_call(name: string, callId, payload: ArrayBuffer) -> ArrayBuffer | null
 *
 *  Returning bytes completes a **sync** name (the primitive catalog, clock, module, the
 *  raw-link and transport names) inline. Returning `null` means the host started an
 *  **async** name under `callId` — `net/send` and every `fs/*` — and the guest parks a
 *  Promise here, which the host later settles with `__netResolve(callId, bytes)` or
 *  `__netReject(callId, msg)`. `null` is RESERVED for that — a sync name that ever returned
 *  null/undefined would be read as async and leave a Promise pending forever.
 *
 *  The async half is deliberately plain ECMAScript rather than a host-created deferred:
 *  the guest builds its own Promise, so the seam needs no promise primitive from the
 *  embedding engine. That is what lets one preamble serve both a host holding
 *  quickjs-emscripten's `newPromise()` and one driving quickjs-ng over wazero, which has
 *  no such primitive. */
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
  // "net/send", "crypto/blake2b-256" — never by a number.
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
  // A synchronous entrypoint (the holder 'handle') returns bytes directly; an async
  // entrypoint (an initiator 'put'/'get') returns a guest promise the host settles.
  // __norm normalizes both to an ArrayBuffer.
  const out = fn(new Uint8Array(argBuf));
  return out && typeof out.then === "function" ? out.then(__norm) : __norm(out);
};
`;
/** The authority catalog — declared in core/domains.ts and re-exported so a reader of the
 *  seam finds it beside the names it governs. A bundle's signed manifest declares the
 *  authorities its guest holds (its `requires`), the loader checks them against this table
 *  before anything is trusted, and the shell passes them to the bridge as the exact set it
 *  enforces (`allowedNames`). Fine-grained and human-auditable: "this app reaches
 *  `node/sign` + `fs/get`", not a prefix that grows every op ever added under it.
 *
 *  **Only authorities are grants; `crypto/*` and `module/call` are not.**
 *  `node/sign` is a signing oracle under the node identity, `node/identity` hands out
 *  the node's public key, `node/random` reaches the OS entropy source — each a grant
 *  over something the host owns. The `crypto/` primitives are functions of their
 *  arguments, so a guest holding them computes only what it could have computed with
 *  code of its own, and a manifest that had to ask before hashing a byte string
 *  would be describing an authority that does not exist. `module/call` is exempt for
 *  the same reason: the modules it reaches are the asking bundle's own, installed
 *  and verified with it, so calling one reaches nothing the guest does not already
 *  hold — its scope (one app's map) is the shape, not a grant.
 *
 *  Neither exemption is a parse of the name: the gate asks `isGrant`, which is
 *  membership in this table, so a name is an authority exactly by being one the host owns
 *  something for — and the manifest never mentions the rest of the seam at all. */
export { AUTHORITY_CALLS, MOUNT_GROUPS } from "../core/domains.js";
/** The host-derived scope the node/sign name binds every guest signature to (README §12.2):
 *  `author_pk ‖ app_len u8 ‖ app`, from the admitted manifest's `(author, app)`.
 *  Never guest-supplied — a guest can only sign within its own bundle's namespace,
 *  and two bundles derive disjoint scopes. Every node running the same bundle derives
 *  the same bytes, which is what makes the scoped signatures portable across a cohort. */
export function guestSignScope(author: Uint8Array, app: string): Uint8Array {
    const appBytes = enc.encode(app);
    if (appBytes.length > 255)
        throw new Error("cap-bridge: app name too long for a scope (>255 bytes)");
    const out = new Uint8Array(author.length + 1 + appBytes.length);
    out.set(author, 0);
    out[author.length] = appBytes.length;
    out.set(appBytes, author.length + 1);
    return out;
}
/** The full scoped-signature *prefix* the node/sign name prepends to a guest message before
 *  signing: `DOMAIN_guest ‖ scope`. Exported so a host-side signer/verifier in another
 *  package (e.g. seedstore's out-of-band descriptor signing, README §12.2) reconstructs the
 *  byte-identical preimage `guestSignPrefix(scope) ‖ msg` WITHOUT mirroring the domain
 *  tag — if this string ever revs, every such verifier revs with it instead of silently
 *  diverging. `scope` comes from `guestSignScope(author, app)`. */
export function guestSignPrefix(scope: Uint8Array): Uint8Array {
    return concatBytes([DOMAIN_GUEST, scope]);
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
/** The generated `const BUNDLE = {…};` block injected ahead of a bundle's guest source,
 *  holding what the runtime knows about the admitted bundle (README §12.4).
 *
 *  Every field here is a fact the runtime DERIVES, so no author ever restates one by
 *  hand: the signing prefix in particular is `DOMAIN_guest ‖ guestSignScope(author, app)`
 *  — precisely what `node/sign` prepends — and a hand-baked copy that disagrees with the
 *  host's derivation fails as a signature that verifies nowhere, with nothing naming the
 *  cause. This is the same one-file rule the DOMAIN_* family follows.
 *
 *  `module/call` takes the logical name, which is also the name the module is bound
 *  under, so there is no map for BUNDLE to carry and no modules field.
 *
 *  Kept deliberately separate from the app's `const APP`: APP is author config that a
 *  deployment's operator config merges over, so anything living there is operator-
 *  writable. Nothing in BUNDLE is. */
export function bundlePreamble(f: BundleFacts): string {
    const bundle = {
        app: f.app,
        author: toHex(f.author),
        // The prefix a guest prepends before the "crypto/ed25519/verify" primitive to
        // rebuild what node/sign signed.
        signPrefix: toHex(guestSignPrefix(guestSignScope(f.author, f.app))),
    };
    return `const BUNDLE = ${JSON.stringify(bundle)};\n`;
}
// ── Opting out of gating, explicitly ────────────────────────────────────────
//
// `allowedNames` governs how far a guest reaches, and it once had a permissive meaning for
// the *absent* value — omit it and the guest got every name in the catalog. That is the
// wrong default in the one file where a mistake is a capability escalation: it makes full
// authority the thing a new call site gets by forgetting a field, in a runtime whose
// admission policy is otherwise deny-all (policy.ts).
//
// It is now required, and the permissive case is a value a caller has to name. There IS a
// legitimate permissive caller — a host-side orchestrator that already holds every
// primitive the bridge wraps, so gating it protects nothing — and this sentinel is for it.
// A symbol rather than a string or `null`: a symbol cannot arrive from parsed config or be
// produced by a manifest, so the only way to reach the permissive branch is to import the
// constant and mean it.
//
// Module scoping used to need the same treatment, and no longer does: `callModule` is
// bound to one app's module map (ModuleTable), so there is no wider namespace an omitted
// argument could open onto and nothing to opt out of.
/** Run without name gating: every authority resolves. For a host-side
 *  caller that already holds the primitives; never for a bundle's guest, whose reach is
 *  its manifest `requires` and nothing else (§12.2). */
export const UNRESTRICTED_NAMES = Symbol("seedkernel.cap.unrestricted-names");
// Host-side allocation bounds for guest-controlled sizes. The realm's own
// 64 MiB memory limit does not cover host allocations the guest requests, so
// the bridge caps them itself (a confined guest must not be able to size a
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
/** Build the single capability funnel for one node. Most names resolve *synchronously*
 *  (returns bytes); the ones that genuinely round-trip — `net/send` and every `fs/*` —
 *  return a Promise the guest `await`s. Which side of that line a name sits on is the
 *  ABI (§12.2), which is what `guest.abi` versions.
 *
 *  One bridge serves both roles. The **holder** path awaits like the initiator does — it
 *  answers from local fs, and fs is not answerable in the same turn on a target whose
 *  storage backend is asynchronous — so the two are the same shape, and what keeps one
 *  entrypoint invocation from interleaving with the next is the realm's serialization
 *  queue (realm-queue.ts) rather than anything here. */
export function createCapBridge(deps: CapBridgeDeps): SafeRealmBridge {
    const { sodium, identity, callModule, transport } = deps;
    const now = deps.now ?? (() => Date.now());
    // Checked at runtime, not only in the types: the native target evaluates the COMPILED
    // JS of this file inside QuickJS (§12.9), where a TypeScript signature is not present
    // to enforce anything. A gate that only holds on one of two targets is not a gate, so
    // an absent value throws here rather than resolving to the permissive branch.
    if (deps.allowedNames === undefined) {
        throw new Error("cap-bridge: allowedNames is required — pass the manifest's declared requires, or UNRESTRICTED_NAMES to opt out");
    }
    // null means "the caller named the sentinel" — never "the caller forgot".
    const allowed = deps.allowedNames === UNRESTRICTED_NAMES ? null : new Set(deps.allowedNames);
    // ── the catalog — the seam ABI (§12.2), ONE table: the names a guest can call
    // are the keys of this object — no second list, no numbers, never a wire value.
    // The `crypto/*` entries (the primitive catalog, keys typed `crypto/${PrimitiveName}`)
    // and `module/call` (the asking bundle's own module map) reach nothing a guest does
    // not already hold, so they are ungated by a rule; every other name is an
    // authority, gated by EXACT membership in the manifest's declared requires.
    // Two nets (§12.1): `net/*` is the transport slot's structured OUTPUT, `link/*` is
    // the platform's raw contribution; the slot holds both, an app holds only `net`.
    const fs = () => {
        if (!deps.fs)
            throw new Error("cap-bridge: fs.* used but no fs backend wired");
        return deps.fs;
    };
    const rawNet = () => {
        if (!deps.rawNet)
            throw new Error("cap-bridge: link.* used but no raw net is wired (only the transport slot holds sockets)");
        return deps.rawNet;
    };
    const timers = () => {
        if (!deps.timers)
            throw new Error("cap-bridge: timer.* used but no timer backend wired");
        return deps.timers;
    };
    const sink = () => {
        if (!deps.transportSink)
            throw new Error("cap-bridge: the transport names are the mounted transport's, and this bridge is not it");
        return deps.transportSink;
    };
    // Null-prototype, so the table holds exactly what is written here: a plain object
    // literal would answer `handlers["toString"]` (and "constructor", "valueOf", …) with
    // an inherited function, which the dispatch below would then CALL. The gate happens
    // to refuse those — `isGrant("toString")` is false, so it falls straight through to
    // a lookup — but a lookup that can resolve to something nobody put
    // in the table is the wrong shape for this file, and the construction check below
    // walks own keys, so it could never see them.
    const handlers: Record<string, CapHandler> = Object.assign(Object.create(null), {
        // ── the primitive seam (§12.2): two ungated halves ─────────────────────────
        // The catalog's `crypto/*` half reaches nothing a guest does not already hold,
        // and the app-supplied half below reaches the asking bundle's own module map —
        // both are computation the guest could have done itself, so neither prefix is
        // a grant (§12.1).
        ...cryptoCatalog(sodium),
        // ── the app-supplied half: the asking bundle's own modules ────────────────
        "module/call": (payload) => {
            // The guest calls its own modules by the logical name from its manifest
            // (README §5.1), and that is the name they are bound under inside this app's
            // module map — so there is nothing to resolve and no scoping to apply. The
            // app key was fixed when the shell built this bridge; a name the app does not
            // have resolves to nothing, and no name reaches another app at all. Its own
            // bundle's code is a pure transform the guest already holds, so this is
            // ungated like `crypto` — a primitive, never a grant.
            if (payload.length < 1)
                return NONE;
            const nameLen = payload[0];
            if (payload.length < 1 + nameLen)
                return NONE;
            const r = callModule(dec.decode(payload.slice(1, 1 + nameLen)), payload.slice(1 + nameLen));
            return r ?? NONE;
        },
        // ── authorities: each reaches something no confined guest can hold ──────────
        // node/sign is scoped, never raw: it signs `domain ‖ scope ‖ msg` with the
        // key the asking bundle's slot selected (see `SignScope` above).
        "node/sign": (payload) => {
            const s = deps.signScope;
            if (!s)
                throw new Error("cap-bridge: node/sign needs a slot-derived scope (signing is never raw)");
            return sodium.crypto_sign_detached(concatBytes([s.domain, s.scope, payload]), s.key.privateKey);
        },
        "node/identity": () => identity.publicKey.slice(),
        "node/random": (payload) => {
            const n = readU32BE(payload, 0);
            if (n > MAX_RANDOM_BYTES)
                throw new Error("cap-bridge: node/random size over cap");
            return sodium.randombytes_buf(n);
        },
        // ── net: net/send is the only async name — a real round trip → a Promise ──
        "net/send": (payload) => {
            if (!transport)
                throw new Error("cap-bridge: net/send used but no transport is wired (the transport bundle itself must not declare net)");
            const peer = toHex(payload.slice(0, 32));
            const pidLen = payload[32];
            const proto = payload.slice(33, 33 + pidLen);
            const off = 33 + pidLen;
            return transport.request(peer, proto, payload.slice(off)).then((resp) => concatBytes([ONE, resp]), () => ZERO);
        },
        // net/peers — -> [count u32][pk 32 …]
        "net/peers": () => {
            const peers = deps.peers();
            const head = new Uint8Array(4);
            writeU32BE(head, 0, peers.length);
            return concatBytes([head, ...peers.map(fromHex)]);
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
        // No peer, no protocol id, no correlation — those are the transport slot's
        // OUTPUT (transport/* below), which an app reaches through the ordinary `net`
        // domain. Inbound bytes arrive the other way, as ordinary entrypoint
        // invocations on the mounted transport's guest.
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
        // ── what the transport slot PROVIDES back: the structured face (attributed
        // peer, protocol id, correlation) an app reaches through the `net` domain ──
        "transport/deliver": (payload) => {
            const corr = readU32BE(payload, 0);
            const noReply = payload[4] === 1;
            const from = payload.slice(5, 37);
            const pidLen = payload[37];
            const proto = payload.slice(38, 38 + pidLen);
            sink().deliver(corr, noReply, from, proto, payload.slice(38 + pidLen));
            return NONE;
        },
        "transport/settle": (payload) => {
            sink().settle(readU32BE(payload, 0), payload[4] === 1, payload.slice(5));
            return NONE;
        },
        "transport/link-auth": (payload) => sink().linkAuth(readU32BE(payload, 0), payload.slice(5, 37), payload[4] === 1) ? ONE : ZERO,
        "transport/peer-edge": (payload) => {
            sink().peerEdge(payload[0] === 1, payload.slice(1, 33));
            return NONE;
        },
        "transport/ready": (payload) => {
            sink().ready(payload[0] === 1);
            return NONE;
        },
        "transport/link-down": (payload) => {
            sink().linkDown(readU32BE(payload, 0), payload[4]);
            return NONE;
        },
    } satisfies Record<HandlerKey, CapHandler>);
    // The one-file rule, checked at construction: every name this table dispatches
    // through is a `HandlerKey` — an authority the loader knows (`AUTHORITY_CALLS`), a
    // primitive (`PRIMITIVE_NAMES`), or `module/call`. A key outside that set would be a
    // name no manifest could ever reach, and an authority the loader knows but the table
    // lacks would answer "no such name" at the guest's first call.
    //
    // The `satisfies` above is the compile-time half of the same rule (a missing
    // authority is a type error); this walk is the runtime half, holding on the COMPILED
    // JS the native target evaluates (§12.9) where the types are gone — and it is the one
    // check a typo'd EXTRA key would trip.
    for (const name of Object.keys(handlers)) {
        if (!HANDLER_KEYS.includes(name)) {
            throw new Error(`cap-bridge: "${name}" is not a host-call name — it is no authority (AUTHORITY_CALLS), no primitive (PRIMITIVE_NAMES), and not module/call`);
        }
    }
    return (name, payload) => {
        // The gate covers authorities, and a granted authority is an EXACT-name check:
        // the name itself must be one of the manifest's declared requires — an
        // undeclared `node/identity` is refused even beside a declared `node/sign`.
        // What counts as an authority is `isGrant` — membership in the catalog's
        // authority table (domains.ts) — never a prefix read off the name: `crypto/*`
        // is a fixed host-side catalog of functions of bytes the guest already holds
        // and `module/call` reaches the asking bundle's own module map, so neither is
        // something to grant. Gating either would make a guest ask permission to
        // compute a function of bytes it already has.
        if (allowed && isGrant(name) && !allowed.has(name)) {
            throw new Error("cap-bridge: " + name + " not declared by the bundle manifest requires");
        }
        // The table lookup IS the dispatch: an unknown name (or a primitive this host
        // does not carry) reads `undefined` and is refused by name.
        const fn = handlers[name];
        if (!fn)
            throw new Error("cap-bridge: no such name " + name);
        return fn(payload);
    };
}
