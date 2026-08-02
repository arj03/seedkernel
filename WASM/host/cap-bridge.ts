// cap-bridge — the capability counterpart to `safe-js` (exported as
// `seedkernel-wasm/cap-bridge`). Given a safe-js realm, it services the guest's
// single `host.call(op, bytes)` seam from the kernel's *primitive* capabilities
// and nothing else: crypto primitives (sumo), raw net (bytes over an opaque link id)
// and the structured net the transport slot builds on it, fs (raw bytes under an
// opaque key), an installed-handler call, timers, clock, and identity. Every op is
// application-neutral — the bridge has no idea it is
// hosting storage (or chat, or anything). All structure — content addressing,
// descriptor envelopes, the HAVE/OFFER/STORE wire format, Reed–Solomon, the
// nonce convention — is the guest's business, built on top of these primitives.
//
// This is what lets the seedkernel shell run an arbitrary signed guest: it
// constructs a cap-bridge from kernel primitives it already holds (README
// §12.2). A host-side caller that holds the same primitives constructs the
// identical bridge, so output orchestrated through the confined guest is
// byte-compatible with a host-side reference path.
import { toHex, fromHex, concatBytes, writeU32BE, readU32BE } from "../core/util.js";
import { DOMAIN_GUEST, DOMAIN_CHANNEL, PRIMITIVE_NAMES, type PrimitiveName } from "../core/domains.js";
import { type PeerId } from "../core/net.js";
import { type Fs } from "../core/fs.js";
import { type SafeRealmBridge } from "./safe-js.js";

export type CapDomain = keyof typeof CAP_DOMAINS;

/** What `SIGN` signs under — derived by the host from the asking bundle's slot, never
 *  from anything the guest says (phase 3a, task 10).
 *
 *  **The host prefixes; it does not parse.** It signs `domain ‖ scope ‖ msg` where `msg`
 *  is opaque bytes the guest chose and the host never reads. The guarantee — this key
 *  signs channel transcripts and never app data, an app's data and never another app's —
 *  rides entirely on the prefix, which is what domain separation is for. A host that
 *  instead validated the *fields* of what it signs would have pinned one protocol's
 *  design into the core and bought nothing: a hostile occupant of a slot already holds
 *  everything that slot touches.
 *
 *  `key` is part of the scope because the slot picks it too: an app signs with the guest
 *  subkey, the transport slot with the node's channel key. */
export interface SignScope {
    /** Domain tag — `DOMAIN_guest` for an app, `DOMAIN_channel` for the transport slot. */
    domain: Uint8Array;
    /** Scope bytes under the domain: `author ‖ app` for an app, the network key for the
     *  transport slot. */
    scope: Uint8Array;
    /** The keypair that signs. */
    key: {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    };
}

/** The facts a guest learns about the bundle it is running as, all of them derived by
 *  the runtime at admission from the signed manifest. Kernel names never appear here —
 *  the guest reaches its modules by logical name through MODULE_CALL, and the bridge
 *  resolves to the kernel name. */
export interface BundleFacts {
    /** The manifest `app`. */
    app: string;
    /** The manifest author's public key — the key the signature verified under. */
    author: Uint8Array;
}

/** The libsodium surface the crypto ops use — structural so any sumo build
 *  (the kernel's bundled `libsodium-wrappers-sumo`) satisfies it. */
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

/** The request/response transport the net op drives. `Transport` satisfies it. A
 *  confined guest fans out itself with `Promise.all` over `NET_SEND`, so the bridge
 *  needs only single-peer request/response — no host-side scatter-gather. */
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
 *  **Nothing here may re-enter the guest realm.** The slot occupant calls these from
 *  inside an entrypoint, so anything that would call back into the realm has to reach it
 *  on a later turn — which every implementation does anyway, because a socket does not
 *  deliver during the write that provoked it. */
export interface RawNet {
    /** Open a link to an opaque destination name, returning the link id — or 0 when the
     *  host has no route for it, which a caller treats exactly as a fabric dropping a
     *  frame. The host resolves the name in the address book it was configured with; the
     *  caller never learns a host, a port or a transport. */
    open(dest: Uint8Array): number;
    /** Write whole bytes to a link. Silently dropped if the link is already gone —
     *  a caller cannot distinguish that from the far end vanishing mid-write anyway. */
    send(linkId: number, bytes: Uint8Array): void;
    /** Tear a link down. `graceful` asks the channel to flush already-written bytes
     *  first (transport-seam.ts `RawChannel.close`). */
    close(linkId: number, graceful: boolean): void;
    /** Raise this link's inbound frame cap from `MAX_HANDSHAKE_FRAME_BYTES` to
     *  `MAX_FRAME_BYTES`. Both numbers are the host's (net-limits.ts) — this asks for
     *  the one transition, it does not name a bound. */
    raiseCap(linkId: number): void;
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
 *  not have and every app consumes (phase 3a, task 11).
 *
 *  This is the provision half of the split: the slot occupant reads raw bytes off links
 *  and reports *attributed* traffic here, where the host binds it to the promises apps
 *  are awaiting and to the protocol bindings that route inbound requests. Like `RawNet`,
 *  no method may re-enter the realm synchronously — `deliver` in particular answers
 *  through the `respond` entrypoint on a later turn, which is also what keeps an
 *  asynchronous app handler possible. */
export interface TransportSink {
    /** An inbound request from `from`, already attributed by the slot occupant. */
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

/** Everything a cap-bridge needs — all kernel primitives, zero app knowledge. */
export interface CapBridgeDeps {
    sodium: CapSodium;
    /** This node's kernel keypair (README §12.1): IDENTITY returns its pk. Which key
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
    /** Reach an installed WASM handler by name (KernelHost.callHandler). */
    callHandler: (name: string, payload: Uint8Array) => Uint8Array | null;
    /** Logical name → kernel name for MODULE_CALL resolution. The guest calls modules
     *  by the logical name from its manifest; the bridge maps to the kernel name here
     *  so kernel names never leave the host. Required: pass `UNSCOPED_MODULES` to opt
     *  out deliberately, since a missing map means a guest could name any handler on
     *  the table, including another author's. */
    modules: Record<string, string> | typeof UNSCOPED_MODULES;
    /** The request/response transport the net op drives. `TransportHost` satisfies
     *  it. A confined guest fans out itself with `Promise.all` over `NET_SEND`, so the
     *  bridge needs only single-peer request/response — no host-side scatter-gather.
     *
     *  Optional ONLY for a bundle that never declares the `net` domain — the transport
     *  bundle itself (whose NET_SEND would loop back into itself) is that caller.
     *  NET_SEND without a transport throws rather than resolving to nothing. */
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
    /** The allowed op set, expanded from the manifest's declared cap domains
     *  (README §12.2, `opsForCaps`). Any op outside the set is refused, so a guest
     *  reaches exactly what its bundle declared. Required: pass `UNRESTRICTED_OPS` to
     *  opt out deliberately (a host-side caller that holds the primitives anyway). */
    allowedOps: Iterable<number> | typeof UNRESTRICTED_OPS;
}

/** The version of the seam defined below — re-exported so a reader of the ops finds it
 *  beside them, and so `seedkernel-wasm/cap-bridge` is the import a bundle builder
 *  reaches for (it is stamping "which host contract is this guest written against",
 *  which is this file's subject). It is DECLARED in domains.ts, with the suite ids, so
 *  the loader can check a manifest's `guest.abi` without importing the guest bridge —
 *  see the note there. Anything that changes what an existing op returns bumps it. */
export { GUEST_ABI_VERSION, SUPPORTED_GUEST_ABIS, PRIMITIVE_NAMES } from "../core/domains.js";
/** The op catalog — the seam ABI (README §12.2). `capPreamble()` injects these as
 *  `const CAP_X = n;` into the guest, and the bridge switch reads them here, so guest
 *  and host can never drift. The numbers are a shared guest↔host identifier regenerated
 *  with the preamble — never a wire value between nodes.
 *
 *  **There are two kinds of entry here and only one of them is a capability** (phase 3a,
 *  the shape test). `CRYPTO` is the *primitive* seam: a flat map over opaque names,
 *  resolved in the host's catalog, reaching nothing a guest does not already hold —
 *  a function of its arguments is computation the guest could have done itself, so
 *  there is nothing to grant. Every other op is an *authority*: it touches the node
 *  key, the OS entropy source, the clock, a socket or the disk, and is gated through
 *  `CAP_DOMAINS` below.
 *
 *  That split is why a new algorithm never appears here. Adding one is a catalog entry
 *  (`CRYPTO_CATALOG`), not an op number, not an ABI rev, and not a capability domain —
 *  which is the whole difference between a core that serves opaque names and one that
 *  understands what a cipher suite is.
 *
 *  **There are two nets here and they are different capabilities** (phase 3a, task 11).
 *  `NET_SEND`/`NET_PEERS` are the *structured* face — an attributed peer, a protocol id,
 *  a correlation — which is the transport bundle's OUTPUT, and an ordinary app reaches it
 *  through this seam like anything else. `NET_LINK_*` is the *raw* capability — bytes over
 *  an opaque link id — which is the platform's contribution and the only part of the
 *  network with no endpoint substitute. The transport slot consumes the second and
 *  provides the first; nothing else holds both.
 *
 *  Net fan-out is not an op: with real promises the guest fans out itself with
 *  `Promise.all` over `NET_SEND`. */
export const CAP = {
    /** The primitive seam: `[nameLen u8][name utf8][args …] -> result`, dispatched by
     *  name through `CRYPTO_CATALOG`. Ungated by construction — see above. */
    CRYPTO: 1,
    // ── authorities: each reaches something no confined guest can hold ──────────
    SIGN: 2, // msg -> 64B detached ed25519 signature over
    //   `domain ‖ scope ‖ msg`, both host-supplied from the asking
    //   bundle's slot (scoped, never raw — see SignScope below)
    IDENTITY: 3, // -> this node's 32B public key
    RANDOM: 4, // [n u32] -> n random bytes
    NET_SEND: 5, // [peer 32][pidLen u8][protocolId utf8][payload ..] -> [ok u8][resp]
    NET_PEERS: 6, // -> [count u32][pk 32 …]
    FS_GET: 7, // key(utf8) -> [0] | [1][bytes]
    FS_PUT: 8, // [klen u32][key(utf8)][bytes] -> []
    FS_LIST: 9, // prefix(utf8, may be empty) -> [count u32]{[klen u32][key]}
    FS_DELETE: 10, // key(utf8) -> []
    FS_STAT: 11, // -> [used u64 BE][available u64 BE]
    FS_SIZE: 12, // key(utf8) -> [size i32 BE] (-1 as 0xFFFFFFFF if absent) —
    //   lets a policy layer rebuild a byte budget (quota) without
    //   reading every value back. Existence is size ≥ 0, so there is
    //   no separate FS_HAS.
    MODULE_CALL: 13, // [nameLen u8][name utf8][req] -> installed handler response bytes
    CLOCK: 14, // -> now ms (u64 BE)
    // ── raw net: bytes over an opaque link id, the socket-side twin of `fs` ──────
    //
    // This is the WHOLE of what the platform contributes to the network (phase 3a,
    // task 11): a link id the host mints and the guest never interprets, bytes in and
    // bytes out, opened and closed. There is no peer here, no protocol id and no
    // correlation — a peer id is an *attributed* identity, which is the transport's
    // output rather than the platform's contribution. Inbound bytes arrive the other
    // way, as ordinary entrypoint invocations on the slot occupant's guest.
    NET_LINK_OPEN: 15, // [dest ..] -> [linkId u32 BE]  (0 ⇒ no route; `dest` is an
    //   opaque destination name the host resolves in the address
    //   book it was configured with, exactly as `fs` resolves a key)
    NET_LINK_SEND: 16, // [linkId u32][bytes ..] -> []
    NET_LINK_CLOSE: 17, // [linkId u32][graceful u8] -> []
    NET_LINK_CAP: 18, // [linkId u32] -> []  raise this link's inbound frame cap from
    //   MAX_HANDSHAKE_FRAME_BYTES to MAX_FRAME_BYTES (net-limits.ts).
    //   Both numbers stay the host's; this asks for the transition.
    // ── timers: the platform's event loop ───────────────────────────────────────
    TIMER_ARM: 19, // [id u32][ms u32] -> []  (fires the `timer` entrypoint)
    TIMER_CLEAR: 20, // [id u32] -> []
    // ── what the transport slot PROVIDES back ────────────────────────────────────
    //
    // The structured face — attributed peer, protocol id, correlation — is the slot
    // occupant's output, so it comes back through the same seam as everything else
    // rather than through a second host↔module ABI.
    NET_DELIVER: 21, // [corr u32][noReply u8][from 32][pidLen u8][proto][payload] -> []
    //   an inbound request, attributed. Answered later through the
    //   `respond` entrypoint — never inline, because the app handler
    //   may itself be async and because no op may re-enter the realm.
    NET_SETTLE: 22, // [corr u32][ok u8][payload | utf8 message] -> []  settle an app's
    //   outbound request under the corr the host assigned
    NET_LINK_AUTH: 23, // [linkId u32][conceal u8][pk 32] -> [admitted u8]  this link
    //   authenticated as `pk`. The WHITELIST GATE answers. Asked at the
    //   first point the peer is known and before we have revealed
    //   ourselves — msg3 accepting, msg4 dialing — so the verdict can
    //   still suppress our identity. `conceal` marks the accepting
    //   case, where a refusal must be silence rather than a close.
    NET_PEER_EDGE: 24, // [up u8][pk 32] -> []  a peer's first link came up / last went down
    NET_READY: 25, // [ok u8] -> []  answer to the `ready` entrypoint
    NET_LINK_DOWN: 26, // [linkId u32][reason u8] -> []  a link the host handed over
    //   (openLink) tore down, with why — the reason is the occupant's
    //   vocabulary and the host only relays it to whoever passed the
    //   channel in
};
/** The primitive catalog — the flat name→transform map `CAP.CRYPTO` dispatches through,
 *  and the reason the core can serve a transport whose cipher suite it knows nothing
 *  about. Every entry is a pure function of its argument bytes: no key of the host's, no
 *  entropy, no state. Entropy is deliberately absent — an ephemeral keypair is
 *  `RANDOM(32)` (an authority) followed by `x25519/dh` against the base point, so the
 *  catalog stays functional and the grant stays where it belongs.
 *
 *  Names are the seam, not the numbers: a host that lacks one refuses the load by name
 *  (`checkPrimitives`), and a bundle that wants a new algorithm needs a host carrying it
 *  — which is why a core vocabulary is provisioned ahead of need (README §14.1). */
/** Build the catalog. The return type is keyed by `PRIMITIVE_NAMES` (declared in
 *  domains.ts, with the ABI version and the suite ids), so the list a manifest is checked
 *  against and the map the bridge dispatches through cannot drift — adding one without
 *  the other is a type error. */
export function cryptoCatalog(sodium: CapSodium): Record<PrimitiveName, (a: Uint8Array) => Uint8Array> {
    return {
        "blake2b-256": (a) => sodium.crypto_generichash(32, a),
        "ed25519/verify": (a) => {
            const pk = a.slice(0, 32), sig = a.slice(32, 96), msg = a.slice(96);
            try {
                return sodium.crypto_sign_verify_detached(sig, msg, pk) ? ONE : ZERO;
            }
            catch {
                return ZERO;
            }
        },
        "xchacha20/xor": (a) => sodium.crypto_stream_xchacha20_xor(a.slice(56), a.slice(0, 24), a.slice(24, 56)),
        "chacha20poly1305-ietf/seal": (a) => sodium.crypto_aead_chacha20poly1305_ietf_encrypt(a.slice(44), null, null, a.slice(0, 12), a.slice(12, 44)),
        "chacha20poly1305-ietf/open": (a) => {
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
        // point (9 ‖ 0×31) this is also the public-key derivation, so no separate op.
        "x25519/dh": (a) => {
            try {
                return concatBytes([ONE, sodium.crypto_scalarmult(a.slice(0, 32), a.slice(32, 64))]);
            }
            catch {
                return ZERO;
            }
        },
        // ── ML-KEM-768 (FIPS 203), from mlkem768.wasm on every target (kem.ts,
        // native/mlkem.go). Derandomized, so the entries stay pure functions of their
        // arguments and the entropy grant stays in `RANDOM` where it belongs.
        //
        // [seed 64] -> [pk 1184][sk 2400]. The seed is FIPS 203's `d ‖ z`; a caller
        // supplies 64 bytes of RANDOM.
        "ml-kem-768/keypair": (a) => {
            const kp = sodium.ml_kem768_keypair_from_seed(a.slice(0, 64));
            return concatBytes([kp.publicKey, kp.privateKey]);
        },
        // [pk 1184][coins 32] -> [ok u8][ct 1088][ss 32]. ok=0 is a public key that
        // fails the modulus check of §7.2 — the same shape x25519/dh uses for a
        // low-order point, and for the same reason: a peer's key is not the caller's to
        // trust, so "unusable" has to be answerable without an exception.
        "ml-kem-768/encaps": (a) => {
            const r = sodium.ml_kem768_encaps(a.slice(0, 1184), a.slice(1184, 1216));
            return r ? concatBytes([ONE, r.ciphertext, r.sharedSecret]) : ZERO;
        },
        // [sk 2400][ct 1088] -> [ok u8][ss 32]. ok=0 is a SECRET KEY that fails the hash
        // check of §7.3, never a bad ciphertext: ML-KEM answers those with a shared
        // secret derived from the key's own z, in constant time, and distinguishing that
        // from success is the oracle implicit rejection exists to deny.
        "ml-kem-768/decaps": (a) => {
            const ss = sodium.ml_kem768_decaps(a.slice(0, 2400), a.slice(2400, 3488));
            return ss ? concatBytes([ONE, ss]) : ZERO;
        },
    };
}
/** The generated `const CAP_NAME = n;` block the guest is written against. */
export function capPreamble(): string {
    return Object.entries(CAP).map(([k, v]) => `const CAP_${k} = ${v};`).join("\n") + "\n";
}
/** The guest-side ABI preamble: `host.call(op, bytes)` over the single seam, plus
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
 *    __host_call(op, callId, payload: ArrayBuffer) -> ArrayBuffer | null
 *
 *  Returning bytes completes a **sync** op (the primitive catalog, clock, module, the
 *  raw-link and transport ops) inline. Returning `null` means the host started an
 *  **async** op under `callId` — `NET_SEND` and every `FS_*` — and the guest parks a
 *  Promise here, which the host later settles with `__netResolve(callId, bytes)` or
 *  `__netReject(callId, msg)`. `null` is RESERVED for that — a sync op that ever returned
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
  // A sync op resolves to its bytes directly; a net or fs op returns a real Promise, so
  // a guest's 'await host.call(...)' covers both (awaiting a plain value is a no-op) and
  // a fan-out is just 'await Promise.all(peers.map(p => host.call(CAP_NET_SEND, ...)))'.
  //
  // The payload is normalized to a plain ArrayBuffer — never a view — because that is the
  // narrower of the two hosts' readers: the native loader reads a view or a buffer alike,
  // but quickjs-emscripten's getArrayBuffer accepts only a true ArrayBuffer. A subarray is
  // copied to its own buffer so the host never sees more bytes than the caller passed.
  call(op, bytes) {
    const callId = ++__callSeq;
    const ab = bytes instanceof ArrayBuffer
      ? bytes
      : (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength)
        ? bytes.buffer
        : bytes.slice().buffer;
    const r = __host_call(op, callId, ab);
    if (r !== null) return new Uint8Array(r);          // sync op — bytes directly
    return new Promise((resolve, reject) => { __pending[callId] = { resolve, reject }; }); // net / fs
  },
  // The primitive seam, by name: host.crypto("x25519/dh", sk_pk). Framing the
  // [nameLen][name][args] envelope here rather than in every guest is the point of a
  // named catalog — a guest asks for an algorithm, never for an op number. Always
  // synchronous: a primitive is a function of its arguments.
  crypto(name, args) {
    const n = new Uint8Array(name.length);
    for (let i = 0; i < name.length; i++) n[i] = name.charCodeAt(i);   // catalog names are ASCII
    const a = args || new Uint8Array(0);
    const buf = new Uint8Array(1 + n.length + a.length);
    buf[0] = n.length;
    buf.set(n, 1);
    buf.set(a, 1 + n.length);
    return this.call(CAP_CRYPTO, buf);
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
/** Capability *domains* — named groups of ops. A bundle's signed manifest declares
 *  the domains its guest needs (its `caps`), and the shell expands them to the
 *  concrete op set it enforces (`allowedOps`) and to which backends it wires. This
 *  is the coarse, human-auditable capability vocabulary: "this app reaches net + fs",
 *  not a list of 17 op numbers. `caps` is the grant; the preamble is the ABI.
 *
 *  **Only authorities appear here, because only authorities are grants** (phase 3a).
 *  `SIGN` is a signing oracle under the node identity, `IDENTITY` hands out the node's
 *  public key, `RANDOM` reaches the OS entropy source — each a grant over something the
 *  host owns. `CAP.CRYPTO` is deliberately absent: its primitives are functions of their
 *  arguments, so a guest holding them computes only what it could have computed with code
 *  of its own, and a vocabulary that made an app ask for a domain in order to hash a byte
 *  string would be describing an authority that does not exist.
 *
 *  That absence is what retires the earlier `crypto`/`transform` split. The split was
 *  right that authority and pure transform are not one word; it was wrong that both
 *  words name grants. One does. */
export const CAP_DOMAINS = {
    crypto: [CAP.SIGN, CAP.IDENTITY, CAP.RANDOM],
    net: [CAP.NET_SEND, CAP.NET_PEERS],
    fs: [CAP.FS_GET, CAP.FS_PUT, CAP.FS_LIST, CAP.FS_DELETE, CAP.FS_STAT, CAP.FS_SIZE],
    module: [CAP.MODULE_CALL],
    clock: [CAP.CLOCK],
    timer: [CAP.TIMER_ARM, CAP.TIMER_CLEAR],
    rawnet: [CAP.NET_LINK_OPEN, CAP.NET_LINK_SEND, CAP.NET_LINK_CLOSE, CAP.NET_LINK_CAP],
    transport: [CAP.NET_DELIVER, CAP.NET_SETTLE, CAP.NET_LINK_AUTH, CAP.NET_PEER_EDGE,
        CAP.NET_READY, CAP.NET_LINK_DOWN],
};
/** Which domains only a slot occupant may declare — see the note in domains.ts, where it
 *  is declared for the same reason `GUEST_ABI_VERSION` is: the loader checks a manifest
 *  field without importing this op catalog. Re-exported so a reader of `CAP_DOMAINS`
 *  finds the restriction beside the domains it restricts. */
export { SLOT_ONLY_DOMAINS } from "../core/domains.js";
/** The host-derived scope the SIGN op binds every guest signature to (README §12.2):
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
/** The full scoped-signature *prefix* the SIGN op prepends to a guest message before
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
/** The generated `const BUNDLE = {…};` block injected alongside `capPreamble()`, holding
 *  what the runtime knows about the admitted bundle (README §12.4).
 *
 *  Every field here is a fact the runtime DERIVES, so no author ever restates one by
 *  hand: the signing prefix in particular is `DOMAIN_guest ‖ guestSignScope(author, app)`
 *  — precisely what the SIGN op prepends — and a hand-baked copy that disagrees with the
 *  host's derivation fails as a signature that verifies nowhere, with nothing naming the
 *  cause. This is the same one-file rule the DOMAIN_* family follows.
 *
 *  MODULE_CALL takes the logical name — the guest never sees a kernel name — so the
 *  module map lives in the bridge, not here. BUNDLE carries no modules field.
 *
 *  Kept deliberately separate from the app's `const APP`: APP is author config that a
 *  deployment's operator config merges over, so anything living there is operator-
 *  writable. Nothing in BUNDLE is. */
export function bundlePreamble(f: BundleFacts): string {
    const bundle = {
        app: f.app,
        author: toHex(f.author),
        // The prefix a guest prepends before the "ed25519/verify" primitive to rebuild
        // what CAP_SIGN signed.
        signPrefix: toHex(guestSignPrefix(guestSignScope(f.author, f.app))),
    };
    return `const BUNDLE = ${JSON.stringify(bundle)};\n`;
}
/** Expand declared capability domains to the concrete op numbers a bridge allows.
 *  Throws on an unknown domain so a typo in a manifest fails loudly rather than
 *  silently granting nothing (or, worse, everything). */
export function opsForCaps(domains: Iterable<string>): number[] {
    const out = [];
    for (const d of domains) {
        const ops = (CAP_DOMAINS as Record<string, number[] | undefined>)[d];
        if (!ops)
            throw new Error(`cap-bridge: unknown capability domain "${d}"`);
        out.push(...ops);
    }
    return out;
}
/** Check a manifest's declared `guest.primitives` against this host's catalog, throwing
 *  the missing name (phase 3a, task 8).
 *
 *  **This is a compatibility check, not an authorization one** — the distinction the
 *  primitive/authority split turns on. It grants nothing, because after `CAP_DOMAINS`
 *  dropped the pure transforms there is nothing to grant; it exists so a host that cannot
 *  serve a name refuses the load *by name* rather than failing at the guest's first call,
 *  which is exactly the legibility `guest.abi` buys for the seam version (§12.4). That is
 *  why the field sits beside `abi` in the manifest and not inside `caps`. */
export function checkPrimitives(names: Iterable<string> | undefined): void {
    if (!names)
        return;
    for (const n of names) {
        if (!(PRIMITIVE_NAMES as readonly string[]).includes(n)) {
            throw new Error(`bundle: this host has no primitive "${n}" (manifest guest.primitives; this host serves: ${PRIMITIVE_NAMES.join(", ")})`);
        }
    }
}
// ── Opting out of gating, explicitly ────────────────────────────────────────
//
// Two of the deps below govern how far a guest reaches: `allowedOps` (which ops resolve
// at all) and `modules` (which kernel names MODULE_CALL can address). Both once had a
// permissive meaning for the *absent* value — omit them and the guest got every op and
// every name. That is the wrong default in the one file where a mistake is a capability
// escalation: it makes full authority the thing a new call site gets by forgetting a
// field, in a runtime whose admission policy is otherwise deny-all (policy.ts).
//
// They are now required, and the permissive case is a value a caller has to name. There
// IS a legitimate permissive caller — a host-side orchestrator that already holds every
// primitive the bridge wraps, so gating it protects nothing — and these sentinels are for
// it. Symbols rather than strings or `null`: a symbol cannot arrive from parsed config or
// be produced by `opsForCaps`, so the only way to reach the permissive branch is to
// import the constant and mean it.
/** Run without op gating: every op in `CAP` resolves. For a host-side caller that
 *  already holds the primitives; never for a bundle's guest, whose reach is its
 *  manifest `caps` and nothing else (§12.2). */
export const UNRESTRICTED_OPS = Symbol("seedkernel.cap.unrestricted-ops");
/** Run without module-name scoping: MODULE_CALL passes logical names straight through
 *  as kernel names. For tests and host-side callers that address the table directly;
 *  never for a guest, which must not be able to name another author's modules. */
export const UNSCOPED_MODULES = Symbol("seedkernel.cap.unscoped-modules");
// Host-side allocation bounds for guest-controlled sizes. The realm's own
// 64 MiB memory limit does not cover host allocations the guest requests, so
// the bridge caps them itself (a confined guest must not be able to size a
// host buffer past these).
const MAX_RANDOM_BYTES = 1 << 20; // 1 MiB per CAP_RANDOM call
const ONE = new Uint8Array([1]);
const ZERO = new Uint8Array([0]);
const NONE = new Uint8Array(0);
const enc = new TextEncoder();
const dec = new TextDecoder();
function u64be(value: number): Uint8Array {
    const out = new Uint8Array(8);
    writeU32BE(out, 0, Math.floor(value / 0x100000000));
    writeU32BE(out, 4, value >>> 0);
    return out;
}
/** Build the single capability funnel for one node. Most ops resolve *synchronously*
 *  (returns bytes); the ones that genuinely round-trip — `NET_SEND` and every `FS_*` —
 *  return a Promise the guest `await`s.
 *
 *  One bridge serves both roles. The **holder** path awaits like the initiator does — it
 *  answers from local fs, and fs is not answerable in the same turn on a target whose
 *  storage backend is asynchronous — so the two are the same shape, and what keeps one
 *  entrypoint invocation from interleaving with the next is the realm's serialization
 *  queue (realm-queue.ts) rather than anything here. */
export function createCapBridge(deps: CapBridgeDeps): SafeRealmBridge {
    const { sodium, identity, callHandler, transport } = deps;
    const now = deps.now ?? (() => Date.now());
    // Checked at runtime, not only in the types: the native target evaluates the COMPILED
    // JS of this file inside QuickJS (§12.9), where a TypeScript signature is not present
    // to enforce anything. A gate that only holds on one of two targets is not a gate, so
    // an absent value throws here rather than resolving to the permissive branch.
    if (deps.allowedOps === undefined) {
        throw new Error("cap-bridge: allowedOps is required — pass opsForCaps(manifest caps), or UNRESTRICTED_OPS to opt out");
    }
    if (deps.modules === undefined) {
        throw new Error("cap-bridge: modules is required — pass the manifest's logical→kernel name map, or UNSCOPED_MODULES to opt out");
    }
    // null in both cases means "the caller named the sentinel" — never "the caller forgot".
    const allowed = deps.allowedOps === UNRESTRICTED_OPS ? null : new Set(deps.allowedOps);
    const modules = deps.modules === UNSCOPED_MODULES ? null : deps.modules;
    // Built once per bridge: the name→transform map CAP.CRYPTO dispatches through. It is
    // not gated, and does not appear in CAP_DOMAINS, because none of its entries reach
    // anything — see the note on CAP above.
    const catalog = cryptoCatalog(sodium);
    const fs = () => {
        if (!deps.fs)
            throw new Error("cap-bridge: fs.* used but no fs backend wired");
        return deps.fs;
    };
    const rawNet = () => {
        if (!deps.rawNet)
            throw new Error("cap-bridge: net.link.* used but no raw net is wired (only the transport slot holds sockets)");
        return deps.rawNet;
    };
    const timers = () => {
        if (!deps.timers)
            throw new Error("cap-bridge: timer.* used but no timer backend wired");
        return deps.timers;
    };
    const sink = () => {
        if (!deps.transportSink)
            throw new Error("cap-bridge: the transport ops are the slot occupant's, and this bridge serves no slot");
        return deps.transportSink;
    };
    return (op, payload) => {
        // The gate covers authorities. `CAP.CRYPTO` is exempt by construction, not by
        // oversight: it appears in no domain because it grants nothing, so gating it would
        // make a guest ask permission to compute a function of bytes it already holds —
        // the coarse-vocabulary lie the primitive/authority split exists to remove. Its
        // catalog is fixed host-side, so the only thing an ungated CRYPTO reaches is a pure
        // transform over the guest's own arguments.
        if (allowed && op !== CAP.CRYPTO && !allowed.has(op)) {
            throw new Error("cap-bridge: op " + op + " not declared by the bundle manifest");
        }
        switch (op) {
            // ── the primitive seam: one op, a flat map over opaque names ─────────
            case CAP.CRYPTO: {
                const nameLen = payload[0];
                const name = dec.decode(payload.slice(1, 1 + nameLen));
                const prim = (catalog as Record<string, ((a: Uint8Array) => Uint8Array) | undefined>)[name];
                // By name, so a host that cannot serve one says which — the same legibility
                // an unsupported `guest.abi` gets. A manifest declaring its primitives is
                // refused at load, so reaching here means an undeclared name.
                if (!prim)
                    throw new Error(`cap-bridge: no such primitive "${name}"`);
                return prim(payload.slice(1 + nameLen));
            }
            // ── authorities ──────────────────────────────────────────────────────
            case CAP.SIGN: {
                // The host prefixes and does not parse (phase 3a, task 10): it signs
                // `domain ‖ scope ‖ msg` with the key the asking bundle's slot selected, so a
                // signature can never verify outside the domain it was made in — an app's can
                // never pass as a channel transcript, nor in another app's scope, and the
                // transport's can never pass as app data.
                const s = deps.signScope;
                if (!s)
                    throw new Error("cap-bridge: SIGN needs a slot-derived scope (signing is never raw)");
                return sodium.crypto_sign_detached(concatBytes([s.domain, s.scope, payload]), s.key.privateKey);
            }
            case CAP.IDENTITY:
                return identity.publicKey.slice();
            case CAP.RANDOM: {
                const n = readU32BE(payload, 0);
                if (n > MAX_RANDOM_BYTES)
                    throw new Error("cap-bridge: RANDOM size over cap");
                return sodium.randombytes_buf(n);
            }
            // ── net (NET_SEND is the only async op — a real round trip → a Promise) ──
            case CAP.NET_SEND: {
                if (!transport)
                    throw new Error("cap-bridge: NET_SEND used but no transport is wired (the transport bundle itself must not declare net)");
                const peer = toHex(payload.slice(0, 32));
                const pidLen = payload[32];
                const proto = payload.slice(33, 33 + pidLen);
                const off = 33 + pidLen;
                return transport.request(peer, proto, payload.slice(off)).then((resp) => concatBytes([ONE, resp]), () => ZERO);
            }
            case CAP.NET_PEERS: {
                const peers = deps.peers();
                const head = new Uint8Array(4);
                writeU32BE(head, 0, peers.length);
                return concatBytes([head, ...peers.map(fromHex)]);
            }
            // ── fs (raw bytes under an opaque key) ───────────────────────────────
            //
            // Every one of these round-trips, so each returns a Promise and the guest
            // reads it with `await`. The seam is what is async, not the backend: a
            // synchronous `get` is a shape no browser backend can implement — IndexedDB
            // cannot, and OPFS only inside a Worker — so a sync fs would make the browser
            // the one target unable to carry a core capability. `MemoryFs` and Go's
            // primitive both answer in the call, and still resolve in a microtask.
            case CAP.FS_GET:
                return fs().get(dec.decode(payload)).then((v) => (v ? concatBytes([ONE, v]) : ZERO));
            case CAP.FS_PUT: {
                const klen = readU32BE(payload, 0);
                const key = dec.decode(payload.slice(4, 4 + klen));
                return fs().put(key, payload.slice(4 + klen)).then(() => NONE);
            }
            case CAP.FS_LIST: {
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
            }
            case CAP.FS_DELETE:
                return fs().delete(dec.decode(payload)).then(() => NONE);
            case CAP.FS_SIZE:
                return fs().size(dec.decode(payload)).then((sz) => {
                    const out = new Uint8Array(4);
                    writeU32BE(out, 0, sz < 0 ? 0xffffffff : sz);
                    return out;
                });
            case CAP.FS_STAT:
                return fs().stat().then((s) => concatBytes([u64be(s.used), u64be(s.available)]));
            // ── installed-handler call + clock ───────────────────────────────────
            case CAP.MODULE_CALL: {
                // The guest calls its own modules by the logical name from its manifest
                // (README §5.1); the bridge resolves to the kernel name here so kernel
                // names never leave the host. The guest is held to what its manifest
                // declared — an undeclared name resolves to nothing, rather than being
                // passed through as a kernel name it could have chosen freely.
                if (payload.length < 1)
                    return NONE;
                const nameLen = payload[0];
                if (payload.length < 1 + nameLen)
                    return NONE;
                const logicalName = dec.decode(payload.slice(1, 1 + nameLen));
                const kernelName = modules ? modules[logicalName] : logicalName;
                if (kernelName === undefined)
                    return NONE;
                const r = callHandler(kernelName, payload.slice(1 + nameLen));
                return r ?? NONE;
            }
            case CAP.CLOCK:
                return u64be(now());
            // ── raw net: bytes over an opaque link id (the socket-side twin of fs) ──
            case CAP.NET_LINK_OPEN: {
                const id = rawNet().open(payload);
                const out = new Uint8Array(4);
                writeU32BE(out, 0, id);
                return out;
            }
            case CAP.NET_LINK_SEND:
                rawNet().send(readU32BE(payload, 0), payload.slice(4));
                return NONE;
            case CAP.NET_LINK_CLOSE:
                rawNet().close(readU32BE(payload, 0), payload[4] === 1);
                return NONE;
            case CAP.NET_LINK_CAP:
                rawNet().raiseCap(readU32BE(payload, 0));
                return NONE;
            // ── timers ───────────────────────────────────────────────────────────
            case CAP.TIMER_ARM:
                // How many deadlines one guest may hold at once is bounded by the BACKEND,
                // not here: the table of live timers is the backend's memory to spend, and a
                // limit protecting a resource belongs to whoever owns the resource — the same
                // rule that put MAX_FRAME_BYTES in the core and MAX_QUEUE_BYTES in the module.
                // Counting here would also be wrong rather than merely misplaced, since this
                // seam never learns that a timer fired.
                timers().arm(readU32BE(payload, 0), readU32BE(payload, 4));
                return NONE;
            case CAP.TIMER_CLEAR:
                timers().clear(readU32BE(payload, 0));
                return NONE;
            // ── the transport slot's structured output ───────────────────────────
            case CAP.NET_DELIVER: {
                const corr = readU32BE(payload, 0);
                const noReply = payload[4] === 1;
                const from = payload.slice(5, 37);
                const pidLen = payload[37];
                const proto = payload.slice(38, 38 + pidLen);
                sink().deliver(corr, noReply, from, proto, payload.slice(38 + pidLen));
                return NONE;
            }
            case CAP.NET_SETTLE:
                sink().settle(readU32BE(payload, 0), payload[4] === 1, payload.slice(5));
                return NONE;
            case CAP.NET_LINK_AUTH:
                return sink().linkAuth(readU32BE(payload, 0), payload.slice(5, 37), payload[4] === 1) ? ONE : ZERO;
            case CAP.NET_PEER_EDGE:
                sink().peerEdge(payload[0] === 1, payload.slice(1, 33));
                return NONE;
            case CAP.NET_READY:
                sink().ready(payload[0] === 1);
                return NONE;
            case CAP.NET_LINK_DOWN:
                sink().linkDown(readU32BE(payload, 0), payload[4]);
                return NONE;
            default:
                throw new Error("cap-bridge: unknown op " + op);
        }
    };
}
