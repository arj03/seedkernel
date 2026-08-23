// guest-seam — `host.call(name, bytes)` (§12.2). Ownership of the three deps:
//   platform — per node (crypto, identity, clock)
//   grants   — per realm (declared names, scopes, backends); unwired = unreachable
//   modules  — per app (this bundle's WASM, by logical name)
import { concatBytes, writeU32BE, readU32BE, enc, dec } from "../core/util.js";
import { DOMAIN_GUEST, DOMAIN_LINK_SCOPE, AUTHORITY_CALLS, PRIMITIVE_NAMES, PRIVILEGE_LINK, serviceOf, type PrimitiveName, type CapabilityName, type Privilege } from "../core/domains.js";
import { type Fs } from "../core/fs.js";
import type { ModuleResult } from "./bundle.js";

/** What a scoped SIGN/VERIFY name signs under (§12.2). The host prefixes
 *  `domain ‖ scope ‖ msg` and never parses `msg`. `key` is the node's one identity. */
export interface SignScope {
    /** Domain tag — `DOMAIN_guest` for an app slot, `DOMAIN_link_scope` for the slot
     *  holding the raw-link resource. */
    domain: Uint8Array;
    /** Scope bytes under the domain: `author ‖ app` for an app slot, the network key for
     *  the link slot. */
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

/** Cross-realm call by a local service id. `null` when nothing claims it. */
export interface SeamCalls {
    call(id: string, payload: Uint8Array): Promise<Uint8Array> | null;
}

/** Raw-link capability (§12.1): bytes over an opaque host-minted link id.
 *  Nothing here may re-enter the guest realm. The node's immutable facts never pass
 *  this way — the host invoked the freshly stood slot once, with them, before the
 *  binding is published (shell-core.ts), and the mutable address book arrives as
 *  `addr` events. This is only the byte pipe. */
export interface RawNet {
    /** Open a link to an opaque destination name, returning the link id — or 0 when the
     *  host has no route for it, which a caller treats as a fabric dropping a frame. The
     *  host resolves the name in its own address book; the caller learns no route it could
     *  dial for itself, only which wire codec applies and, for a dialed WebSocket, its
     *  `Host` authority (socket-seam.ts). */
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
    /** Report the fate of a platform-owned link back to the binding that supplied it. */
    authenticated(linkId: number, peer: Uint8Array): void;
    down(linkId: number, reason: number): void;
}

/** The platform's event loop, as the one thing a zero-authority realm cannot do for
 *  itself: there is no `setTimeout` in a fresh QuickJS context. `id` is the guest's own, so
 *  the host keeps no name of its own for a deadline. The implementer bounds how many
 *  deadlines a guest may hold at once — the table of live timers is its memory to spend. */
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
    /** This node's node keypair (README §12.1): IDENTITY returns its pk. Which key SIGN
     *  uses is `grants.signScope.key`, chosen by the slot — not this. */
    identity: {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    };
    /** Wall clock (ms). Defaults to Date.now. */
    now?: () => number;
}

/** Per-REALM: exactly what THIS realm may reach — the names it may utter, the scope its
 *  signatures are bound to, and the backends behind the gated names.
 *
 *  Two mechanisms for one decision. The load-bearing one is non-wiring (§1): a realm handed
 *  no `rawNet` cannot acquire one at any point in the process's life. `names` is what makes
 *  an undeclared name a refusal by name rather than a null backend surfacing later as a
 *  confusing failure. */
export interface SeamGrants {
    /** EXACTLY the manifest's declared `guest.requires` (§12.2) — service names and local
     *  service ids together, as signed. A `host.call` naming a host method is refused unless
     *  the method's SERVICE (`serviceOf`) is a member of this set; `crypto/*`, a bare module
     *  name and a declared local service pass regardless — none of them names a host
     *  service, so a local service id sitting unused in this set for that check is harmless.
     *  Required — pass `UNRESTRICTED_NAMES` to opt out deliberately. */
    names: Iterable<string> | typeof UNRESTRICTED_NAMES;
    /** THIS realm's declared local service ids — the `guest.requires` entries that are not
     *  host services (bundle.ts validates their shape and their non-collision with this
     *  bundle's own module names at load). What tells a bare `host.call` name apart from one
     *  of this bundle's own modules (§12.10): declared here, it is a cross-realm call
     *  (`calls`, below); otherwise it is a module. Explicit rather than inferred from `names`
     *  so the rule holds under `UNRESTRICTED_NAMES` too, where there is no name set to infer
     *  it from. Absent or empty for a bundle that calls no local service. */
    localServices?: ReadonlySet<string>;
    /** What `node/sign`/`node/verify` sign and check under — THIS SLOT's scope, derived
     *  once at load (`slotSignScope`): an app slot gets `DOMAIN_guest ‖ author ‖ app`,
     *  the link slot gets `DOMAIN_link_scope ‖ network_key`. The host always chooses
     *  domain ‖ scope; the guest never supplies either. Without a scope both names are
     *  unavailable, because guest signing and scoped verification are never raw. */
    signScope?: SignScope;
    /** Raw-byte fs backend, already scoped to this app's keyspace by the shell
     *  (`scopedFs`). Optional: a node that only initiates never reads it. */
    fs?: Fs;
    /** The RAW net capability — sockets behind opaque link ids. Wired ONLY for a bundle
     *  that reaches the `link` privilege, so nothing else can ever reach a descriptor
     *  whatever is installed (§1, capability-by-non-wiring). */
    rawNet?: RawNet;
    /** The platform's event loop, for a guest that declares `timer`. */
    timers?: HostTimers;
    /** The cross-realm call: how a `_`-led name in `names` is answered. Wired for every
     *  realm — reaching one is a grant like any other, and `names` above decides who holds
     *  it. Absent only for a host-side caller with no routing to resolve against. */
    calls?: SeamCalls;
}

/** Per-APP: this bundle's OWN WASM modules, by the logical names its manifest declared.
 *
 *  Not a grant and not gated — the code was installed and verified with the guest, so
 *  calling one reaches nothing the guest does not already hold. The slot wires this
 *  private value directly, so there is no wider module namespace to scope. */
export interface SeamModules {
    names: ReadonlySet<string>;
    /** Reach one of this app's modules by bare name. Async; `deadlineMs` is the
     *  calling guest's remaining segment, never guest-supplied. */
    call: (name: string, payload: Uint8Array, deadlineMs?: number) => Uint8Array | Promise<ModuleResult> | null;
}

/** Everything the seam needs, in the three groups that own it. */
export interface GuestSeamDeps {
    platform: SeamPlatform;
    grants: SeamGrants;
    modules: SeamModules;
}

/** Calling guest's execution segment. Host plumbing, never ABI: `remainingMs`
 *  is what a module call runs under; `charge` bills it afterwards. */
export interface CallBudget {
    /** Milliseconds left in the calling guest's segment; `Infinity` when unbudgeted. */
    remainingMs: number;
    /** Bill `ms` of host-side CPU to that segment. */
    charge(ms: number): void;
}

/** The host half of `host.call`. Sync names return bytes; round-tripping ones
 *  return a Promise. `budget` is the caller's segment, supplied by the realm. */
export type HostCall = (name: string, payload: Uint8Array, budget?: CallBudget) => Promise<Uint8Array> | Uint8Array;

export { PRIMITIVE_NAMES } from "../core/domains.js";
/** The `crypto/` members of the catalog, as a template literal over `PRIMITIVE_NAMES`, so
 *  the vocabulary a manifest is checked against and the table the seam dispatches through
 *  cannot drift. */
type CryptoName = `crypto/${PrimitiveName}`;
/** The keys the dispatch table must cover, typed so a name added to the vocabulary without
 *  a handler is a compile error, and so is a handler whose name the loader would refuse.
 *
 *  Every one contains a `/`, which is load-bearing (§12.2): module names are held to
 *  `[A-Za-z0-9_-]`, so they cannot spell one of these, which is what lets the dispatch tell
 *  host names and module names apart by the name alone. */
type HandlerKey = CapabilityName | CryptoName;
/** The same union as a runtime list, for the construction check below — the compiled-JS
 *  half of the one-file rule, where `HandlerKey` enforces nothing. */
const HANDLER_KEYS: readonly string[] = [
    ...AUTHORITY_CALLS,
    ...PRIMITIVE_NAMES.map((p) => `crypto/${p}`),
];
/** One catalog entry's implementation: argument bytes in, response bytes out (or a
 *  Promise of them, for the round-tripping `fs/*` names). */
type SeamHandler = (payload: Uint8Array) => Uint8Array | Promise<Uint8Array>;
/** Primitive half of the catalog (§12.1): a flat name→transform map. */
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
        // [sk 32][pk 32] -> [ok u8][shared 32]. ok=0: low-order point.
        "crypto/x25519/dh": (a) => {
            try {
                return concatBytes([ONE, sodium.crypto_scalarmult(a.slice(0, 32), a.slice(32, 64))]);
            }
            catch {
                return ZERO;
            }
        },
        // [seed 64] -> [pk 1184][sk 2400]. Seed is FIPS 203's `d ‖ z`.
        "crypto/ml-kem-768/keypair": (a) => {
            const kp = sodium.ml_kem768_keypair_from_seed(a.slice(0, 64));
            return concatBytes([kp.publicKey, kp.privateKey]);
        },
        // [pk 1184][coins 32] -> [ok u8][ct 1088][ss 32]. ok=0: FIPS 203 §7.2.
        "crypto/ml-kem-768/encaps": (a) => {
            const r = sodium.ml_kem768_encaps(a.slice(0, 1184), a.slice(1184, 1216));
            return r ? concatBytes([ONE, r.ciphertext, r.sharedSecret]) : ZERO;
        },
        // [sk 2400][ct 1088] -> [ok u8][ss 32]. ok=0: §7.3 on the secret key, never a bad ct.
        "crypto/ml-kem-768/decaps": (a) => {
            const ss = sodium.ml_kem768_decaps(a.slice(0, 2400), a.slice(2400, 3488));
            return ss ? concatBytes([ONE, ss]) : ZERO;
        },
    };
}
/** Guest preamble: `host.call` and the one entrypoint, `handle` — nothing else. The
 *  kernel's whole inbound vocabulary is the entrypoint's argument `[caller 32][body …]`:
 *  attribution only. What follows the 32 bytes is the callee's own format; the kernel
 *  never reads it, so it never grows a language. */
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
  // Sync names return bytes; fs / cross-realm return a Promise. Payload is a plain
  // ArrayBuffer — quickjs-emscripten's getArrayBuffer rejects a view.
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
// The answer-to-a-later-turn marker. The guest sets it (its own helper, content) and the
// invocation's queue spot frees at the end of the synchronous segment even though nothing
// has settled (realm-queue.ts). The one ABI bit beyond handle returning bytes: without
// it, a guest whose answer arrives as another invocation of its own realm would hold the
// queue against the only event that could settle it.
globalThis.__deferred = false;
function __norm(out) {
  if (out instanceof ArrayBuffer) return out;
  if (out instanceof Uint8Array) {
    return (out.byteOffset === 0 && out.byteLength === out.buffer.byteLength) ? out.buffer : out.slice().buffer;
  }
  throw new Error("guest: entrypoint must return Uint8Array | ArrayBuffer");
}
globalThis.__invoke = (argBuf) => {
  if (typeof globalThis.handle !== "function") throw new Error("guest: no entrypoint 'handle'");
  // Cleared HERE rather than by the host, so the flag describes exactly this
  // invocation and a guest cannot leave it set for the next one.
  globalThis.__deferred = false;
  // A synchronous entrypoint returns bytes; an async one returns a guest promise the host
  // settles. __norm normalizes both to an ArrayBuffer.
  const out = globalThis.handle(new Uint8Array(argBuf));
  return out && typeof out.then === "function" ? out.then(__norm) : __norm(out);
};
`;
// ── the attribution prefix, host side ────────────────────────────────────────
//
// The ONLY bytes the host puts in front of a callee's format. An app's own format and a
// transport's event framing are content; this prefix is what the host can be asked for,
// one 32-byte id, unforgeable by a guest. There is exactly ONE host id: the zero id,
// whose events and loopback calls the host writes — a fired deadline re-enters this way
// too, as an ordinary loopback naming a "timer" op, so a second host id was never needed
// to tell one from another. Everything else non-zero is a peer or a co-resident app key.
/** The host's own caller id: 32 zero bytes. No app key derives it. */
export const HOST_CALLER_ID = new Uint8Array(32);
/** Method catalog, re-exported from core/domains.ts. A grant is a SERVICE name
 *  (`HOST_SERVICES`) or a local service id declared in `guest.requires`; `crypto/*` and
 *  the bundle's own modules are not. */
export { AUTHORITY_CALLS, PRIVILEGES } from "../core/domains.js";
/** The host-derived scope `node/sign` binds every guest signature to (§12.2):
 *  `author_pk ‖ app_len u8 ‖ app`, from the admitted manifest. Never guest-supplied, so a
 *  guest signs only within its own bundle's namespace; every node running the same bundle
 *  derives the same bytes, which is what makes scoped signatures portable across a cohort. */
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
/** An ordinary app's signing scope: `DOMAIN_guest ‖ author ‖ app`. Two bundles derive
 *  disjoint scopes. */
export function appSignScope(key: {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}, author: Uint8Array, app: string): SignScope {
    return { domain: DOMAIN_GUEST, scope: guestSignScope(author, app), key };
}
/** Host-side twin of a slot's scoped SIGN/VERIFY (§12.2). Same scope as `appSignScope`. */
export function appSigner(
    sodium: SeamCrypto,
    key: { publicKey: Uint8Array; privateKey: Uint8Array },
    author: Uint8Array, app: string,
): {
    sign(msg: Uint8Array): Uint8Array;
    /** False on a signature that does not verify under `(scope, pk)`; a `sig` or `pk` of
     *  the wrong shape ALSO reads false (the seam's `node/verify` refuses a mis-framed
     *  payload by throwing; a caller-facing verifier has no caller left to explain to). */
    verify(pk: Uint8Array, sig: Uint8Array, msg: Uint8Array): boolean;
} {
    const scope = appSignScope(key, author, app);
    const pre = (msg: Uint8Array) => concatBytes([scope.domain, scope.scope, msg]);
    return {
        sign(msg) {
            return sodium.crypto_sign_detached(pre(msg), scope.key.privateKey);
        },
        verify(pk, sig, msg) {
            try {
                return sodium.crypto_sign_verify_detached(sig, pre(msg), pk);
            }
            catch {
                return false;
            }
        },
    };
}
/** The `link` capability's signing scope: `DOMAIN_link_scope ‖ networkKey`, signed by the
 *  node's identity key. The suffix is the slot occupant's business and the host does not
 *  look at it — the transport bundle tags its own handshake format inside it, so changing
 *  that format is a bundle update and never a kernel change. An absent network key is the
 *  public network's zero key, said explicitly (§12.6). */
export function linkSignScope(key: {
    publicKey: Uint8Array;
    privateKey: Uint8Array;
}, networkKey?: Uint8Array): SignScope {
    return { domain: DOMAIN_LINK_SCOPE, scope: (networkKey ?? new Uint8Array(32)).slice(), key };
}
/** The one scope a slot's SIGN/VERIFY signs under — derived once at load (§12.2):
 *  `DOMAIN_guest ‖ author ‖ app` for an ordinary app slot, `DOMAIN_link_scope ‖
 *  networkKey` for the slot reaching `link` — the network binding of the channel AUTH is a
 *  fact of the slot, not a second name. A function of admitted facts only: nothing local,
 *  and nothing from `protocols`, which move per version and would silently restate what
 *  signed records mean. */
export function slotSignScope(node: {
    identity: {
        publicKey: Uint8Array;
        privateKey: Uint8Array;
    };
    networkKey?: Uint8Array;
}, author: Uint8Array, app: string, privileges: readonly Privilege[]): SignScope {
    return privileges.includes(PRIVILEGE_LINK)
        ? linkSignScope(node.identity, node.networkKey)
        : appSignScope(node.identity, author, app);
}
// ── Opting out of gating, explicitly ────────────────────────────────────────
//
// Absent grants.names must not mean permissive. The sentinel is a Symbol so it
// cannot arrive from parsed config (§12.2).
/** Run without name gating. Host-side only; never a bundle's guest. */
export const UNRESTRICTED_NAMES = Symbol("seedkernel.seam.unrestricted-names");
// Host-side allocation bounds for guest-controlled sizes: the realm's own memory limit
// does not cover host allocations the guest requests, so the seam caps them itself.
const MAX_RANDOM_BYTES = 1 << 20; // 1 MiB per node/random call
const ONE = new Uint8Array([1]);
const ZERO = new Uint8Array([0]);
const NONE = new Uint8Array(0);
/** `grants.localServices`'s default: a realm that declared no local service reaches
 *  none, not every bare name. */
const EMPTY_SET: ReadonlySet<string> = new Set();
function u64be(value: number): Uint8Array {
    const out = new Uint8Array(8);
    writeU32BE(out, 0, Math.floor(value / 0x100000000));
    writeU32BE(out, 4, value >>> 0);
    return out;
}
/** The host half of the catalog (§12.2): keys of this table are the host names a
 *  guest may call. `crypto/*` is ungated; everything else is an authority. */
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
            throw new Error("guest-seam: link.* used but no raw net is wired");
        return grants.rawNet;
    };
    const timers = () => {
        if (!grants.timers)
            throw new Error("guest-seam: timer.* used but no timer backend wired");
        return grants.timers;
    };
    // Null-prototype, so the table holds exactly what is written here: a plain object
    // literal would answer `handlers["toString"]` with an inherited function, which the
    // dispatch below would then CALL.
    const handlers: Record<string, SeamHandler> = Object.assign(Object.create(null), {
        // ── the primitive seam (§12.1): functions of bytes the guest already holds, so
        // there is nothing to grant. The bundle's own modules are the other ungated half,
        // resolved past the end of this table.
        ...cryptoCatalog(sodium),
        // ── authorities: each reaches something no confined guest can hold ──────────
        // node/sign and node/verify are scoped, never raw, to THIS SLOT's one scope
        // (see `SignScope`) — derived at load: an app slot's own `DOMAIN_guest ‖ author ‖
        // app`, the link slot's `DOMAIN_link_scope ‖ network_key`. The host chooses what
        // the name signs under, so the guest never reconstructs host-owned bytes and never
        // picks a namespace for itself.
        "node/sign": (payload) => {
            const s = grants.signScope;
            if (!s)
                throw new Error("guest-seam: node/sign needs a slot-derived scope (signing is never raw)");
            return sodium.crypto_sign_detached(concatBytes([s.domain, s.scope, payload]), s.key.privateKey);
        },
        // node/verify — [pk 32][sig 64][msg …] → [ok u8]. Scoped like node/sign: the caller
        // supplies the key but never the scope, so a signature made under any other scope
        // answers [0] here. A payload too short to hold both throws rather than answering
        // [0]: that is a mis-framed call, not a signature that failed, and [0] is a verdict
        // about bytes that were actually checked. An empty `msg` is legitimate, so the
        // bound is exactly the fixed prefix.
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
        // ── fs: raw bytes under an opaque key. Every one round-trips, so each returns a
        // Promise the guest awaits — the seam is what is async, not the backend (§12.1).
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
        // ── raw net: bytes over an opaque link id, the socket-side twin of `fs` — the
        // whole of what the platform contributes to the network (§12.1). No peer, no
        // protocol id, no correlation: those are the transport's own. Inbound bytes arrive
        // the other way, as ordinary invocations of the transport's `handle`. The node's
        // immutable facts were delivered once at init; nothing here is re-readable.
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
        "link/authenticated": (payload) => {
            rawNet().authenticated(readU32BE(payload, 0), payload.slice(4));
            return NONE;
        },
        "link/down": (payload) => {
            rawNet().down(readU32BE(payload, 0), payload[4]);
            return NONE;
        },
        // ── timers: the platform's event loop ─────────────────────────────────────
        "timer/arm": (payload) => {
            // The live-timer cap is the BACKEND's, not here: the table is its memory to
            // spend.
            timers().arm(readU32BE(payload, 0), readU32BE(payload, 4));
            return NONE;
        },
        "timer/clear": (payload) => {
            timers().clear(readU32BE(payload, 0));
            return NONE;
        },
    } satisfies Record<HandlerKey, SeamHandler>);
    // The one-file rule, checked at construction: every name here is a host method the
    // loader knows or a primitive, and every name contains a `/` — the namespace invariant
    // the dispatch below relies on to tell a host method from a bundle's own module (a
    // bare `"ping"` here would shadow every app's module of that name).
    //
    // The `satisfies` above is the compile-time half; this walk is the runtime half, which
    // holds on the COMPILED JS the native target evaluates (§12.9), and is the one check a
    // typo'd EXTRA key trips.
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
/** The one `host.call` a realm runs against: the gate in front of `hostCatalog`.
 *  Sync vs async is the ABI (`guest.abi`); serialization is the realm's, not here. */
export function createGuestSeam(deps: GuestSeamDeps): HostCall {
    const { platform, grants, modules } = deps;
    // Checked at runtime, not only in the types: the native target evaluates the COMPILED
    // JS of this file (§12.9), where a TypeScript signature enforces nothing — and a gate
    // that holds on one of two targets is not a gate.
    if (grants.names === undefined) {
        throw new Error("guest-seam: grants.names is required — pass the manifest's declared requires, or UNRESTRICTED_NAMES to opt out");
    }
    // null means "the caller named the sentinel" — never "the caller forgot".
    const allowed = grants.names === UNRESTRICTED_NAMES ? null : new Set(grants.names);
    const localServices = grants.localServices ?? EMPTY_SET;
    const handlers = hostCatalog(platform, grants);
    return (name, payload, budget) => {
        // ONE catalog, three sources of names, resolved in DECLARATION order (§12.2). A
        // name THIS realm declared as a local service is another realm's, however it is
        // spelled: the id is an ordinary claim and may carry a `/` like any other, so
        // asking the declaration before the charset is what keeps one vocabulary from
        // becoming two. It can never shadow a host method — the loader refuses a
        // `requires` entry whose head is a known service (bundle.ts). The callee answers
        // on a later turn, never inside this guest's frame, which is what keeps the call
        // graph a graph, and an id nothing claims is refused by name rather than parked
        // on a promise no one will settle.
        if (localServices.has(name)) {
            if (!grants.calls)
                throw new Error("guest-seam: " + name + " is a cross-realm call and this seam has no routing wired");
            const answer = grants.calls.call(name, payload);
            if (!answer)
                throw new Error("guest-seam: no realm claims " + name);
            return answer;
        }
        // A `/` says a host method: the table lookup IS the dispatch, gated by the
        // method's SERVICE — an undeclared `node/identity` is refused even beside a
        // declared `node/sign`, because the unit a manifest grants is the SERVICE, and
        // `node/sign` and `node/identity` are the same service under two calls. What
        // counts as a service is `serviceOf` — a table lookup on the text before the
        // first `/`, never a semantic parse of the rest of the name. An unknown name (or
        // a primitive this host does not carry) reads `undefined` and is refused
        // regardless of the gate.
        if (name.includes("/")) {
            const svc = serviceOf(name);
            if (allowed && svc && !allowed.has(svc)) {
                throw new Error("guest-seam: " + name + " not declared by the bundle manifest requires");
            }
            const fn = handlers[name];
            if (!fn)
                throw new Error("guest-seam: no such name " + name);
            return fn(payload);
        }
        // Any other name is one of THIS slot's private modules, by its manifest name.
        // The slot wired this value directly, so no name can reach another app. Ungated
        // like `crypto/*`.
        //
        // A name the app never installed is a typo, refused by name like an unknown host
        // name. A module that runs and FAILS is a different event and answers empty bytes.
        if (!modules.names.has(name))
            throw new Error("guest-seam: no such name " + name + " (this bundle installs no module by that name)");
        // Module call charged to caller's segment (§4.3). Refuse if nothing left —
        // realm interrupt alone cannot catch a guest that only awaits.
        if (budget !== undefined && budget.remainingMs <= 0)
            throw new Error("guest-seam: execution budget exhausted before " + name);
        const r = modules.call(name, payload, budget?.remainingMs);
        if (r !== null && typeof (r as Promise<ModuleResult>).then === "function") {
            return (r as Promise<ModuleResult>).then(({ bytes, ms }) => {
                // Bill the module's OWN processing time (measured on the worker that ran
                // it), never the issue-to-settle wall clock: a burst of fire-and-forget
                // module calls serialized through one worker would otherwise charge their
                // queue wait quadratically, killing a busy-but-honest guest mid-window.
                // Only the parked path is charged: a module answering synchronously ran
                // inside the guest's own open segment, which the realm's clock counted.
                budget?.charge(ms);
                return bytes ?? NONE;
            });
        }
        return (r as Uint8Array | null) ?? NONE;
    };
}
