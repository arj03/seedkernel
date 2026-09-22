// guest-seam — `host.call(name, bytes)` (§12.2). Ownership of the three deps:
//   platform — per node (crypto, identity, clock)
//   grants   — per realm (declared names, scopes, backends); unwired = unreachable
//   modules  — per app (this bundle's WASM, by logical name)
import { concatBytes, writeU32BE, readU32BE, enc, dec } from "../core/util.js";
import { DOMAIN_GUEST, DOMAIN_LINK_SCOPE, serviceOf, type HostTransformName, type CapabilityName } from "../core/domains.js";
import { type Fs } from "../core/fs.js";
import type { ModuleResult } from "./bundle.js";
import { HOST_CALL_SPENT, monotonicMs, type CausalClock } from "./realm-queue.js";
import type { Keypair } from "../core/subkeys.js";

/** What a scoped SIGN/VERIFY name signs under (§12.2). The host prefixes
 *  `domain ‖ scope ‖ msg` and never parses `msg`. `key` is the node's one identity. */
export interface SignScope {
  /** Domain tag — `DOMAIN_guest` for an app slot, `DOMAIN_link_scope` for the slot
   *  holding the raw-link resource. */
  domain: Uint8Array;
  /** Scope bytes under the domain: the app label for an app slot, empty for the link
   *  slot. */
  scope: Uint8Array;
  /** The keypair that signs. */
  key: Keypair;
}

/** The libsodium surface the remaining host crypto names use. */
export interface SeamCrypto {
  crypto_generichash(hashLength: number, message: Uint8Array): Uint8Array;
  crypto_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
  crypto_sign_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
  randombytes_buf(n: number): Uint8Array;
  crypto_aead_chacha20poly1305_ietf_encrypt(message: Uint8Array, additional_data: Uint8Array | null, secret_nonce: Uint8Array | null, public_nonce: Uint8Array, key: Uint8Array): Uint8Array;
  crypto_aead_chacha20poly1305_ietf_decrypt(secret_nonce: Uint8Array | null, ciphertext: Uint8Array, additional_data: Uint8Array | null, public_nonce: Uint8Array, key: Uint8Array): Uint8Array;
  crypto_scalarmult(sk: Uint8Array, pk: Uint8Array): Uint8Array;
}

/** Cross-realm call by a local service id. `null` when nothing claims it. */
export interface SeamCalls {
  call(id: string, payload: Uint8Array, deadlineMs?: number, causalClock?: CausalClock): Promise<Uint8Array> | null;
}

/** Raw-link capability (§12.1): bytes over an opaque host-minted link id, plus the one
 *  call that goes the other way — `deliver`, which hands the host a request this occupant
 *  decoded off those links. Transport configuration arrives in `LOCAL`, the node's identity
 *  in `HOST`, and address-book updates as `addr` events. */
export interface RawNet {
  /** Open an opaque destination; id 0 means no route (§12.1). */
  open(dest: string): { linkId: number; stream: boolean };
  /** Write whole bytes to a link. Silently dropped if the link is already gone —
   *  a caller cannot distinguish that from the far end vanishing mid-write anyway. */
  send(linkId: number, bytes: Uint8Array): void;
  /** Tear a link down. `graceful` asks the channel to flush already-written bytes
   *  first (socket-seam.ts `RawLink.close`). */
  close(linkId: number, graceful: boolean): void;
  /** Route one request this occupant decoded off its links: a claim and the `[attribution
   *  32][payload …]` the claimant is entered with, answered with that claimant's bytes. No
   *  new authority — the call names no link, and both arguments are already the caller's
   *  own to choose, so it is worth exactly what holding the sockets is worth (§12.10). Both
   *  a claim no peer may reach and a handler that failed answer EMPTY: refusal and silence
   *  are one fact here.
   *
   *  The one member that enters a guest realm — the CLAIMANT's, never the caller's own
   *  frame, since a realm serializes its invocations. The caller must therefore fire this
   *  and return from its event rather than await it inside one; the answer resumes it as a
   *  new turn (`CallBudget.detach`). */
  deliver(claim: string, framed: Uint8Array, deadlineMs?: number, causalClock?: CausalClock): Promise<Uint8Array>;
}

/** One replaceable wake. The four-byte tag is opaque guest content, returned after
 *  HOST_CALLER_ID. Content multiplexes deadlines inside its own confined heap. */
export interface HostTimers {
  arm(ms: number, tag: Uint8Array): void;
  /** Cancel the armed wake; a notification already in flight cannot be retracted. */
  clear(): void;
}

/** Per-NODE facts every realm on this host shares. Nothing here is a grant — a realm
 *  holds these because it is running on this node at all — so nothing here is gated. */
export interface SeamPlatform {
  sodium: SeamCrypto;
  /** Wall clock (ms), defaulted by the shell before constructing a seam. */
  now: () => number;
}

/** Per-REALM: exactly what THIS realm may reach — the names it may utter, the scope its
 *  signatures are bound to, and the backends behind the gated names.
 *
 *  Two mechanisms for one decision. The load-bearing one is non-wiring (§1): a realm handed
 *  no `rawNet` cannot acquire one at any point in the process's life. `names` is what makes
 *  an undeclared name a refusal by name rather than a null backend surfacing later as a
 *  confusing failure. */
export interface SeamGrants {
  /** EXACTLY the manifest's declared `guest.requires` (§12.2) — the host SERVICES this
   *  realm is granted, as signed. A `host.call` naming a host method is refused unless the
   *  method's SERVICE (`serviceOf`) is a member; `crypto/*`, a bare module name and a
   *  declared local service pass regardless. */
  names: Iterable<string>;
  /** EXACTLY the manifest's declared `guest.calls` (§12.10) — the local service ids this
   *  realm may reach on a co-resident guest, as signed. What tells a bare `host.call` name
   *  from one of this bundle's own modules: declared here, it is a cross-realm call;
   *  otherwise a module. */
  localServices?: ReadonlySet<string>;
  /** What `node/sign`/`node/verify` sign and check under — THIS SLOT's scope, derived
   *  once at load (`slotSignScope`): an app slot gets `DOMAIN_guest ‖ app`, the link
   *  slot gets `DOMAIN_link_scope`. The host always chooses
   *  domain ‖ scope; the guest never supplies either. Without a scope both names are
   *  unavailable, because guest signing and scoped verification are never raw. */
  signScope?: SignScope;
  /** Raw-byte fs backend, already scoped to this app's keyspace by the shell
   *  (`scopedFs`). Optional: a node that only initiates never reads it. */
  fs?: Fs;
  /** The RAW net capability — sockets behind opaque link ids. Wired ONLY for a bundle
   *  that requires the `link` service, so nothing else can ever reach a descriptor
   *  whatever is installed (§1, capability-by-non-wiring). */
  rawNet?: RawNet;
  /** The platform's event loop. `names` decides whether this realm may reach it. */
  timers: HostTimers;
  /** The cross-realm call: how a name in `localServices` is answered. Wired for every
   *  realm — reaching one is a grant like any other, and the signed list above decides who
   *  holds it. */
  calls: SeamCalls;
}

/** Per-APP: this bundle's OWN WASM modules, by the logical names its manifest declared.
 *  Not a grant and not gated — calling one reaches nothing the guest does not already hold.
 *  The slot wires this private value directly, so there is no wider module namespace. */
export interface SeamModules {
  names: ReadonlySet<string>;
  /** Reach one of this app's modules by bare name. Async like every seam call;
   *  `deadlineMs` is the calling guest's remaining segment, never guest-supplied. */
  call: (name: string, payload: Uint8Array, deadlineMs?: number) => Promise<ModuleResult>;
}

/** Everything the seam needs, in the three groups that own it. */
export interface GuestSeamDeps {
  platform: SeamPlatform;
  grants: SeamGrants;
  modules: SeamModules;
}

/** What host CPU spent on a guest's behalf is added to: one invocation's accumulated
 *  execution (§4.3). The realm factory owns the rest of that record. */
export interface Spend {
  consumedMs: number;
}

/** The calling guest's execution segment, as the seam sees it. Host plumbing, never ABI.
 *
 *  A CLASS rather than a record built per call: the record layer makes one of these for
 *  every hash, seal and write, and as a literal each one carried two closures of its own.
 *  Here `charge` and `detach` are on the prototype and the object is three fields. */
export class CallBudget {
  /** Set by a name whose answer is new work rather than the tail of what the caller was
   *  doing (`link/deliver`); read by the settlement, which then resumes the caller as a NEW
   *  turn under a fresh budget of its own ceiling instead of the invocation that made the
   *  call. The call's own handoff deadline is unchanged. */
  detached = false;

  /** @param remainingMs milliseconds left in the calling guest's segment, `Infinity` when
   *    unbudgeted — what a module call runs under. A caller with none left is refused
   *    HERE, so a spent budget cannot be built and no name below need ask again.
   *  @param causalClock the self-initiated root this call descends from, if any.
   *    Propagated across realm calls so the root pays for execution in every callee, never
   *    for time awaiting it.
   *  @param spend the invocation record host burn is billed to. NONE on the native target,
   *    where a module runs inside the guest's own armed segment and Go has already counted
   *    it — billing here would be a second charge for the same work. */
  constructor(
    readonly remainingMs: number,
    readonly causalClock: CausalClock | undefined,
    private readonly spend: Spend | undefined,
  ) {
    if (remainingMs <= 0) throw new Error(HOST_CALL_SPENT);
  }

  /** Add CPU the host burned ON THE GUEST'S BEHALF to the caller's segment — a module
   *  call, whose time is the guest's by §4.3 but is burned while that segment is closed.
   *  What it bounds that the handoff deadline cannot is CONCURRENT burn: a guest awaiting
   *  one module at a time spends wall clock at the same rate, so the deadline already stops
   *  it, but a guest fanning out to N workers burns N ms of CPU per ms of its own wait.
   *  Summing the measured burns holds that sum inside the window the invocation was
   *  admitted under, instead of multiplying it by however many modules the bundle ships. */
  charge(ms: number): void {
    if (ms <= 0 || this.spend === undefined) return;
    this.spend.consumedMs += ms;
    this.causalClock?.charge(ms);
  }

  detach(): void {
    this.detached = true;
  }
}

/** The host half of `host.call`. EVERY name answers a Promise — the seam is async,
 *  not any backend — so "forgetting the await" is the one calling convention and it is
 *  wrong for all of them alike. `budget` is the caller's segment, supplied by the realm. */
export type HostCall = (name: string, payload: Uint8Array, budget: CallBudget) => Promise<Uint8Array>;

export { HOST_TRANSFORM_NAMES } from "../core/domains.js";

/** The `crypto/` members of the legacy host transform table, as a template literal over
 *  `HOST_TRANSFORM_NAMES`, so
 *  the vocabulary a manifest is checked against and the table the seam dispatches through
 *  cannot drift. */
type CryptoName = `crypto/${HostTransformName}`;

/** The keys the dispatch table must cover, typed so a name added to the vocabulary without
 *  a handler is a compile error, and so is a handler whose name the loader would refuse.
 *
 *  Every one contains a `/`, which is load-bearing (§12.2): module names are held to
 *  `[A-Za-z0-9_-]`, so they cannot spell one of these — that is what lets the dispatch tell
 *  host names and module names apart by the name alone. */
type HandlerKey = CapabilityName | CryptoName;

/** One host transform's implementation: argument bytes in, response bytes out. A handler
 *  may answer inline (every crypto name, clock, link, timer) or round-trip (fs/*); the
 *  seam flattens both into the one Promise the guest awaits. */
type SeamHandler = (payload: Uint8Array, budget: CallBudget) => Uint8Array | Promise<Uint8Array>;

/** Residual host-transform table (§12.1). */
function hostTransforms(sodium: SeamCrypto): Record<CryptoName, SeamHandler> {
  return {
    "crypto/blake2b-256": (a) => sodium.crypto_generichash(32, a),
    // `subarray`, not `slice`: every primitive below reads its arguments into its own
    // storage before it returns, so a view is enough — and on the record layer's hot path
    // `slice` copied the whole payload once more on the way in, for nothing.
    "crypto/chacha20poly1305-ietf/seal": (a) => sodium.crypto_aead_chacha20poly1305_ietf_encrypt(a.subarray(44), null, null, a.subarray(0, 12), a.subarray(12, 44)),
    "crypto/chacha20poly1305-ietf/open": (a) => {
      try {
        const pt = sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, a.subarray(44), null, a.subarray(0, 12), a.subarray(12, 44));
        return concatBytes([ONE, pt]);
      } catch {
        return ZERO;
      }
    },
    // [sk 32][pk 32] -> [ok u8][shared 32]. ok=0: low-order point.
    "crypto/x25519/dh": (a) => {
      try {
        return concatBytes([ONE, sodium.crypto_scalarmult(a.subarray(0, 32), a.subarray(32, 64))]);
      } catch {
        return ZERO;
      }
    },
  };
}

/** Guest preamble: `host.call` and the one entrypoint, `handle` — nothing else. The
 *  entrypoint receives `[caller 32][body …]`. Application and local-service bodies use
 *  the callee's format and remain opaque to routing. The socket driver constructs
 *  raw-link event bodies using the kernel ABI in core/op-frame.ts (RUNTIME §12.2).
 *
 *  Every realm factory drives `handle` through the preamble's `__start`, having installed
 *  the three host functions it calls out through: `__host_call`, `__callDone` and
 *  `__callFail`. */
export function guestPreamble(): string {
  return GUEST_PREAMBLE;
}

const GUEST_PREAMBLE = `
"use strict";
let __callSeq = 0;
const __pending = Object.create(null);
globalThis.__resolveHostCall = (callId, bytes) => {
  const p = __pending[callId];
  if (!p) return;
  delete __pending[callId];
  p.resolve(new Uint8Array(bytes));
};
globalThis.__rejectHostCall = (callId, msg) => {
  const p = __pending[callId];
  if (!p) return;
  delete __pending[callId];
  p.reject(new Error(msg));
};
globalThis.host = {
  // EVERY name answers a Promise the guest awaits — there is no sync/async line to
  // fall on the wrong side of. A name the seam REFUSES (undeclared service, no such
  // name) still throws right here: a mis-uttered name is a programming error, and it
  // fails at the call site rather than as a rejection nobody awaits. Payload is a
  // plain ArrayBuffer — quickjs-emscripten's getArrayBuffer rejects a view.
  call(name, bytes) {
    const callId = ++__callSeq;
    const ab = bytes instanceof ArrayBuffer
      ? bytes
      : (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength)
        ? bytes.buffer
        : bytes.slice().buffer;
    // Issued BEFORE the table entry exists: every target settles through a microtask
    // attached to the seam's own promise, so nothing can resolve a call that is not
    // parked yet — and a synchronous refusal above leaves nothing behind to clean up.
    __host_call(name, callId, ab);
    let resolve, reject;
    const answer = new Promise((res, rej) => { resolve = res; reject = rej; });
    __pending[callId] = { resolve, reject };
    return answer;
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
const __fail = (id, e) => __callFail(id, String(e && e.message || e));
// The one way in: run handle on one invocation's input and report its answer as bytes
// through the host's __callDone / __callFail, so no guest promise ever crosses to the
// host. A synchronous answer is reported within this call, an async one when its promise
// settles. Answers 1 when the entrypoint handed its answer to a later turn — the realm is
// free for the next invocation although this one has not settled (realm-queue.ts).
globalThis.__start = (id, argBuf) => {
  // Cleared HERE rather than by the host, so the flag describes exactly this
  // invocation and a guest cannot leave it set for the next one.
  globalThis.__deferred = false;
  try {
    if (typeof globalThis.handle !== "function") throw new Error("guest: no entrypoint 'handle'");
    const out = globalThis.handle(new Uint8Array(argBuf));
    if (out && typeof out.then === "function") {
      out.then((v) => { try { __callDone(id, __norm(v)); } catch (e) { __fail(id, e); } },
        (e) => __fail(id, e));
    } else {
      __callDone(id, __norm(out));
    }
  } catch (e) {
    __fail(id, e);
  }
  return globalThis.__deferred === true ? 1 : 0;
};
`;

// ── the attribution prefix, host side ────────────────────────────────────────
//
// The ONLY bytes the host puts in front of a callee's format: one 32-byte id, unforgeable
// by a guest. There is exactly ONE host id — the zero id, whose events and loopback calls
// the host writes (a fired deadline re-enters as an ordinary loopback carrying the opaque
// body supplied when it was armed, so a second host id is unnecessary). Everything else
// non-zero is a peer or a co-resident app.
/** The host's own caller id: 32 zero bytes. No app label derives it. */
export const HOST_CALLER_ID = new Uint8Array(32);

/** The host-derived scope `node/sign` binds every guest signature to (§12.2):
 *  `app_len u8 ‖ app`, the admitted manifest's label. Never guest-supplied, and one slot
 *  per node holds a label, so a guest signs only within its own namespace; every node
 *  running an app under that label derives the same bytes, whoever authored it, which is
 *  what makes scoped signatures portable across a cohort. */
export function guestSignScope(app: string): Uint8Array {
  const appBytes = enc.encode(app);
  if (appBytes.length > 255) throw new Error("guest-seam: app name too long for a scope (>255 bytes)");
  const out = new Uint8Array(1 + appBytes.length);
  out[0] = appBytes.length;
  out.set(appBytes, 1);
  return out;
}

/** An ordinary app's signing scope: `DOMAIN_guest ‖ app`. Two slots on one node hold two
 *  labels, so they derive disjoint scopes. */
export function appSignScope(key: Keypair, app: string): SignScope {
  return { domain: DOMAIN_GUEST, scope: guestSignScope(app), key };
}

/** The one scoped-signature transcript: `domain ‖ scope ‖ message`. */
function scopedSigningInput(scope: Pick<SignScope, "domain" | "scope">, message: Uint8Array): Uint8Array {
  return concatBytes([scope.domain, scope.scope, message]);
}

/** Host-side twin of a slot's scoped SIGN/VERIFY (§12.2). Same scope as `appSignScope`. */
export function appSigner(sodium: SeamCrypto, key: Keypair, app: string): {
  sign(msg: Uint8Array): Uint8Array;
  /** False on a signature that does not verify under `(scope, pk)`; a `sig` or `pk` of
   *  the wrong shape ALSO reads false (the seam's `node/verify` refuses a mis-framed
   *  payload by throwing; a caller-facing verifier has no caller left to explain to). */
  verify(pk: Uint8Array, sig: Uint8Array, msg: Uint8Array): boolean;
} {
  const scope = appSignScope(key, app);
  return {
    sign(msg) {
      return sodium.crypto_sign_detached(scopedSigningInput(scope, msg), scope.key.privateKey);
    },
    verify(pk, sig, msg) {
      try {
        return sodium.crypto_sign_verify_detached(sig, scopedSigningInput(scope, msg), pk);
      } catch {
        return false;
      }
    },
  };
}

/** The `link` capability's signing scope: `DOMAIN_link_scope`, signed by the
 *  node's identity key. The suffix is the slot occupant's business and the host does not
 *  look at it — the transport bundle tags its own handshake format inside it, so changing
 *  that format is a bundle update and never a kernel change. Network separation belongs
 *  to the transport's signed handshake content (§12.6). */
export function linkSignScope(key: Keypair): SignScope {
  return { domain: DOMAIN_LINK_SCOPE, scope: new Uint8Array(0), key };
}

/** The one scope a slot's SIGN/VERIFY signs under — derived once at load (§12.2):
 *  `DOMAIN_guest ‖ app` for an ordinary app slot, `DOMAIN_link_scope` for the slot
 *  reaching `link`. A function of admitted facts only: nothing local, nothing from
 *  `protocols`, which move per version and would silently restate what signed records
 *  mean, and not the author, whose key can rotate or fork under the same label. */
export function slotSignScope(node: { identity: Keypair }, app: string, links: boolean): SignScope {
  return links
    ? linkSignScope(node.identity)
    : appSignScope(node.identity, app);
}

// Host-side allocation bounds for guest-controlled sizes: the realm's own memory limit
// does not cover host allocations the guest requests, so the seam caps them itself.
const MAX_RANDOM_BYTES = 1 << 20; // 1 MiB per node/random call
const ONE = new Uint8Array([1]);
const ZERO = new Uint8Array([0]);
const NONE = new Uint8Array(0);
/** `grants.localServices`'s default: a realm whose manifest named no `guest.calls` reaches
 *  no local service, not every bare name. */
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
  const { sodium, now } = platform;
  const fs = () => {
    if (!grants.fs) throw new Error("guest-seam: fs.* used but no fs backend wired");
    return grants.fs;
  };
  const rawNet = () => {
    if (!grants.rawNet) throw new Error("guest-seam: link.* used but no raw net is wired");
    return grants.rawNet;
  };
  const timers = grants.timers;
  // Null-prototype, so the table holds exactly what is written here: a plain object
  // literal would answer `handlers["toString"]` with an inherited function.
  const handlers: Record<string, SeamHandler> = Object.assign(Object.create(null), {
    // ── the primitive seam (§12.1): functions of bytes the guest already holds, so
    // there is nothing to grant. The bundle's own modules are the other ungated half.
    ...hostTransforms(sodium),
    // ── authorities: each reaches something no confined guest can hold ──────────
    // node/sign and node/verify are scoped, never raw, to THIS SLOT's one scope,
    // derived at load: an app slot's own `DOMAIN_guest ‖ app`, the link
    // slot's `DOMAIN_link_scope`. The guest never picks a namespace.
    "node/sign": (payload) => {
      const s = grants.signScope;
      if (!s) throw new Error("guest-seam: node/sign needs a slot-derived scope (signing is never raw)");
      return sodium.crypto_sign_detached(scopedSigningInput(s, payload), s.key.privateKey);
    },
    // node/verify — [pk 32][sig 64][msg …] → [ok u8]. Scoped like node/sign: the caller
    // supplies the key but never the scope, so a signature under any other scope answers
    // [0]. A payload too short to hold both throws rather than answering [0] — that is a
    // mis-framed call, not a signature that failed. An empty `msg` is legitimate, so the
    // bound is exactly the fixed prefix.
    "node/verify": (payload) => {
      const s = grants.signScope;
      if (!s) {
        throw new Error("guest-seam: node/verify needs a slot-derived scope (verification is never raw)");
      }
      if (payload.length < 96) throw new Error("guest-seam: node/verify takes [pk 32][sig 64][msg ..]");
      try {
        return sodium.crypto_sign_verify_detached(payload.subarray(32, 96), scopedSigningInput(s, payload.subarray(96)), payload.subarray(0, 32)) ? ONE : ZERO;
      } catch {
        return ZERO;
      }
    },
    "node/random": (payload) => {
      const n = readU32BE(payload, 0);
      if (n > MAX_RANDOM_BYTES) throw new Error("guest-seam: node/random size over cap");
      return sodium.randombytes_buf(n);
    },
    // ── fs: raw bytes under an opaque key. Every one round-trips, so each returns a
    // Promise the guest awaits — the seam is what is async, not the backend (§12.1).
    "fs/get": (payload) => fs().get(dec.decode(payload)).then((v) => (v ? concatBytes([ONE, v]) : ZERO)),
    // Views rather than copies, here and in `link/send`: the payload is already this call's
    // own copy, and every backend copies or writes what it is handed.
    "fs/put": (payload) => {
      const klen = readU32BE(payload, 0);
      const key = dec.decode(payload.subarray(4, 4 + klen));
      return fs().put(key, payload.subarray(4 + klen)).then(() => NONE);
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
    // ── raw net: bytes over an opaque link id, the socket-side twin of `fs` (§12.1).
    // No peer, no protocol id, no correlation: those are the transport's own. Inbound
    // bytes arrive the other way, as ordinary invocations of the transport's `handle`.
    "link/open": (payload) => {
      const link = rawNet().open(dec.decode(payload));
      const out = new Uint8Array(5);
      writeU32BE(out, 0, link.linkId);
      out[4] = link.stream ? 1 : 0;
      return out;
    },
    "link/send": (payload) => {
      rawNet().send(readU32BE(payload, 0), payload.subarray(4));
      return NONE;
    },
    "link/close": (payload) => {
      rawNet().close(readU32BE(payload, 0), payload[4] === 1);
      return NONE;
    },
    // Inbound attributed delivery (§12.10), the one `link` name that carries something
    // INTO the node rather than out of it: `[claimLen u8][claim][attribution 32]
    // [payload …]`. The attribution is fixed at the kernel's caller-id width — it IS
    // that field, filled with the authenticated sender — so nothing here is
    // length-delimited except the claim, and the payload simply runs to the end. One
    // request per call is what makes that safe.
    //
    // The answer is the occupant's next turn, not the tail of the read that carried the
    // request: the reply it writes is new work on a link every request shares, and a
    // claimant that spends the read's whole deadline would leave that write to a turn with
    // nothing left — a record the budget refuses halfway is a hole in the stream (§12.3).
    "link/deliver": (payload, budget) => {
      budget.detach();
      const attrAt = 1 + payload[0];
      // Everything past the claim is ALREADY `[attribution 32][payload …]`, which is the
      // shape a realm is entered with — this body writes those two fields in that order
      // and adjacent. So the frame handed on is a view of this call, never the two halves
      // taken apart here and copied back together one layer down.
      return rawNet().deliver(dec.decode(payload.subarray(1, attrAt)), payload.subarray(attrAt), budget.remainingMs, budget.causalClock);
    },
    // ── timers: the platform's event loop ─────────────────────────────────────
    "timer/arm": (payload) => {
      if (payload.byteLength !== 8) throw new Error("guest: timer/arm requires [ms u32][tag 4]");
      timers.arm(readU32BE(payload, 0), payload.subarray(4));
      return NONE;
    },
    "timer/clear": (payload) => {
      if (payload.byteLength !== 0) throw new Error("guest: timer/clear requires an empty body");
      timers.clear();
      return NONE;
    },
  } satisfies Record<HandlerKey, SeamHandler>);
  return handlers;
}

/** The one `host.call` a realm runs against: the gate in front of `hostCatalog`.
 *  Every name ANSWERS a Promise — the one shape a guest can read, so "forgetting the
 *  await" is wrong for all of them alike and there is no line to version. Failures keep
 *  their old voice: a refusal (undeclared service, unknown name, uninstalled module,
 *  spent budget) and a handler that throws inline both throw AT THE CALL SITE —
 *  programming errors fail loudly where they were made, awaited or not — while a call
 *  that round-trips fails as its own rejected Promise. Serialization is the realm's,
 *  not here. */
export function createGuestSeam(deps: GuestSeamDeps): HostCall {
  const { platform, grants, modules } = deps;
  // Checked at runtime, not only in the types: the native target evaluates the COMPILED
  // JS of this file (§12.9), where a TypeScript signature enforces nothing — and a gate
  // that holds on one of two targets is not a gate.
  if (grants.names === undefined) {
    throw new Error("guest-seam: grants.names is required — pass the manifest's declared guest.requires");
  }
  const allowed = new Set(grants.names);
  const localServices = grants.localServices ?? EMPTY_SET;
  const handlers = hostCatalog(platform, grants);
  return (name, payload, budget) => {
    // ONE catalog, three sources of names, resolved in DECLARATION order (§12.2). A
    // name THIS realm declared as a local service is another realm's, however it is
    // spelled: the id is an ordinary claim and may carry a `/` like any other, so
    // asking the declaration before the charset is what keeps one vocabulary from
    // becoming two. It can never shadow a host method — the loader refuses a
    // `guest.calls` entry whose head is a known service (bundle.ts). The callee answers
    // on a later turn, never inside this guest's frame; an id nothing claims is refused
    // by name rather than parked on a promise no one will settle.
    if (localServices.has(name)) {
      // No budget check here or at the module call below: a `CallBudget` cannot exist with
      // nothing left, so the refusal has already happened at the guest's call site.
      const answer = grants.calls.call(name, payload, budget.remainingMs, budget.causalClock);
      if (!answer) throw new Error("guest-seam: no realm claims " + name);
      return answer;
    }
    // A `/` says a host method: the table lookup IS the dispatch, gated by the
    // method's SERVICE — an undeclared `node/random` is refused even beside a
    // declared `node/sign`, because the unit a manifest grants is the SERVICE.
    // `serviceOf` is a table lookup on the text before the first `/`, never a semantic
    // parse. An unknown name (or a primitive this host does not carry) reads
    // `undefined` and is refused regardless of the gate.
    if (name.includes("/")) {
      const svc = serviceOf(name);
      if (svc && !allowed.has(svc)) {
        throw new Error("guest-seam: " + name + " not declared by the bundle manifest guest.requires");
      }
      const fn = handlers[name];
      if (!fn) throw new Error("guest-seam: no such name " + name);
      // Flattened so the caller reads ONE shape: a handler that answered inline
      // (every crypto name, clock, link, timer) resolves in a microtask exactly like
      // a round-tripping one. An inline THROW propagates synchronously, on purpose —
      // see the contract above.
      //
      // The SYNCHRONOUS span is host compute spent on this caller's behalf: libsodium
      // runs ed25519, x25519 and the AEADs to completion before returning, while an
      // I/O name returns its promise having done nothing. Measuring exactly that span
      // bills the causal root (§12.3) for host CPU and leaves waiting free, with no
      // second list of which names are which to keep in step with the catalog. In
      // `finally` because an AEAD that rejects a bad tag has already done the whole
      // open. Not `budget.charge`: this is the root's pacing share, not the calling
      // realm's own execution segment (§4.3), which the host is not running inside.
      //
      // Only a timer root carries a clock, so the reading is skipped entirely for
      // peer- and host-initiated work — which is every seam call the transport makes
      // on the frame path, and the reason this measurement costs that path nothing.
      const owner = budget.causalClock;
      if (owner === undefined) return Promise.resolve(fn(payload, budget));
      const at = monotonicMs();
      try {
        return Promise.resolve(fn(payload, budget));
      } finally {
        owner.charge(monotonicMs() - at);
      }
    }
    // Any other name is one of THIS slot's private modules, by its manifest name. The
    // slot wired this value directly, so no name can reach another app. Ungated like
    // `crypto/*`. A name the app never installed is a typo, refused by name; a module
    // that runs and fails is a different event, and rejects like any other (§12.2).
    if (!modules.names.has(name)) {
      throw new Error("guest-seam: no such name " + name + " (this bundle installs no module by that name)");
    }
    // Module call charged to the caller's segment (§4.3).
    return modules.call(name, payload, budget.remainingMs).then(({ bytes, ms }) => {
      // Bill the module's OWN processing time (measured on the worker that ran
      // it), never the issue-to-settle wall clock — a burst of fire-and-forget
      // module calls serialized through one worker would otherwise charge their
      // queue wait quadratically.
      budget.charge(ms);
      // Null is the table's failure, empty is a module that said nothing (§12.2).
      // Folding them together would make every caller guess failure from a length.
      if (bytes === null) throw new Error("guest-seam: module " + name + " failed");
      return bytes;
    });
  };
}
