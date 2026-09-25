// guest-seam — `host.call(name, bytes)` (§12.2). Ownership of the three deps:
//   platform — per node (crypto)
//   grants   — per realm (declared names, scopes, backends); unwired = unreachable
//   modules  — per app (this bundle's WASM, by logical name)
import { concatBytes, writeU32BE, readU32BE, enc, dec } from "../services/util.js";
import { DOMAIN_GUEST, DOMAIN_LINK_SCOPE, serviceOf, isService, type HostTransformName, type HostMethod } from "../services/domains.js";
import { type Fs } from "../services/fs.js";
import type { ModuleResult } from "./bundle.js";
import { HOST_CALL_SPENT, monotonicMs, type CausalClock } from "./realm-queue.js";
import type { Keypair } from "../services/subkeys.js";

/** What a scoped SIGN/VERIFY signs under (§12.2): `domain ‖ scope ‖ msg`, `msg` never
 *  parsed. */
export interface SignScope {
  /** `DOMAIN_guest` for an app slot, `DOMAIN_link_scope` for the link slot. */
  domain: Uint8Array;
  /** The app label for an app slot, empty for the link slot. */
  scope: Uint8Array;
  /** The node's identity keypair. */
  key: Keypair;
}

/** The libsodium surface the remaining host crypto names use. */
export interface SeamCrypto {
  crypto_generichash(hashLength: number, message: Uint8Array, key: Uint8Array | null): Uint8Array;
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

/** Raw-link service (§12.1): bytes over an opaque host-minted link id, plus `deliver`. */
export interface RawNet {
  /** Open an opaque destination; id 0 means no route (§12.1). */
  open(dest: string): { linkId: number; stream: boolean };
  /** Write whole bytes to a link; silently dropped if the link is gone. */
  send(linkId: number, bytes: Uint8Array): void;
  /** Tear a link down; `graceful` flushes already-written bytes first. */
  close(linkId: number, graceful: boolean): void;
  /** Route one request the occupant decoded off its links to the claim's realm, entered
   *  with `[attribution 32][payload …]` (§12.10). An unreachable claim and a failed handler
   *  both answer empty. It enters another realm, so the caller must fire it and return; the
   *  answer resumes the caller as a new turn (`CallBudget.detach`). */
  deliver(claim: string, framed: Uint8Array, deadlineMs?: number, causalClock?: CausalClock): Promise<Uint8Array>;
}

/** One replaceable wake, delivered as the `wake` host event. */
export interface HostTimers {
  arm(ms: number): void;
  /** Cancel the armed wake; a notification already in flight cannot be retracted. */
  clear(): void;
}

/** Per-node facts every realm shares; nothing here is gated. */
export interface SeamPlatform {
  sodium: SeamCrypto;
}

/** Per-realm grants. Non-wiring is the load-bearing gate (§1): a realm handed no `rawNet`
 *  can never acquire one. `names` makes an undeclared name a refusal by name. */
export interface SeamGrants {
  /** Exactly the signed `guest.requires` (§12.2): host services and local service ids. A
   *  host method resolves iff its service is listed; `crypto/*` and module names pass. */
  names: Iterable<string>;
  /** This slot's scope for `node/sign`/`node/verify` (`slotSignScope`). Without one, both
   *  are unavailable: signing is never raw. */
  signScope?: SignScope;
  /** The fs backend, already scoped to this app (`scopedFs`). */
  fs?: Fs;
  /** Wired only for a bundle requiring `link` (§1). */
  rawNet?: RawNet;
  timers: HostTimers;
  /** How a local service id in `names` is answered. */
  calls: SeamCalls;
}

/** This bundle's own WASM modules, by manifest name. Not a grant: calling one reaches
 *  nothing the guest does not already hold. */
export interface SeamModules {
  names: ReadonlySet<string>;
  /** `deadlineMs` is the calling guest's remaining segment, never guest-supplied. */
  call: (name: string, payload: Uint8Array, deadlineMs?: number) => Promise<ModuleResult>;
}

export interface GuestSeamDeps {
  platform: SeamPlatform;
  grants: SeamGrants;
  modules: SeamModules;
}

/** One invocation's accumulated execution, which host burn on its behalf is added to
 *  (§4.3). */
export interface Spend {
  consumedMs: number;
}

/** The calling guest's execution segment, as the seam sees it. A class, not a literal,
 *  because the record layer builds one per call. */
export class CallBudget {
  /** Set by a name whose answer is new work (`link/deliver`): the caller resumes as a new
   *  turn under a fresh budget. The handoff deadline is unchanged. */
  detached = false;

  /** @param remainingMs what is left of the segment (`Infinity` when unbudgeted); none
   *    left is refused here, so no name below asks again.
   *  @param causalClock the self-initiated root this call descends from, if any.
   *  @param spend the record host burn is billed to. None on native, where Go already
   *    counted the module time inside the guest's segment. */
  constructor(
    readonly remainingMs: number,
    readonly causalClock: CausalClock | undefined,
    private readonly spend: Spend | undefined,
  ) {
    if (remainingMs <= 0) throw new Error(HOST_CALL_SPENT);
  }

  /** Bill CPU the host burned for the guest while its segment was closed (a module call).
   *  This bounds concurrent burn, which the wall-clock deadline cannot: N parallel module
   *  calls burn N ms per ms waited. */
  charge(ms: number): void {
    if (ms <= 0 || this.spend === undefined) return;
    this.spend.consumedMs += ms;
    this.causalClock?.charge(ms);
  }

  detach(): void {
    this.detached = true;
  }
}

/** The host half of `host.call`: every name answers a Promise. */
export type HostCall = (name: string, payload: Uint8Array, budget: CallBudget) => Promise<Uint8Array>;

export { HOST_TRANSFORM_NAMES } from "../services/domains.js";

/** The `crypto/` names, derived from `HOST_TRANSFORM_NAMES` so vocabulary and table
 *  cannot drift. */
type CryptoName = `crypto/${HostTransformName}`;

/** Every key the dispatch table must cover; a missing or extra handler is a compile error.
 *  Each contains a `/`, which module names cannot (§12.4). */
type HandlerKey = HostMethod | CryptoName;

/** Argument bytes in, response bytes out, inline or async. */
type SeamHandler = (payload: Uint8Array, budget: CallBudget) => Uint8Array | Promise<Uint8Array>;

/** Residual host-transform table (§12.1). */
function hostTransforms(sodium: SeamCrypto): Record<CryptoName, SeamHandler> {
  return {
    // [outLen u8][keyLen u8][key][msg] -> outLen bytes (RFC 7693: 1..64, keyed or not).
    "crypto/blake2b": (a) => {
      const outLen = a[0], keyLen = a[1];
      if (a.length < 2 || outLen < 1 || outLen > 64 || keyLen > 64 || a.length < 2 + keyLen) {
        throw new Error("guest-seam: crypto/blake2b wants [outLen 1..64][keyLen 0..64][key][msg]");
      }
      return sodium.crypto_generichash(outLen, a.subarray(2 + keyLen), keyLen === 0 ? null : a.subarray(2, 2 + keyLen));
    },
    // [n u32] -> n bytes of host entropy.
    "crypto/random": (a) => {
      const n = readU32BE(a, 0);
      if (n > MAX_RANDOM_BYTES) throw new Error("guest-seam: crypto/random size over cap");
      return sodium.randombytes_buf(n);
    },
    // [npub 12][key 32][adLen u32][ad][msg] -> msg ‖ tag 16. Views, not copies: the
    // primitives copy their inputs, and this is the record layer's hot path.
    "crypto/chacha20poly1305-ietf/seal": (a) => {
      const { npub, key, ad, body } = aeadArgs(a, "seal");
      return sodium.crypto_aead_chacha20poly1305_ietf_encrypt(body, ad, null, npub, key);
    },
    // [npub 12][key 32][adLen u32][ad][ct ‖ tag] -> [1][pt] | [0]. A bad tag is an answer;
    // a mis-framed call throws.
    "crypto/chacha20poly1305-ietf/open": (a) => {
      const { npub, key, ad, body } = aeadArgs(a, "open");
      try {
        return concatBytes([ONE, sodium.crypto_aead_chacha20poly1305_ietf_decrypt(null, body, ad, npub, key)]);
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

/** Guest preamble: `host.call` and the one entrypoint, `handle`, which receives
 *  `[caller 32][body …]`. Every realm factory drives `handle` through `__start`, having
 *  installed `__host_call`, `__callDone` and `__callFail`. */
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
  // Every name answers a Promise. A refused name throws here, at the call site. The
  // payload crosses as a plain ArrayBuffer: quickjs-emscripten rejects a view.
  call(name, bytes) {
    const callId = ++__callSeq;
    const ab = bytes instanceof ArrayBuffer
      ? bytes
      : (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength)
        ? bytes.buffer
        : bytes.slice().buffer;
    // Issued before the table entry exists: every target settles on a later microtask,
    // and a synchronous refusal leaves nothing to clean up.
    __host_call(name, callId, ab);
    let resolve, reject;
    const answer = new Promise((res, rej) => { resolve = res; reject = rej; });
    __pending[callId] = { resolve, reject };
    return answer;
  },
};
// Set by a guest whose answer will arrive in a later invocation of this realm: the queue
// frees at the end of the synchronous segment instead of waiting (realm-queue.ts).
globalThis.__deferred = false;
function __norm(out) {
  if (out instanceof ArrayBuffer) return out;
  if (out instanceof Uint8Array) {
    return (out.byteOffset === 0 && out.byteLength === out.buffer.byteLength) ? out.buffer : out.slice().buffer;
  }
  throw new Error("guest: entrypoint must return Uint8Array | ArrayBuffer");
}
const __fail = (id, e) => __callFail(id, String(e && e.message || e));
// Run handle on one invocation and report its answer as bytes, so no guest promise crosses
// to the host. Answers 1 when the invocation deferred.
globalThis.__start = (id, argBuf) => {
  // Cleared here, so a guest cannot leave it set for the next invocation.
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

/** The host's own caller id: 32 zero bytes, which no app label derives. Every other id is
 *  a peer or a co-resident app. */
export const HOST_CALLER_ID = new Uint8Array(32);

/** The scope `node/sign` binds a guest signature to (§12.2): `app_len u8 ‖ app`. Derived
 *  from the label, so every node running the app derives the same bytes. */
export function guestSignScope(app: string): Uint8Array {
  const appBytes = enc.encode(app);
  if (appBytes.length > 255) throw new Error("guest-seam: app name too long for a scope (>255 bytes)");
  const out = new Uint8Array(1 + appBytes.length);
  out[0] = appBytes.length;
  out.set(appBytes, 1);
  return out;
}

/** An ordinary app's signing scope: `DOMAIN_guest ‖ app`. */
export function appSignScope(key: Keypair, app: string): SignScope {
  return { domain: DOMAIN_GUEST, scope: guestSignScope(app), key };
}

/** The one scoped-signature transcript: `domain ‖ scope ‖ message`. */
function scopedSigningInput(scope: Pick<SignScope, "domain" | "scope">, message: Uint8Array): Uint8Array {
  return concatBytes([scope.domain, scope.scope, message]);
}

/** Host-side twin of a slot's scoped SIGN/VERIFY (§12.2). */
export function appSigner(sodium: SeamCrypto, key: Keypair, app: string): {
  sign(msg: Uint8Array): Uint8Array;
  /** False on a bad signature, and on a `sig` or `pk` of the wrong shape. */
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

/** The `link` slot's signing scope: `DOMAIN_link_scope`, empty suffix. The transport tags
 *  its own handshake format inside the message, so changing it needs no host change. */
export function linkSignScope(key: Keypair): SignScope {
  return { domain: DOMAIN_LINK_SCOPE, scope: new Uint8Array(0), key };
}

/** A slot's one signing scope, derived at load from admitted facts only (§12.2) — never
 *  `protocols`, which move per version, nor the author, whose key can rotate. */
export function slotSignScope(node: { identity: Keypair }, app: string, links: boolean): SignScope {
  return links
    ? linkSignScope(node.identity)
    : appSignScope(node.identity, app);
}

// The realm's memory limit does not cover host allocations, so the seam caps them itself.
const MAX_RANDOM_BYTES = 1 << 20; // 1 MiB per crypto/random call

/** The AEAD names' framing, `[npub 12][key 32][adLen u32][ad][body]`; empty `ad` → null. */
function aeadArgs(a: Uint8Array, op: string): { npub: Uint8Array; key: Uint8Array; ad: Uint8Array | null; body: Uint8Array } {
  if (a.length < 48) throw new Error(`guest-seam: chacha20poly1305-ietf/${op} wants [npub 12][key 32][adLen u32][ad][bytes]`);
  const adLen = readU32BE(a, 44);
  if (adLen > a.length - 48) throw new Error(`guest-seam: chacha20poly1305-ietf/${op} associated data runs past the call`);
  return {
    npub: a.subarray(0, 12),
    key: a.subarray(12, 44),
    ad: adLen === 0 ? null : a.subarray(48, 48 + adLen),
    body: a.subarray(48 + adLen),
  };
}
const ONE = new Uint8Array([1]);
const ZERO = new Uint8Array([0]);
const NONE = new Uint8Array(0);

function u64be(value: number): Uint8Array {
  const out = new Uint8Array(8);
  writeU32BE(out, 0, Math.floor(value / 0x100000000));
  writeU32BE(out, 4, value >>> 0);
  return out;
}

/** The host names a guest may call (§12.2). `crypto/*` is ungated; the rest are
 *  authorities. */
function hostCatalog(platform: SeamPlatform, grants: SeamGrants): Record<string, SeamHandler> {
  const { sodium } = platform;
  const fs = () => {
    if (!grants.fs) throw new Error("guest-seam: fs.* used but no fs backend wired");
    return grants.fs;
  };
  const rawNet = () => {
    if (!grants.rawNet) throw new Error("guest-seam: link.* used but no raw net is wired");
    return grants.rawNet;
  };
  const timers = grants.timers;
  // Null-prototype, so `handlers["toString"]` is not an inherited function.
  const handlers: Record<string, SeamHandler> = Object.assign(Object.create(null), {
    ...hostTransforms(sodium),
    // Signed under this slot's scope; the guest never picks a namespace.
    "node/sign": (payload) => {
      const s = grants.signScope;
      if (!s) throw new Error("guest-seam: node/sign needs a slot-derived scope (signing is never raw)");
      return sodium.crypto_sign_detached(scopedSigningInput(s, payload), s.key.privateKey);
    },
    // [pk 32][sig 64][msg …] → [ok u8], under this slot's scope. Too short to hold the
    // prefix throws; an empty msg is legitimate.
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
    "fs/get": (payload) => fs().get(dec.decode(payload)).then((v) => (v ? concatBytes([ONE, v]) : ZERO)),
    // Views, not copies: the payload is already this call's own, and backends copy.
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
    // Raw bytes over an opaque link id (§12.1); inbound bytes arrive as `handle` events.
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
    // [claimLen u8][claim][attribution 32][payload …] (§12.10). Detached: the reply is new
    // work on a shared link, and must not inherit a read's spent budget — a record cut
    // halfway is a hole in the stream (§12.3). Everything past the claim is already the
    // realm argument, so it is passed on as a view.
    "link/deliver": (payload, budget) => {
      budget.detach();
      const attrAt = 1 + payload[0];
      return rawNet().deliver(dec.decode(payload.subarray(1, attrAt)), payload.subarray(attrAt), budget.remainingMs, budget.causalClock);
    },
    "timer/arm": (payload) => {
      if (payload.byteLength !== 4) throw new Error("guest: timer/arm requires [ms u32]");
      timers.arm(readU32BE(payload, 0));
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

/** The one `host.call` a realm runs against. A refusal (undeclared service, unknown name,
 *  missing module, spent budget) or an inline handler throw throws at the call site; a
 *  round trip that fails rejects. Serialization is the realm's. */
export function createGuestSeam(deps: GuestSeamDeps): HostCall {
  const { platform, grants, modules } = deps;
  // Checked at runtime too: native runs the compiled JS, where types enforce nothing.
  if (grants.names === undefined) {
    throw new Error("guest-seam: grants.names is required — pass the manifest's declared guest.requires");
  }
  const allowed = new Set(grants.names);
  const handlers = hostCatalog(platform, grants);
  // Declared names resolved once. Install keeps modules, local ids and host names disjoint
  // (bundle.ts), so lookup order decides nothing.
  const declared = new Map<string, (payload: Uint8Array, budget: CallBudget) => Promise<Uint8Array>>();
  // This slot's private modules, charged to the caller's segment (§4.3).
  for (const name of modules.names) {
    declared.set(name, (payload, budget) => modules.call(name, payload, budget.remainingMs).then(({ bytes, ms }) => {
      // The module's own processing time, not wall clock: queue wait behind one worker
      // would otherwise be charged quadratically.
      budget.charge(ms);
      // Null is failure; empty is a module that said nothing (§12.2).
      if (bytes === null) throw new Error("guest-seam: module " + name + " failed");
      return bytes;
    }));
  }
  // Every declared name that is not a host service is another realm's service. One that
  // nothing claims is refused rather than parked forever.
  for (const id of allowed) {
    if (isService(id)) continue;
    declared.set(id, (payload, budget) => {
      const answer = grants.calls.call(id, payload, budget.remainingMs, budget.causalClock);
      if (!answer) throw new Error("guest-seam: no realm claims " + id);
      return answer;
    });
  }
  return (name, payload, budget) => {
    const route = declared.get(name);
    if (route) return route(payload, budget);
    // Host names are gated by their SERVICE: declaring `node` grants `node/sign` and
    // `node/verify` together.
    const svc = serviceOf(name);
    if (svc && !allowed.has(svc)) {
      throw new Error("guest-seam: " + name + " not declared by the bundle manifest guest.requires");
    }
    const fn = handlers[name];
    if (!fn) throw new Error("guest-seam: no such name " + name);
    // The synchronous span is host CPU spent for the caller (libsodium runs to completion;
    // I/O returns a promise at once), so billing it to a timer root's clock (§12.3) needs
    // no list of which names compute. `finally`, because a rejected tag still did the work.
    // Not `budget.charge`: this is the root's pacing, not the realm's segment (§4.3).
    // Only timer roots carry a clock, so the frame path pays nothing.
    const owner = budget.causalClock;
    if (owner === undefined) return Promise.resolve(fn(payload, budget));
    const at = monotonicMs();
    try {
      return Promise.resolve(fn(payload, budget));
    } finally {
      owner.charge(monotonicMs() - at);
    }
  };
}
