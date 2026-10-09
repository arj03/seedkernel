// `host.call(name, bytes)` (§12.2). One map per realm, built at construction from what
// the bundle declares, so an undeclared service has no handler at all (§12.1).
import { concatBytes, writeU32BE, readU32BE, enc, dec } from "../services/util.js";
import { DOMAIN_GUEST, DOMAIN_LINK_SCOPE, isService, type HostTransformName, type ServiceMethod, type ServiceName } from "../services/domains.js";
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

/** The libsodium functions the host crypto names use. */
export interface SeamCrypto {
  crypto_generichash(hashLength: number, message: Uint8Array, key: Uint8Array | null): Uint8Array;
  crypto_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
  crypto_sign_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
  randombytes_buf(n: number): Uint8Array;
  crypto_aead_chacha20poly1305_ietf_encrypt(message: Uint8Array, additional_data: Uint8Array | null, secret_nonce: Uint8Array | null, public_nonce: Uint8Array, key: Uint8Array): Uint8Array;
  crypto_aead_chacha20poly1305_ietf_decrypt(secret_nonce: Uint8Array | null, ciphertext: Uint8Array, additional_data: Uint8Array | null, public_nonce: Uint8Array, key: Uint8Array): Uint8Array;
  crypto_scalarmult(sk: Uint8Array, pk: Uint8Array): Uint8Array;
}

/** Raw links (§12.1): bytes over an opaque host-assigned link id. The socket driver's
 *  half of the `link` service. */
export interface RawNet {
  /** Open an opaque destination; id 0 means no route (§12.1). */
  open(dest: string): { linkId: number; stream: boolean };
  /** Write whole bytes to a link; silently dropped if the link is gone. */
  send(linkId: number, bytes: Uint8Array): void;
  /** Tear a link down; `graceful` flushes already-written bytes first. */
  close(linkId: number, graceful: boolean): void;
}

/** The `link` backend: the driver's raw links plus the shell's claim routing. */
export interface LinkBackend extends RawNet {
  /** Route one request the occupant decoded from its links to the claim's realm, called
   *  with `[attribution 32][payload ...]` (§12.10). An unreachable claim and a failed
   *  handler both answer empty. It enters another realm, so the caller must not wait on it
   *  in the same turn; the answer resumes the caller as a new turn (`CallBudget.detach`). */
  deliver(claim: string, framed: Uint8Array, deadlineMs?: number, causalClock?: CausalClock): Promise<Uint8Array>;
  /** The occupant's word on its relay's state, and on who is linked now and how each is
   *  reached, as its `relayState` and `routes` ops answer them: told each time either
   *  changes. */
  status(status: Uint8Array): void;
}

/** One replaceable wake, delivered as the `wake` host event. */
export interface HostTimers {
  arm(ms: number): void;
  /** Cancel the armed wake; a wake already in flight cannot be retracted. */
  clear(): void;
}

/** What stands behind each host service. */
export interface SeamBackends {
  /** This slot's signing scope (`slotSignScope`): signing is never raw. */
  node: SignScope;
  /** Already scoped to this app (`scopedFs`). */
  fs: Fs;
  timer: HostTimers;
  link: LinkBackend;
}

/** Cross-realm call by a local service id. `null` when nothing claims it. */
export type LocalCall = (id: string, payload: Uint8Array, deadlineMs?: number,
  causalClock?: CausalClock) => Promise<Uint8Array> | null;

/** This bundle's own WASM modules, by manifest name. Calling one reaches nothing the
 *  guest does not already have. */
export interface SeamModules {
  names: ReadonlySet<string>;
  /** `deadlineMs` is the calling guest's remaining segment, never guest-supplied. */
  call: (name: string, payload: Uint8Array, deadlineMs?: number) => Promise<ModuleResult>;
}

export interface GuestSeamDeps {
  sodium: SeamCrypto;
  /** Exactly the signed `guest.requires` (§12.2): host services and local service ids. */
  requires: Iterable<string>;
  /** What this node provides. Only declared services are read; a declared one missing
   *  here fails seam construction, so the bundle fails at install, not on first use. */
  backends: Partial<SeamBackends>;
  /** How a declared local service id is answered, resolved at call time. */
  callLocal: LocalCall;
  modules: SeamModules;
}

/** One invocation's accumulated execution time, including host CPU spent on its behalf
 *  (§4.3). */
export interface Spend {
  consumedMs: number;
}

/** The calling guest's execution segment, as the seam sees it. A class because one is
 *  built per host call, on the record layer's hot path. */
export class CallBudget {
  /** Set by a name whose answer is new work (`link/deliver`): the caller resumes as a new
   *  turn under a fresh budget. The handoff deadline is unchanged. */
  detached = false;

  /** @param remainingMs what is left of the segment (`Infinity` when unbudgeted). Zero
   *    is refused here, so no handler needs to check again.
   *  @param causalClock the clock of the self-initiated work this call belongs to, if any.
   *  @param spend the record host CPU time is billed to. None on native, where Go already
   *    counts module time inside the guest's segment. */
  constructor(
    readonly remainingMs: number,
    readonly causalClock: CausalClock | undefined,
    private readonly spend: Spend | undefined,
  ) {
    if (remainingMs <= 0) throw new Error(HOST_CALL_SPENT);
  }

  /** Bill CPU the host spent for the guest outside its segment (a module call). This
   *  bounds concurrent use, which the wall-clock deadline cannot: N parallel module calls
   *  use N ms per ms waited. */
  charge(ms: number): void {
    if (ms <= 0 || this.spend === undefined) return;
    this.spend.consumedMs += ms;
    this.causalClock?.charge(ms);
  }

  detach(): void {
    this.detached = true;
  }
}

/** The host half of `host.call`. A handler that already has its answer returns the bytes,
 *  and the realm hands them to the guest in the frame that asked: no host promise, no
 *  deadline and no later turn, which is most of what a call costs. One that has to wait
 *  returns a Promise. The guest sees a Promise either way. */
export type HostCall = (name: string, payload: Uint8Array, budget: CallBudget) => Uint8Array | Promise<Uint8Array>;

export { HOST_TRANSFORM_NAMES } from "../services/domains.js";

/** The `crypto/` names, derived from `HOST_TRANSFORM_NAMES` so vocabulary and table
 *  cannot drift. */
type CryptoName = `crypto/${HostTransformName}`;

/** Argument bytes in, response bytes out, inline or async. */
type SeamHandler = (payload: Uint8Array, budget: CallBudget) => Uint8Array | Promise<Uint8Array>;

/** A resolved name: its answer, or a Promise of it. */
type Route = SeamHandler;

/** The host crypto transforms (§12.1). */
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

/** Guest preamble: `host.call` and the entrypoint, `handle`, which receives
 *  `[caller 32][body ...]`. Every realm factory calls `handle` through `__start`, after
 *  installing `__host_call`, `__callDone` and `__callFail`. */
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
    // The host answers in this frame when it already has the answer: with the bytes, or
    // with why they could not be handed over, which rejects. Otherwise it parks the call
    // and settles it on a later turn. Called before the table entry exists, so an answer
    // or a synchronous refusal leaves nothing to clean up.
    const now = __host_call(name, callId, ab);
    if (typeof now === "string") return Promise.reject(new Error(now));
    if (now !== null && now !== undefined) return Promise.resolve(new Uint8Array(now));
    let resolve, reject;
    const answer = new Promise((res, rej) => { resolve = res; reject = rej; });
    __pending[callId] = { resolve, reject };
    return answer;
  },
};
// Set by a guest whose answer will arrive in a later invocation of this realm, so the
// queue frees the realm at the end of the synchronous part (realm-queue.ts).
globalThis.__deferred = false;
function __norm(out) {
  if (out instanceof ArrayBuffer) return out;
  if (out instanceof Uint8Array) {
    return (out.byteOffset === 0 && out.byteLength === out.buffer.byteLength) ? out.buffer : out.slice().buffer;
  }
  throw new Error("guest: entrypoint must return Uint8Array | ArrayBuffer");
}
const __fail = (id, e) => __callFail(id, String(e && e.message || e));
// Run handle for one invocation and report its answer as bytes, so no guest promise
// reaches the host. Returns 1 when the invocation deferred.
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

/** A slot's signing scope, derived at load from admitted facts only (§12.2): never
 *  `protocols`, which change between versions, nor the author, whose key can rotate. */
export function slotSignScope(node: { identity: Keypair }, app: string, links: boolean): SignScope {
  return links
    ? linkSignScope(node.identity)
    : appSignScope(node.identity, app);
}

// The realm's memory limit does not cover host allocations, so the seam caps them itself.
const MAX_RANDOM_BYTES = 1 << 20; // 1 MiB per crypto/random call

/** The AEAD names' framing, `[npub 12][key 32][adLen u32][ad][body]`; empty `ad` is null. */
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

/** Each host service's handlers over its backend (§12.2). A missing or extra method is a
 *  compile error; every name contains a `/`, which module names cannot (§12.4). */
const SERVICES: {
  [S in ServiceName]: (backend: SeamBackends[S], sodium: SeamCrypto) => Record<ServiceMethod<S>, SeamHandler>
} = {
  // Signed under this slot's scope; the guest never picks a namespace.
  node: (s, sodium) => ({
    "node/sign": (payload) => sodium.crypto_sign_detached(scopedSigningInput(s, payload), s.key.privateKey),
    // [pk 32][sig 64][msg ...] -> [ok u8]. Too short for the prefix throws; an empty msg
    // is valid.
    "node/verify": (payload) => {
      if (payload.length < 96) throw new Error("guest-seam: node/verify takes [pk 32][sig 64][msg ..]");
      try {
        return sodium.crypto_sign_verify_detached(payload.subarray(32, 96), scopedSigningInput(s, payload.subarray(96)), payload.subarray(0, 32)) ? ONE : ZERO;
      } catch {
        return ZERO;
      }
    },
  }),
  fs: (fs) => ({
    "fs/get": (payload) => fs.get(dec.decode(payload)).then((v) => (v ? concatBytes([ONE, v]) : ZERO)),
    // Views, not copies: the payload already belongs to this call, and backends copy.
    "fs/put": (payload) => {
      const klen = readU32BE(payload, 0);
      const key = dec.decode(payload.subarray(4, 4 + klen));
      return fs.put(key, payload.subarray(4 + klen)).then(() => NONE);
    },
    "fs/list": (payload) => {
      const prefix = payload.length ? dec.decode(payload) : undefined;
      return fs.list(prefix).then((keys) => {
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
    "fs/delete": (payload) => fs.delete(dec.decode(payload)).then(() => NONE),
    "fs/size": (payload) => fs.size(dec.decode(payload)).then((sz) => {
      const out = new Uint8Array(4);
      writeU32BE(out, 0, sz < 0 ? 0xffffffff : sz);
      return out;
    }),
    "fs/stat": () => fs.stat().then((s) => concatBytes([u64be(s.used), u64be(s.available)])),
  }),
  timer: (timers) => ({
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
  }),
  // Raw bytes over an opaque link id (§12.1); inbound bytes arrive as `handle` events.
  link: (net) => ({
    "link/open": (payload) => {
      const link = net.open(dec.decode(payload));
      const out = new Uint8Array(5);
      writeU32BE(out, 0, link.linkId);
      out[4] = link.stream ? 1 : 0;
      return out;
    },
    "link/send": (payload) => {
      net.send(readU32BE(payload, 0), payload.subarray(4));
      return NONE;
    },
    "link/close": (payload) => {
      net.close(readU32BE(payload, 0), payload[4] === 1);
      return NONE;
    },
    // [claimLen u8][claim][attribution 32][payload ...] (§12.10). Detached: the reply is
    // new work on a shared link and must not inherit a read's spent budget, since a record
    // cut halfway breaks the stream (§12.3). Everything after the claim is already the
    // realm argument, so it is passed on as a view.
    "link/deliver": (payload, budget) => {
      budget.detach();
      const attrAt = 1 + payload[0];
      return net.deliver(dec.decode(payload.subarray(1, attrAt)), payload.subarray(attrAt), budget.remainingMs, budget.causalClock);
    },
    // The relay's state and who is linked now, `[relay u8][key 32][direct u8]*`, said by the
    // occupant when either changes.
    "link/status": (payload) => {
      net.status(payload.slice());
      return NONE;
    },
  }),
};

/** A host handler as a route. Its synchronous part is host CPU spent for the caller
 *  (libsodium runs to completion; I/O returns a promise at once), so it can be billed to
 *  a wake's clock (§12.3) without listing which names compute. `finally`, because a
 *  rejected tag still did the work. Not `budget.charge`: this paces self-initiated work,
 *  it is not the realm's segment (§4.3). Only wakes carry a clock, so the frame path pays
 *  nothing. */
function charged(fn: SeamHandler): Route {
  return (payload, budget) => {
    const owner = budget.causalClock;
    if (owner === undefined) return fn(payload, budget);
    const at = monotonicMs();
    try {
      return fn(payload, budget);
    } finally {
      owner.charge(monotonicMs() - at);
    }
  };
}

/** The `host.call` a realm runs against. A refusal (unreachable name, spent budget) or a
 *  synchronous handler error throws at the call site; a failed round trip rejects. The
 *  realm handles serialization. */
export function createGuestSeam({ sodium, requires, backends, callLocal, modules }: GuestSeamDeps): HostCall {
  // Checked at runtime too, since native runs the compiled JS.
  if (requires === undefined) {
    throw new Error("guest-seam: requires is required — pass the manifest's declared guest.requires");
  }
  // Every reachable name. Install keeps modules, local ids and host names disjoint
  // (bundle.ts), so insertion order does not matter.
  const routes = new Map<string, Route>();
  const addHost = (handlers: Record<string, SeamHandler>) => {
    for (const [name, fn] of Object.entries(handlers)) routes.set(name, charged(fn));
  };
  addHost(hostTransforms(sodium));
  for (const id of new Set(requires)) {
    // A service comes whole: declaring `node` wires `node/sign` and `node/verify`.
    if (isService(id)) {
      const backend = backends[id];
      if (backend === undefined) throw new Error(`guest-seam: the bundle requires "${id}", which this node does not provide`);
      addHost(SERVICES[id](backend as never, sodium));
      continue;
    }
    // Any other declared name is another realm's service. One that nothing claims is
    // refused instead of waiting forever.
    routes.set(id, (payload, budget) => {
      const answer = callLocal(id, payload, budget.remainingMs, budget.causalClock);
      if (!answer) throw new Error("guest-seam: no realm claims " + id);
      return answer;
    });
  }
  // This slot's private modules, charged to the caller's segment (§4.3).
  for (const name of modules.names) {
    routes.set(name, (payload, budget) => modules.call(name, payload, budget.remainingMs).then(({ bytes, ms }) => {
      // The module's own processing time, not wall clock, or queue wait behind one worker
      // would be charged quadratically.
      budget.charge(ms);
      // Null is failure; empty is a module that said nothing (§12.2).
      if (bytes === null) throw new Error("guest-seam: module " + name + " failed");
      return bytes;
    }));
  }
  return (name, payload, budget) => {
    const route = routes.get(name);
    if (!route) throw new Error("guest-seam: no such name " + name + " (not crypto, a module, or declared in guest.requires)");
    return route(payload, budget);
  };
}
