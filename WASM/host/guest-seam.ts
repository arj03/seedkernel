// `host.call(name, bytes)` (§12.2). One map per realm, built at construction from what
// the bundle declares, so an undeclared service has no handler at all (§12.1). Each host
// service's handlers live with its backend in services/; this file knows none of them.
import { concatBytes, readU32BE, ONE, ZERO } from "./util.js";
import { isService, type HostTransformName, type ServiceMethod, type ServiceName } from "./domains.js";
import type { ModuleResult } from "./bundle.js";
import { HOST_CALL_SPENT, type CausalClock } from "./realm-queue.js";

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

/** Argument bytes in, response bytes out, inline or async. */
export type SeamHandler = (payload: Uint8Array, budget: CallBudget) => Uint8Array | Promise<Uint8Array>;

/** One host service's handlers (services/), exactly its `HOST_SERVICES` calls: a missing
 *  or extra method is a compile error. Every name contains a `/`, which module names
 *  cannot (§12.4). */
export type ServiceHandlers<S extends ServiceName> = Record<ServiceMethod<S>, SeamHandler>;

/** The host services this node offers one slot. One left out is not offered. */
export type SeamServices = { [S in ServiceName]?: ServiceHandlers<S> };

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
  /** What this node offers. Only declared services are wired; a declared one missing here
   *  fails seam construction, so the bundle fails at install, not on first use. */
  services: SeamServices;
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
   *  @param spend the record host CPU time is billed to. */
  constructor(
    readonly remainingMs: number,
    readonly causalClock: CausalClock | undefined,
    private readonly spend: Spend,
  ) {
    if (remainingMs <= 0) throw new Error(HOST_CALL_SPENT);
  }

  /** Bill CPU the host spent for the guest outside its segment (a module call). This
   *  bounds concurrent use, which the wall-clock deadline cannot: N parallel module calls
   *  use N ms per ms waited. */
  charge(ms: number): void {
    if (ms <= 0) return;
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
export type HostCall = ((name: string, payload: Uint8Array, budget: CallBudget) => Uint8Array | Promise<Uint8Array>) & {
  /** Whether `name`'s handler is done with its payload when it returns, so the realm may
   *  lend it a view of its memory instead of a copy (engine-realm.ts). Absent: never. */
  borrows?(name: string): boolean;
};

export { HOST_TRANSFORM_NAMES } from "./domains.js";

/** The `crypto/` names, derived from `HOST_TRANSFORM_NAMES` so vocabulary and table
 *  cannot drift. */
type CryptoName = `crypto/${HostTransformName}`;

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
 *  installing `__host_call`, `__callDone` and `__callFail`, and settles a parked call
 *  through `__settleHostCall`. */
export function guestPreamble(): string {
  return GUEST_PREAMBLE;
}

const GUEST_PREAMBLE = `
"use strict";
let __callSeq = 0;
const __pending = Object.create(null);
globalThis.__settleHostCall = (callId, ok, v) => {
  const p = __pending[callId];
  if (!p) return;
  delete __pending[callId];
  if (ok) p.resolve(new Uint8Array(v));
  else p.reject(new Error(v));
};
// Bytes as the plain ArrayBuffer the realm reads (realm.c), copied only when a view covers
// part of its buffer.
function __ab(bytes, refusal) {
  if (bytes instanceof ArrayBuffer) return bytes;
  if (bytes instanceof Uint8Array) {
    return (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength) ? bytes.buffer : bytes.slice().buffer;
  }
  throw new Error(refusal);
}
globalThis.host = {
  // Every name answers a Promise. A refused name throws here, at the call site.
  call(name, bytes) {
    const callId = ++__callSeq;
    // The host answers in this frame when it already has the answer: with the bytes, or
    // with why they could not be handed over, which rejects. Otherwise it parks the call
    // and settles it on a later turn. Called before the table entry exists, so an answer
    // or a synchronous refusal leaves nothing to clean up.
    const now = __host_call(name, callId, __ab(bytes, "guest: host.call takes Uint8Array | ArrayBuffer"));
    if (typeof now === "string") return Promise.reject(new Error(now));
    if (now !== null && now !== undefined) return Promise.resolve(new Uint8Array(now));
    const parked = Promise.withResolvers();
    __pending[callId] = parked;
    return parked.promise;
  },
};
// Set by a guest whose answer will arrive in a later invocation of this realm, so the
// queue frees the realm at the end of the synchronous part (realm-queue.ts).
globalThis.__deferred = false;
const __norm = (out) => __ab(out, "guest: entrypoint must return Uint8Array | ArrayBuffer");
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

/** The `host.call` a realm runs against. A refusal (unreachable name, spent budget) or a
 *  synchronous handler error throws at the call site; a failed round trip rejects. The
 *  realm handles serialization. */
export function createGuestSeam({ sodium, requires, services, callLocal, modules }: GuestSeamDeps): HostCall {
  // Every reachable name. Install keeps modules, local ids and host names disjoint
  // (bundle.ts), so insertion order does not matter.
  const routes = new Map<string, SeamHandler>();
  const addHost = (handlers: Record<string, SeamHandler>) => {
    for (const [name, fn] of Object.entries(handlers)) routes.set(name, fn);
  };
  addHost(hostTransforms(sodium));
  for (const id of new Set(requires)) {
    // A service comes whole: declaring `node` wires `node/sign` and `node/verify`.
    if (isService(id)) {
      const handlers = services[id];
      if (handlers === undefined) throw new Error(`guest-seam: the bundle requires "${id}", which this node does not provide`);
      addHost(handlers);
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
  const seam: HostCall = (name, payload, budget) => {
    const route = routes.get(name);
    if (!route) throw new Error("guest-seam: no such name " + name + " (not crypto, a module, or declared in guest.requires)");
    return route(payload, budget);
  };
  // The crypto transforms, `node` and `fs` answer inline and keep nothing of their payload.
  seam.borrows = (name) => name.startsWith("crypto/") || name.startsWith("node/") || name.startsWith("fs/");
  return seam;
}
