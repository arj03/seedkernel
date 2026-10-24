// `host.call(name, bytes)` (§12.2). One map per realm, built at construction from what
// the bundle declares, so an undeclared service has no handler at all (§12.1).
import { concatBytes, writeU32BE, readU32BE, enc, dec, EMPTY } from "../services/util.js";
import { DOMAIN_GUEST, DOMAIN_LINK_SCOPE, isService, type HostTransformName, type ServiceMethod, type ServiceName } from "../services/domains.js";
import { type Fs } from "../services/fs.js";
import type { ModuleResult } from "./bundle.js";
import { HOST_CALL_SPENT, type CausalClock } from "./realm-queue.js";
import { OpArgs } from "../services/op-frame.js";
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
  /** A datagram socket for the occupant's UDP paths (§12.7); its reads arrive as
   *  `datagrams` events. */
  udpBind(): Promise<DatagramSocket>;
  /** A turn's datagrams, each `[socket u32][hostLen u8][host][port u16][len u16][bytes]`;
   *  one that fails is lost. */
  udpSend(batch: Uint8Array): void;
  udpClose(id: number): void;
}

/** A bound socket: socket 0 when refused or failed. `addresses` are every address this
 *  machine's sockets are reached at, `\n`-separated; which are candidates is the
 *  occupant's. */
export interface DatagramSocket { id: number; port: number; addresses: string }

/** The `link` backend: the driver's raw links plus the shell's claim routing. */
export interface LinkBackend extends RawNet {
  /** Route one request the occupant decoded from its links to the claim's realm, called
   *  with `[attribution 32][payload ...]` (§12.10). An unreachable claim and a failed
   *  handler both answer empty. It enters another realm, so the caller must not wait on it
   *  in the same turn; the answer resumes the caller as a new turn (`CallBudget.detach`). */
  deliver(claim: string, framed: Uint8Array, deadlineMs?: number, causalClock?: CausalClock): Promise<Uint8Array>;
  /** The occupant's word on its own standing, in its own format, told each time it
   *  changes; the host passes it to the embedder unread. */
  status(status: Uint8Array): void;
}

/** One replaceable wake, delivered as the `wake` host event. */
export interface HostTimers {
  arm(ms: number): void;
  /** Cancel the armed wake; a wake already in flight cannot be retracted. */
  clear(): void;
}

/** The loader's host slots (§12.9): keep a host blob as the one to run next, or refuse it
 *  with the reason. */
export interface HostStaging {
  stage(blob: Uint8Array): void | Promise<void>;
}

/** What stands behind each host service. */
export interface SeamBackends {
  /** This slot's signing scope (`slotSignScope`): signing is never raw. */
  node: SignScope;
  /** Already scoped to this app (`scopedFs`). */
  fs: Fs;
  timer: HostTimers;
  link: LinkBackend;
  host: HostStaging;
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

export { HOST_TRANSFORM_NAMES } from "../services/domains.js";

/** The `crypto/` names, derived from `HOST_TRANSFORM_NAMES` so vocabulary and table
 *  cannot drift. */
type CryptoName = `crypto/${HostTransformName}`;

/** Argument bytes in, response bytes out, inline or async. */
type SeamHandler = (payload: Uint8Array, budget: CallBudget) => Uint8Array | Promise<Uint8Array>;

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

/** The host's own caller id: 32 zero bytes, which no app label derives. Every other id is
 *  a peer or a co-resident app. */
export const HOST_CALLER_ID = new Uint8Array(32);

/** An ordinary app's signing scope (§12.2): `DOMAIN_guest ‖ app_len u8 ‖ app`. Derived
 *  from the label, so every node running the app derives the same bytes. */
export function appSignScope(key: Keypair, app: string): SignScope {
  const appBytes = enc.encode(app);
  if (appBytes.length > 255) throw new Error("guest-seam: app name too long for a scope (>255 bytes)");
  return { domain: DOMAIN_GUEST, scope: concatBytes([Uint8Array.of(appBytes.length), appBytes]), key };
}

/** A slot's signing scope, derived at load from admitted facts only (§12.2): never
 *  `protocols`, which change between versions, nor the author, whose key can rotate. The
 *  `link` slot signs under `DOMAIN_link_scope` with an empty suffix; the transport tags its
 *  own handshake format inside the message, so changing it needs no host change. */
export function slotSignScope(node: { identity: Keypair }, app: string, links: boolean): SignScope {
  return links ? { domain: DOMAIN_LINK_SCOPE, scope: EMPTY, key: node.identity } : appSignScope(node.identity, app);
}

/** Sign and verify under one scope, over `domain ‖ scope ‖ msg`: `node/sign` and
 *  `node/verify`, and their host-side twin `appSigner`. */
function scopedSigner(sodium: SeamCrypto, scope: SignScope): {
  sign(msg: Uint8Array): Uint8Array;
  /** False on a bad signature, and on a `sig` or `pk` of the wrong shape. */
  verify(pk: Uint8Array, sig: Uint8Array, msg: Uint8Array): boolean;
} {
  const input = (msg: Uint8Array) => concatBytes([scope.domain, scope.scope, msg]);
  return {
    sign(msg) {
      return sodium.crypto_sign_detached(input(msg), scope.key.privateKey);
    },
    verify(pk, sig, msg) {
      try {
        return sodium.crypto_sign_verify_detached(sig, input(msg), pk);
      } catch {
        return false;
      }
    },
  };
}

/** Host-side twin of a slot's scoped SIGN/VERIFY (§12.2). */
export function appSigner(sodium: SeamCrypto, key: Keypair, app: string): ReturnType<typeof scopedSigner> {
  return scopedSigner(sodium, appSignScope(key, app));
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
  node: (s, sodium) => {
    const signer = scopedSigner(sodium, s);
    return {
      "node/sign": (payload) => signer.sign(payload),
      // [pk 32][sig 64][msg ...] -> [ok u8]. Too short for the prefix throws; an empty msg
      // is valid.
      "node/verify": (payload) => {
        if (payload.length < 96) throw new Error("guest-seam: node/verify takes [pk 32][sig 64][msg ..]");
        return signer.verify(payload.subarray(0, 32), payload.subarray(32, 96), payload.subarray(96)) ? ONE : ZERO;
      },
    };
  },
  fs: (fs) => ({
    "fs/get": (payload) => fs.get(dec.decode(payload)).then((v) => (v ? concatBytes([ONE, v]) : ZERO)),
    // Views, not copies: the payload already belongs to this call, and backends copy.
    "fs/put": (payload) => {
      const klen = readU32BE(payload, 0);
      const key = dec.decode(payload.subarray(4, 4 + klen));
      return fs.put(key, payload.subarray(4 + klen)).then(() => EMPTY);
    },
    // -> [count u32]([len u32][key utf8])*
    "fs/list": (payload) => fs.list(payload.length ? dec.decode(payload) : undefined).then((keys) => {
      const out = new OpArgs().u32(keys.length);
      for (const k of keys) out.text(k);
      return out.build();
    }),
    "fs/delete": (payload) => fs.delete(dec.decode(payload)).then(() => EMPTY),
    // -> [size u32], all ones for absent.
    "fs/size": (payload) => fs.size(dec.decode(payload))
      .then((sz) => new OpArgs().u32(sz < 0 ? 0xffffffff : sz).build()),
    "fs/stat": () => fs.stat().then((s) => concatBytes([u64be(s.used), u64be(s.available)])),
  }),
  host: (staging) => ({
    "host/stage": async (payload) => { await staging.stage(payload); return EMPTY; },
  }),
  timer: (timers) => ({
    "timer/arm": (payload) => {
      if (payload.byteLength !== 4) throw new Error("guest: timer/arm requires [ms u32]");
      timers.arm(readU32BE(payload, 0));
      return EMPTY;
    },
    "timer/clear": (payload) => {
      if (payload.byteLength !== 0) throw new Error("guest: timer/clear requires an empty body");
      timers.clear();
      return EMPTY;
    },
  }),
  // Raw bytes over an opaque link id (§12.1); inbound bytes arrive as `handle` events.
  link: (net) => ({
    // -> [link u32][stream u8], link 0 for no route.
    "link/open": (payload) => {
      const link = net.open(dec.decode(payload));
      return new OpArgs().u32(link.linkId).u8(link.stream ? 1 : 0).build();
    },
    "link/send": (payload) => {
      net.send(readU32BE(payload, 0), payload.subarray(4));
      return EMPTY;
    },
    "link/close": (payload) => {
      net.close(readU32BE(payload, 0), payload[4] === 1);
      return EMPTY;
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
    // The occupant's standing, in its own format, for the embedder.
    "link/status": (payload) => {
      net.status(payload.slice());
      return EMPTY;
    },
    // -> [socket u32][port u16][addresses utf8], socket 0 for none.
    "link/udpBind": () => net.udpBind()
      .then((s) => new OpArgs().u32(s.id).u16(s.port).bytes(enc.encode(s.addresses)).build()),
    "link/udpSend": (payload) => {
      net.udpSend(payload);
      return EMPTY;
    },
    "link/udpClose": (payload) => {
      net.udpClose(readU32BE(payload, 0));
      return EMPTY;
    },
  }),
};

/** The `host.call` a realm runs against. A refusal (unreachable name, spent budget) or a
 *  synchronous handler error throws at the call site; a failed round trip rejects. The
 *  realm handles serialization. */
export function createGuestSeam({ sodium, requires, backends, callLocal, modules }: GuestSeamDeps): HostCall {
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
  const seam: HostCall = (name, payload, budget) => {
    const route = routes.get(name);
    if (!route) throw new Error("guest-seam: no such name " + name + " (not crypto, a module, or declared in guest.requires)");
    return route(payload, budget);
  };
  // The crypto transforms and `node` answer inline and keep nothing of their payload.
  seam.borrows = (name) => name.startsWith("crypto/") || name.startsWith("node/");
  return seam;
}
