// cap-bridge — the capability counterpart to `safe-js` (exported as
// `seedkernel-wasm/cap-bridge`). Given a safe-js realm, it services the guest's
// single `host.call(op, bytes)` seam from the kernel's *primitive* capabilities
// and nothing else: crypto primitives (sumo), net (send / requestMany / peers),
// fs (raw bytes under an opaque key), an installed-handler call, clock, and
// identity. Every op is application-neutral — the bridge has no idea it is
// hosting storage (or chat, or anything). All structure — content addressing,
// descriptor envelopes, the HAVE/OFFER/STORE wire format, Reed–Solomon, the
// nonce convention — is the guest's business, built on top of these primitives.
//
// This is what lets the seedkernel shell run an arbitrary signed guest: it
// constructs a cap-bridge from kernel primitives it already holds (README
// §13.2). A host-side caller that holds the same primitives constructs the
// identical bridge, so output orchestrated through the confined guest is
// byte-compatible with a host-side reference path.

import type { Fs } from "./fs.js";
import type { PeerId } from "./net.js";
import { toHex, fromHex, concatBytes, writeU32BE, readU32BE } from "./util.js";
import type { SafeRealmBridge } from "./safe-js.js";

/** The generic op catalog — the seam ABI. `capPreamble()` injects these as
 *  `const CAP_X = n;` into the guest, and the bridge switch reads them here, so
 *  guest and host can never drift. Numbers are stable wire identifiers. */
export const CAP = {
  HASH: 1,             // bytes -> 32B generic hash (blake2b / crypto_generichash)
  STREAM_XOR: 2,       // [nonce 24][key 32][msg] -> xchacha20 keystream XOR
  SIGN: 3,             // msg -> 64B detached ed25519 signature by this identity
  VERIFY: 4,           // [pk 32][sig 64][msg] -> [valid u8]
  IDENTITY: 5,         // -> this node's 32B public key
  RANDOM: 6,           // [n u32] -> n random bytes
  NET_SEND: 7,         // [peer 32][type u8][payload] -> [ok u8][resp]
  NET_REQUEST_MANY: 8, // [type u8][count u32][peer 32 …][plen u32][payload]
                       //   -> [count u32]{[peer 32][ok u8][len u32][bytes]}
  NET_PEERS: 9,        // -> [count u32][pk 32 …]
  FS_GET: 10,          // key(utf8) -> [0] | [1][bytes]
  FS_PUT: 11,          // [klen u32][key(utf8)][bytes] -> []
  FS_HAS: 12,          // key(utf8) -> [u8]
  FS_LIST: 13,         // prefix(utf8, may be empty) -> [count u32]{[klen u32][key]}
  FS_DELETE: 14,       // key(utf8) -> []
  FS_STAT: 15,         // -> [used u64 BE][available u64 BE]
  MODULE_CALL: 16,     // [nameLen u8][name][req] -> installed handler response bytes
  CLOCK: 17,           // -> now ms (u64 BE)
  FS_SIZE: 18,         // key(utf8) -> [size i32 BE] (-1 as 0xFFFFFFFF if absent) —
                       //   lets a policy layer rebuild a byte budget (quota) without
                       //   reading every value back. Appended (18) so 1–17 stay stable.
} as const;

/** The generated `const CAP_NAME = n;` block the guest is written against. */
export function capPreamble(): string {
  return Object.entries(CAP).map(([k, v]) => `const CAP_${k} = ${v};`).join("\n") + "\n";
}

/** Capability *domains* — named groups of ops. A bundle's signed manifest declares
 *  the domains its guest needs (its `caps`), and the shell expands them to the
 *  concrete op set it enforces (`allowedOps`) and to which backends it wires. This
 *  is the coarse, human-auditable capability vocabulary: "this app reaches net + fs",
 *  not a list of 18 op numbers. `ops` documents the ABI; `caps` is the grant. */
export const CAP_DOMAINS = {
  crypto: [CAP.HASH, CAP.STREAM_XOR, CAP.SIGN, CAP.VERIFY, CAP.IDENTITY, CAP.RANDOM],
  net:    [CAP.NET_SEND, CAP.NET_REQUEST_MANY, CAP.NET_PEERS],
  fs:     [CAP.FS_GET, CAP.FS_PUT, CAP.FS_HAS, CAP.FS_LIST, CAP.FS_DELETE, CAP.FS_STAT, CAP.FS_SIZE],
  module: [CAP.MODULE_CALL],
  clock:  [CAP.CLOCK],
} as const;

export type CapDomain = keyof typeof CAP_DOMAINS;

/** Expand declared capability domains to the concrete op numbers a bridge allows.
 *  Throws on an unknown domain so a typo in a manifest fails loudly rather than
 *  silently granting nothing (or, worse, everything). */
export function opsForCaps(domains: Iterable<string>): number[] {
  const out: number[] = [];
  for (const d of domains) {
    const ops = (CAP_DOMAINS as Record<string, readonly number[]>)[d];
    if (!ops) throw new Error(`cap-bridge: unknown capability domain "${d}"`);
    out.push(...ops);
  }
  return out;
}

/** The libsodium surface the crypto ops use — structural so any sumo build
 *  (the kernel's bundled `libsodium-wrappers-sumo`) satisfies it. */
export interface CapSodium {
  crypto_generichash(hashLength: number, message: Uint8Array): Uint8Array;
  crypto_stream_xchacha20_xor(message: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array;
  crypto_sign_detached(message: Uint8Array, sk: Uint8Array): Uint8Array;
  crypto_sign_verify_detached(sig: Uint8Array, message: Uint8Array, pk: Uint8Array): boolean;
  randombytes_buf(n: number): Uint8Array;
}

/** The request/response transport the net ops drive. `Transport` satisfies it. */
export interface CapTransport {
  request(to: PeerId, type: number, payload: Uint8Array): Promise<Uint8Array>;
  requestMany(
    peers: PeerId[], type: number, payload: Uint8Array,
  ): Promise<{ peer: PeerId; ok: boolean; bytes: Uint8Array }[]>;
}

/** Everything a cap-bridge needs — all kernel primitives, zero app knowledge. */
export interface CapBridgeDeps {
  sodium: CapSodium;
  /** This node's kernel keypair (README §13.1): SIGN signs as it, IDENTITY
   *  returns its pk — so a `crypto`-domain guest holds a signing oracle under
   *  this key (README §15). */
  identity: { publicKey: Uint8Array; privateKey: Uint8Array };
  /** Reach an installed WASM handler by name (KernelHost.callHandler). */
  callHandler: (name: Uint8Array, payload: Uint8Array) => Uint8Array | null;
  transport: CapTransport;
  /** The peers this node can reach (its cohort / connected set). */
  peers: () => PeerId[];
  /** Raw-byte fs backend. Optional: a node that only initiates never reads it. */
  fs?: Fs;
  /** Wall clock (ms). Defaults to Date.now. */
  now?: () => number;
  /** The allowed op set, expanded from the manifest's declared cap domains
   *  (README §13.2, `opsForCaps` — not from `ops`, which is documentation-only).
   *  When present, any op outside the set is refused — the guest analogue of the
   *  §8.2 bridge check. Omitted = unrestricted (a trusted host-side caller that
   *  holds the primitives anyway). */
  allowedOps?: Iterable<number>;
}

// Host-side allocation bounds for guest-controlled sizes. The realm's own
// 64 MiB memory limit does not cover host allocations the guest requests, so
// the bridge caps them itself (a confined guest must not be able to size a
// host buffer past these).
const MAX_RANDOM_BYTES = 1 << 20;     // 1 MiB per CAP_RANDOM call
const MAX_REQUEST_MANY_PEERS = 1024;  // fan-out width per CAP_NET_REQUEST_MANY

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

/** Build the single capability funnel for one node. Every op resolves
 *  *synchronously* (returns bytes) except the two net ops, which genuinely
 *  round-trip and return a Promise — Asyncify makes that transparent to the async
 *  orchestration guest. Because the non-net ops are synchronous, the very same
 *  bridge also drives a *sync* (non-Asyncify) realm — the holder side, which never
 *  touches net (it answers purely from local fs + crypto), runs there so it can
 *  respond while the async realm is parked mid-await (the runtime split). */
export function createCapBridge(deps: CapBridgeDeps): SafeRealmBridge {
  const { sodium, identity, callHandler, transport } = deps;
  const now = deps.now ?? (() => Date.now());
  const allowed = deps.allowedOps ? new Set(deps.allowedOps) : null;
  const fs = (): Fs => {
    if (!deps.fs) throw new Error("cap-bridge: fs.* used but no fs backend wired");
    return deps.fs;
  };

  return (op: number, payload: Uint8Array): Uint8Array | Promise<Uint8Array> => {
    if (allowed && !allowed.has(op)) {
      throw new Error("cap-bridge: op " + op + " not declared by the bundle manifest");
    }
    switch (op) {
      // ── crypto primitives ────────────────────────────────────────────────
      case CAP.HASH:
        return sodium.crypto_generichash(32, payload);
      case CAP.STREAM_XOR: {
        const nonce = payload.slice(0, 24);
        const key = payload.slice(24, 56);
        return sodium.crypto_stream_xchacha20_xor(payload.slice(56), nonce, key);
      }
      case CAP.SIGN:
        return sodium.crypto_sign_detached(payload, identity.privateKey);
      case CAP.VERIFY: {
        const pk = payload.slice(0, 32), sig = payload.slice(32, 96), msg = payload.slice(96);
        try { return sodium.crypto_sign_verify_detached(sig, msg, pk) ? ONE : ZERO; }
        catch { return ZERO; }
      }
      case CAP.IDENTITY:
        return identity.publicKey.slice();
      case CAP.RANDOM: {
        const n = readU32BE(payload, 0);
        if (n > MAX_RANDOM_BYTES) throw new Error("cap-bridge: RANDOM size over cap");
        return sodium.randombytes_buf(n);
      }

      // ── net (the only async ops — a real round trip → a Promise) ──────────
      case CAP.NET_SEND: {
        const peer = toHex(payload.slice(0, 32));
        const type = payload[32];
        return transport.request(peer, type, payload.slice(33)).then(
          (resp) => concatBytes([ONE, resp]),
          () => ZERO,
        );
      }
      case CAP.NET_REQUEST_MANY: {
        const type = payload[0];
        const count = readU32BE(payload, 1);
        // `count` is guest-controlled: it must be backed by actual peer bytes in
        // the payload (no driving an unbounded host loop with a bare number) and
        // stay under the fan-out cap.
        if (count > MAX_REQUEST_MANY_PEERS || 5 + count * 32 + 4 > payload.length) {
          throw new Error("cap-bridge: NET_REQUEST_MANY count invalid");
        }
        const peers: PeerId[] = [];
        let o = 5;
        for (let i = 0; i < count; i++) { peers.push(toHex(payload.slice(o, o + 32))); o += 32; }
        const plen = readU32BE(payload, o); o += 4;
        const req = payload.slice(o, o + plen);
        return transport.requestMany(peers, type, req).then((results) => {
          const head = new Uint8Array(4); writeU32BE(head, 0, results.length);
          const parts: Uint8Array[] = [head];
          for (const r of results) {
            const h = new Uint8Array(32 + 1 + 4);
            h.set(fromHex(r.peer), 0);
            h[32] = r.ok ? 1 : 0;
            writeU32BE(h, 33, r.ok ? r.bytes.length : 0);
            parts.push(h);
            if (r.ok) parts.push(r.bytes);
          }
          return concatBytes(parts);
        });
      }
      case CAP.NET_PEERS: {
        const peers = deps.peers();
        const head = new Uint8Array(4); writeU32BE(head, 0, peers.length);
        return concatBytes([head, ...peers.map(fromHex)]);
      }

      // ── fs (raw bytes under an opaque key) ───────────────────────────────
      case CAP.FS_GET: {
        const v = fs().get(dec.decode(payload));
        return v ? concatBytes([ONE, v]) : ZERO;
      }
      case CAP.FS_PUT: {
        const klen = readU32BE(payload, 0);
        const key = dec.decode(payload.slice(4, 4 + klen));
        fs().put(key, payload.slice(4 + klen));
        return NONE;
      }
      case CAP.FS_HAS:
        return fs().has(dec.decode(payload)) ? ONE : ZERO;
      case CAP.FS_LIST: {
        const prefix = payload.length ? dec.decode(payload) : undefined;
        const keys = fs().list(prefix);
        const head = new Uint8Array(4); writeU32BE(head, 0, keys.length);
        const parts: Uint8Array[] = [head];
        for (const k of keys) {
          const kb = enc.encode(k);
          const kh = new Uint8Array(4); writeU32BE(kh, 0, kb.length);
          parts.push(kh, kb);
        }
        return concatBytes(parts);
      }
      case CAP.FS_DELETE:
        fs().delete(dec.decode(payload));
        return NONE;
      case CAP.FS_SIZE: {
        const sz = fs().size(dec.decode(payload));
        const out = new Uint8Array(4);
        writeU32BE(out, 0, sz < 0 ? 0xffffffff : sz);
        return out;
      }
      case CAP.FS_STAT: {
        const s = fs().stat();
        return concatBytes([u64be(s.used), u64be(s.available)]);
      }

      // ── installed-handler call + clock ───────────────────────────────────
      case CAP.MODULE_CALL: {
        const nameLen = payload[0];
        const name = payload.slice(1, 1 + nameLen);
        const r = callHandler(name, payload.slice(1 + nameLen));
        return r ?? NONE;
      }
      case CAP.CLOCK:
        return u64be(now());

      default:
        throw new Error("cap-bridge: unknown op " + op);
    }
  };
}
