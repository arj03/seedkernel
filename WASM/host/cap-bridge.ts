// cap-bridge — the capability counterpart to `safe-js` (exported as
// `seedkernel-wasm/cap-bridge`). Given a safe-js realm, it services the guest's
// single `host.call(op, bytes)` seam from the kernel's *primitive* capabilities
// and nothing else: crypto primitives (sumo), net (send / peers),
// fs (raw bytes under an opaque key), an installed-handler call, clock, and
// identity. Every op is application-neutral — the bridge has no idea it is
// hosting storage (or chat, or anything). All structure — content addressing,
// descriptor envelopes, the HAVE/OFFER/STORE wire format, Reed–Solomon, the
// nonce convention — is the guest's business, built on top of these primitives.
//
// This is what lets the seedkernel shell run an arbitrary signed guest: it
// constructs a cap-bridge from kernel primitives it already holds (README
// §12.2). A host-side caller that holds the same primitives constructs the
// identical bridge, so output orchestrated through the confined guest is
// byte-compatible with a host-side reference path.

import type { Fs } from "./fs.js";
import type { PeerId } from "./net.js";
import { toHex, fromHex, concatBytes, writeU32BE, readU32BE } from "./util.js";
import { DOMAIN_GUEST } from "./domains.js";
import type { SafeRealmBridge } from "./safe-js.js";

/** The generic op catalog — the seam ABI (README §12.2). `capPreamble()` injects
 *  these as `const CAP_X = n;` into the guest, and the bridge switch reads them
 *  here, so guest and host can never drift. The numbers are a shared guest↔host
 *  identifier regenerated with the preamble — never a wire value between nodes — so
 *  they form one contiguous block grouped by domain (crypto 1–6, net 7–8, fs 9–14,
 *  module 15, clock 16); new ops are appended. Net fan-out is not an op: with real
 *  promises the guest fans out itself with `Promise.all` over `NET_SEND`. */
export const CAP = {
  // crypto (1–6)
  HASH: 1,             // bytes -> 32B generic hash (blake2b / crypto_generichash)
  STREAM_XOR: 2,       // [nonce 24][key 32][msg] -> xchacha20 keystream XOR
  SIGN: 3,             // msg -> 64B detached ed25519 signature by this identity, over
                       //   DOMAIN_guest ‖ scope ‖ msg (scoped, never raw — see below)
  VERIFY: 4,           // [pk 32][sig 64][msg] -> [valid u8]
  IDENTITY: 5,         // -> this node's 32B public key
  RANDOM: 6,           // [n u32] -> n random bytes
  // net (7–8) — NET_SEND is the only async op (a real round trip → a Promise)
  NET_SEND: 7,         // [peer 32][type u8][payload] -> [ok u8][resp]
  NET_PEERS: 8,        // -> [count u32][pk 32 …]
  // fs (9–14)
  FS_GET: 9,           // key(utf8) -> [0] | [1][bytes]
  FS_PUT: 10,          // [klen u32][key(utf8)][bytes] -> []
  FS_LIST: 11,         // prefix(utf8, may be empty) -> [count u32]{[klen u32][key]}
  FS_DELETE: 12,       // key(utf8) -> []
  FS_STAT: 13,         // -> [used u64 BE][available u64 BE]
  FS_SIZE: 14,         // key(utf8) -> [size i32 BE] (-1 as 0xFFFFFFFF if absent) —
                       //   lets a policy layer rebuild a byte budget (quota) without
                       //   reading every value back. Existence is size ≥ 0, so there is
                       //   no separate FS_HAS.
  // module (15) + clock (16)
  MODULE_CALL: 15,     // [nameLen u8][name][req] -> installed handler response bytes
  CLOCK: 16,           // -> now ms (u64 BE)
} as const;

/** The generated `const CAP_NAME = n;` block the guest is written against. */
export function capPreamble(): string {
  return Object.entries(CAP).map(([k, v]) => `const CAP_${k} = ${v};`).join("\n") + "\n";
}

/** Capability *domains* — named groups of ops. A bundle's signed manifest declares
 *  the domains its guest needs (its `caps`), and the shell expands them to the
 *  concrete op set it enforces (`allowedOps`) and to which backends it wires. This
 *  is the coarse, human-auditable capability vocabulary: "this app reaches net + fs",
 *  not a list of 17 op numbers. `caps` is the grant; the preamble is the ABI. */
export const CAP_DOMAINS = {
  crypto: [CAP.HASH, CAP.STREAM_XOR, CAP.SIGN, CAP.VERIFY, CAP.IDENTITY, CAP.RANDOM],
  net:    [CAP.NET_SEND, CAP.NET_PEERS],
  fs:     [CAP.FS_GET, CAP.FS_PUT, CAP.FS_LIST, CAP.FS_DELETE, CAP.FS_STAT, CAP.FS_SIZE],
  module: [CAP.MODULE_CALL],
  clock:  [CAP.CLOCK],
} as const;

export type CapDomain = keyof typeof CAP_DOMAINS;

/** The host-derived scope the SIGN op binds every guest signature to (README §12.2):
 *  `author_pk ‖ app_len u8 ‖ app`, from the admitted manifest's `(author, app)`.
 *  Never guest-supplied — a guest can only sign within its own bundle's namespace,
 *  and two bundles derive disjoint scopes. Every node running the same bundle derives
 *  the same bytes, which is what makes the scoped signatures portable across a cohort. */
export function guestSignScope(author: Uint8Array, app: string): Uint8Array {
  const appBytes = enc.encode(app);
  if (appBytes.length > 255) throw new Error("cap-bridge: app name too long for a scope (>255 bytes)");
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

/** The request/response transport the net op drives. `Transport` satisfies it. A
 *  confined guest fans out itself with `Promise.all` over `NET_SEND`, so the bridge
 *  needs only single-peer request/response — no host-side scatter-gather. */
export interface CapTransport {
  request(to: PeerId, type: number, payload: Uint8Array): Promise<Uint8Array>;
}

/** Everything a cap-bridge needs — all kernel primitives, zero app knowledge. */
export interface CapBridgeDeps {
  sodium: CapSodium;
  /** This node's kernel keypair (README §12.1): SIGN signs as it, IDENTITY
   *  returns its pk. SIGN is a signing oracle under this key but a *scoped* one —
   *  it prepends `DOMAIN_guest ‖ signScope` so a guest never obtains a raw
   *  node-key signature (README §12.2, §14). */
  identity: { publicKey: Uint8Array; privateKey: Uint8Array };
  /** The host-derived signing scope `author_pk ‖ app_len u8 ‖ app` from the admitted
   *  manifest (README §12.2, `guestSignScope`). SIGN binds every guest signature to
   *  `DOMAIN_guest ‖ signScope ‖ msg`; without it SIGN is unavailable (guest signing
   *  is never raw). A host-side caller that never exposes SIGN may omit it. */
  signScope?: Uint8Array;
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
   *  (README §12.2, `opsForCaps` — not from `ops`, which is documentation-only).
   *  When present, any op outside the set is refused — the guest analogue of the
   *  §8 bridge check. Omitted = unrestricted (a trusted host-side caller that
   *  holds the primitives anyway). */
  allowedOps?: Iterable<number>;
}

// Host-side allocation bounds for guest-controlled sizes. The realm's own
// 64 MiB memory limit does not cover host allocations the guest requests, so
// the bridge caps them itself (a confined guest must not be able to size a
// host buffer past these).
const MAX_RANDOM_BYTES = 1 << 20;     // 1 MiB per CAP_RANDOM call

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
 *  *synchronously* (returns bytes) except `NET_SEND`, which genuinely round-trips and
 *  returns a Promise the initiator guest `await`s. Because the non-net ops are
 *  synchronous, the very same bridge also drives the holder side — which never touches
 *  net (it answers purely from local fs + crypto), so it responds synchronously while an
 *  initiator is parked mid-await in the same realm. */
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
      case CAP.SIGN: {
        // Scoped, never raw (README §12.2, §14): the host signs
        // `DOMAIN_guest ‖ scope ‖ msg`, so a guest signature can never verify as an
        // envelope wrapper, manifest, or channel AUTH, nor in another app's scope.
        if (!deps.signScope) throw new Error("cap-bridge: SIGN needs a bundle scope (guest signing is never raw)");
        const pre = concatBytes([guestSignPrefix(deps.signScope), payload]);
        return sodium.crypto_sign_detached(pre, identity.privateKey);
      }
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

      // ── net (NET_SEND is the only async op — a real round trip → a Promise) ──
      case CAP.NET_SEND: {
        const peer = toHex(payload.slice(0, 32));
        const type = payload[32];
        return transport.request(peer, type, payload.slice(33)).then(
          (resp) => concatBytes([ONE, resp]),
          () => ZERO,
        );
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
