// `identity` (§12.2): sign and verify with the node's identity, under the calling slot's
// scope. Plain calls sign with the Ed25519 key, the peer id; the hybrid calls add the
// ML-DSA-65 half derived from it, for records that must outlive Ed25519 (§14.1). Every node
// offers it; the guest never picks a namespace, and no key ever enters a realm.
import { concatBytes, enc, EMPTY, ONE, ZERO } from "../host/util.js";
import { DOMAIN_GUEST, DOMAIN_HYBRID, DOMAIN_LINK_SCOPE } from "../host/domains.js";
import { ML_DSA65_PK_LEN, ML_DSA65_SIG_LEN, type MlDsa65Signer } from "../host/pq.js";
import { deriveHybridKey, type Keypair } from "../host/subkeys.js";
import type { SeamCrypto, ServiceHandlers } from "../host/guest-seam.js";

/** The calls a scoped signer makes: libsodium's Ed25519, SHA-256 for deriving the hybrid
 *  key, and ML-DSA-65. */
export type IdentityCrypto = Pick<SeamCrypto, "sha256" | "crypto_sign_detached" | "crypto_sign_verify_detached">
  & MlDsa65Signer;

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

/** An ordinary app's signing scope (§12.2): `DOMAIN_guest ‖ app_len u8 ‖ app`. Derived
 *  from the label, so every node running the app derives the same bytes. */
export function appSignScope(key: Keypair, app: string): SignScope {
  const appBytes = enc.encode(app);
  if (appBytes.length > 255) throw new Error("identity: app name too long for a scope (>255 bytes)");
  return { domain: DOMAIN_GUEST, scope: concatBytes([Uint8Array.of(appBytes.length), appBytes]), key };
}

/** A slot's signing scope, derived at load from admitted facts only (§12.2): never
 *  `protocols`, which change between versions, nor the author, whose key can rotate. The
 *  `link` slot signs under `DOMAIN_link_scope` with an empty suffix; the transport tags its
 *  own handshake format inside the message, so changing it needs no host change. */
export function slotSignScope(node: { identity: Keypair }, app: string, links: boolean): SignScope {
  return links ? { domain: DOMAIN_LINK_SCOPE, scope: EMPTY, key: node.identity } : appSignScope(node.identity, app);
}

/** Sign and verify under one scope, over `domain ‖ scope ‖ msg`: `identity/sign` and
 *  `identity/verify`, and their host-side twin `appSigner`. */
function scopedSigner(sodium: Pick<IdentityCrypto, "crypto_sign_detached" | "crypto_sign_verify_detached">,
  scope: SignScope): {
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
export function appSigner(sodium: Pick<IdentityCrypto, "crypto_sign_detached" | "crypto_sign_verify_detached">,
  key: Keypair, app: string): ReturnType<typeof scopedSigner> {
  return scopedSigner(sodium, appSignScope(key, app));
}

/** A hybrid signature: the Ed25519 signature, then the ML-DSA-65 one. */
export const HYBRID_SIG_LEN = 64 + ML_DSA65_SIG_LEN;
/** A hybrid public key, as `identity/hybrid-key` answers it: the Ed25519 key, then the
 *  ML-DSA-65 one. */
export const HYBRID_PK_LEN = 32 + ML_DSA65_PK_LEN;

/** Hybrid sign and verify under one scope (§12.2). Both halves sign
 *  `DOMAIN_hybrid ‖ domain ‖ scope ‖ ed_pk ‖ ml_pk ‖ msg`: the leading prefix keeps either
 *  half from passing as a plain scoped signature, and naming both keys binds the halves to
 *  each other, so neither can be paired with a signature under another key. */
function hybridSigner(sodium: IdentityCrypto, scope: SignScope, hybridKey: () => Keypair): {
  /** `[ed pk 32][ml pk 1952]`. */
  publicKey(): Uint8Array;
  sign(msg: Uint8Array): Uint8Array;
  /** False on a bad signature in either half, and on a key or signature of the wrong
   *  shape. */
  verify(pk: Uint8Array, sig: Uint8Array, msg: Uint8Array): boolean;
} {
  const input = (pk: Uint8Array, msg: Uint8Array) => concatBytes([DOMAIN_HYBRID, scope.domain, scope.scope, pk, msg]);
  const publicKey = () => concatBytes([scope.key.publicKey, hybridKey().publicKey]);
  return {
    publicKey,
    sign(msg) {
      const pre = input(publicKey(), msg);
      return concatBytes([
        sodium.crypto_sign_detached(pre, scope.key.privateKey),
        sodium.ml_dsa65_sign_detached(pre, hybridKey().privateKey),
      ]);
    },
    verify(pk, sig, msg) {
      if (pk.length !== HYBRID_PK_LEN || sig.length !== HYBRID_SIG_LEN) return false;
      const pre = input(pk, msg);
      let ed: boolean;
      try {
        ed = sodium.crypto_sign_verify_detached(sig.subarray(0, 64), pre, pk.subarray(0, 32));
      } catch {
        ed = false;
      }
      // Both halves are checked whatever the first said, so neither one alone decides.
      const ml = sodium.ml_dsa65_verify_detached(sig.subarray(64), pre, pk.subarray(32));
      return ed && ml;
    },
  };
}

/** The `identity` handlers for one slot, signing under its scope. `hybridKey` answers the
 *  node's ML-DSA-65 key; a node passes one shared, lazily derived key to every slot, so the
 *  key is made once, and only if some slot asks for it. */
export function identityService(sodium: IdentityCrypto, scope: SignScope,
  hybridKey: () => Keypair = lazyHybridKey(sodium, scope.key)): ServiceHandlers<"identity"> {
  const signer = scopedSigner(sodium, scope);
  const hybrid = hybridSigner(sodium, scope, hybridKey);
  return {
    "identity/sign": (payload) => signer.sign(payload),
    // [pk 32][sig 64][msg ...] -> [ok u8]. Too short for the prefix throws; an empty msg
    // is valid.
    "identity/verify": (payload) => {
      if (payload.length < 96) throw new Error("identity: identity/verify takes [pk 32][sig 64][msg ..]");
      return signer.verify(payload.subarray(0, 32), payload.subarray(32, 96), payload.subarray(96)) ? ONE : ZERO;
    },
    // [msg ...] -> [ed sig 64][ml sig 3309].
    "identity/sign-hybrid": (payload) => hybrid.sign(payload),
    // [ed pk 32][ml pk 1952][ed sig 64][ml sig 3309][msg ...] -> [ok u8]. Too short for
    // the prefix throws; an empty msg is valid.
    "identity/verify-hybrid": (payload) => {
      const head = HYBRID_PK_LEN + HYBRID_SIG_LEN;
      if (payload.length < head) {
        throw new Error("identity: identity/verify-hybrid takes [ed pk 32][ml pk 1952][ed sig 64][ml sig 3309][msg ..]");
      }
      const pk = payload.subarray(0, HYBRID_PK_LEN), sig = payload.subarray(HYBRID_PK_LEN, head);
      return hybrid.verify(pk, sig, payload.subarray(head)) ? ONE : ZERO;
    },
    // (empty) -> [ed pk 32][ml pk 1952].
    "identity/hybrid-key": () => hybrid.publicKey(),
  };
}

/** The node's ML-DSA-65 key, derived on first use and kept (subkeys.ts `deriveHybridKey`). */
export function lazyHybridKey(sodium: IdentityCrypto, identity: Keypair): () => Keypair {
  let key: Keypair | undefined;
  return () => (key ??= deriveHybridKey(sodium, identity));
}
