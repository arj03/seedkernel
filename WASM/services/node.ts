// `node` (§12.2): sign and verify with the node's key, under the calling slot's scope.
// Every node offers it; the guest never picks a namespace.
import { concatBytes, enc, EMPTY, ONE, ZERO } from "../host/util.js";
import { DOMAIN_GUEST, DOMAIN_LINK_SCOPE } from "../host/domains.js";
import type { SeamCrypto, ServiceHandlers } from "../host/guest-seam.js";
import type { Keypair } from "../host/subkeys.js";

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
  if (appBytes.length > 255) throw new Error("node: app name too long for a scope (>255 bytes)");
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

/** The `node` handlers for one slot, signing under its scope. */
export function nodeService(sodium: SeamCrypto, scope: SignScope): ServiceHandlers<"node"> {
  const signer = scopedSigner(sodium, scope);
  return {
    "node/sign": (payload) => signer.sign(payload),
    // [pk 32][sig 64][msg ...] -> [ok u8]. Too short for the prefix throws; an empty msg
    // is valid.
    "node/verify": (payload) => {
      if (payload.length < 96) throw new Error("node: node/verify takes [pk 32][sig 64][msg ..]");
      return signer.verify(payload.subarray(0, 32), payload.subarray(32, 96), payload.subarray(96)) ? ONE : ZERO;
    },
  };
}
