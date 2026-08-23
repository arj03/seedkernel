// The node's signing keypair, derived from its one stored 32-byte master seed (§12.6.2b):
// BLAKE2b-256 over `DOMAIN_subkey ‖ label ‖ master`, fed to crypto_sign_seed_keypair.
//
// The derivation keeps the stored secret distinct from the key that signs, under a
// versioned label, so the peer id can rotate without changing the key file format. One key
// serves every purpose — what a signature MEANS is the host's choice of domain/scope from
// the slot the asking bundle occupies (guest-seam.ts), not the key's. Why not a second
// keypair: CHANNEL.md §7.

import { DOMAIN_SUBKEY } from "./domains.js";
import { concatBytes, enc } from "./util.js";

/** Labels are closed, literal and versioned — never built from runtime data, so the set
 *  of things this node's seed can derive for is enumerable by reading one file. */
export const SUBKEY_CHANNEL = enc.encode("seedkernel-subkey-channel-v1\0");

/** Kept narrow so subkey derivation is testable without a whole crypto backend. */
export interface SubkeyCrypto {
  crypto_generichash(hashLength: number, message: Uint8Array, key: Uint8Array | null): Uint8Array;
  crypto_sign_seed_keypair(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array };
}

/** An Ed25519 keypair — the one name for this shape in the tree. */
export interface Keypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** Deterministic, so a node rebuilds its keys at boot from the one secret it stores with
 *  nothing extra to persist. Internal: the public surface is `deriveNodeKeys`. */
function deriveSubkey(sodium: SubkeyCrypto, master: Uint8Array, label: Uint8Array): Keypair {
  if (master.length !== 32) throw new Error(`subkey: master seed must be 32 bytes (got ${master.length})`);
  const seed = sodium.crypto_generichash(32, concatBytes([DOMAIN_SUBKEY, label, master]), null);
  const kp = sodium.crypto_sign_seed_keypair(seed);
  seed.fill(0);
  return kp;
}

/** Every keypair a node derives from its master seed. `channel` is the node's identity:
 *  its public half is the peer id, what `senderPk` carries on every dispatch, and what the
 *  handshake and an app's scoped `node/sign` sign with. */
export interface NodeKeys {
  channel: Keypair;
}

export function deriveNodeKeys(sodium: SubkeyCrypto, master: Uint8Array): NodeKeys {
  return {
    channel: deriveSubkey(sodium, master, SUBKEY_CHANNEL),
  };
}
