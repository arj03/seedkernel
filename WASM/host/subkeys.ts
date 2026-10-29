// The node's signing keypair, derived from its one stored 32-byte master seed (§12.6.2b):
// BLAKE2b-256 over `DOMAIN_subkey ‖ label ‖ master`, fed to crypto_sign_seed_keypair.
//
// The derivation keeps the stored secret separate from the signing key, under a versioned
// label, so the peer id can rotate without changing the key file format. One key serves
// every purpose; what a signature means comes from the domain and scope the host picks
// for the calling slot (guest-seam.ts), not from the key. Why not a second keypair:
// docs/CHANNEL.md §7.

import { DOMAIN_SUBKEY } from "./domains.js";
import { concatBytes, enc } from "./util.js";

/** Kept narrow so subkey derivation is testable without a whole crypto backend. */
export interface SubkeyCrypto {
  crypto_generichash(hashLength: number, message: Uint8Array, key: Uint8Array | null): Uint8Array;
  crypto_sign_seed_keypair(seed: Uint8Array): Keypair;
}

/** An Ed25519 keypair. */
export interface Keypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** Deterministic, so a node rebuilds its key at boot from the one secret it stores. The
 *  public half is the peer id and what `senderPk` carries on every dispatch; the key signs
 *  the handshake and an app's scoped `node/sign`. */
export function deriveNodeKey(sodium: SubkeyCrypto, master: Uint8Array): Keypair {
  if (master.length !== 32) throw new Error(`subkey: master seed must be 32 bytes (got ${master.length})`);
  const seed = sodium.crypto_generichash(32, concatBytes([
    DOMAIN_SUBKEY,
    enc.encode("seedkernel-subkey-channel-v1\0"),
    master,
  ]), null);
  const kp = sodium.crypto_sign_seed_keypair(seed);
  seed.fill(0);
  return kp;
}
