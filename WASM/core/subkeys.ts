// Purpose-separated signing keys, derived from one stored master seed.
//
// A node holds ONE secret on disk: a 32-byte master seed. Every signing keypair it uses
// is derived from that seed under a distinct label, so no key ever signs for two
// purposes. The channel handshake signs with the channel subkey; guest SIGN (§12.2)
// signs with the guest subkey; anything added later gets its own label.
//
// WHY, given that every preimage is already domain-separated. Domain separation makes a
// signature produced for one purpose fail verification for another — provided the prefix
// is actually applied, on both the signing and verifying side, on every path, forever.
// It is a property of the code, and a single omitted or mismatched prefix on a signing
// path turns that signer into an oracle for every other purpose sharing the key. Separate
// keys make cross-purpose forgery impossible rather than merely incorrect: the guest SIGN
// op cannot emit a channel signature because it does not hold the channel key at all.
// Belt and braces, and the braces are the cheap half.
//
// This is the practice the Noise spec asks for when it says a static key pair should not
// be used outside the protocol it was generated for, and it is the same reasoning behind
// libsodium's crypto_kdf: one long-term secret, many purpose-bound subkeys.
//
// The derivation is BLAKE2b-256 over `DOMAIN_subkey ‖ label ‖ master`, fed to
// crypto_sign_seed_keypair. The label set is closed and versioned here; a label is never
// constructed from runtime data, so two purposes cannot collide by accident.

import { DOMAIN_SUBKEY } from "./domains.js";
import { concatBytes } from "./util.js";

const enc = new TextEncoder();

/** Labels are closed, literal and versioned — never built from runtime data. Adding a
 *  purpose means adding a constant here, which is the point: the set of things this
 *  node's seed can sign for is enumerable by reading one file. */
export const SUBKEY_CHANNEL = enc.encode("seedkernel-subkey-channel-v1\0");
export const SUBKEY_GUEST = enc.encode("seedkernel-subkey-guest-v1\0");

/** The subset of TransportCrypto this module needs. Kept narrow so subkey derivation is
 *  testable without standing up a whole crypto backend. */
export interface SubkeyCrypto {
  crypto_generichash(hashLength: number, message: Uint8Array, key: Uint8Array | null): Uint8Array;
  crypto_sign_seed_keypair(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array };
}

export interface Keypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** Derive a purpose-bound Ed25519 keypair from the node's master seed.
 *
 *  Deterministic: the same seed and label always give the same keypair, so a node
 *  rebuilds every subkey at boot from the one secret it stores and there is nothing extra
 *  to persist, back up or keep in sync. */
export function deriveSubkey(sodium: SubkeyCrypto, master: Uint8Array, label: Uint8Array): Keypair {
  if (master.length !== 32) throw new Error(`subkey: master seed must be 32 bytes (got ${master.length})`);
  const seed = sodium.crypto_generichash(32, concatBytes([DOMAIN_SUBKEY, label, master]), null);
  const kp = sodium.crypto_sign_seed_keypair(seed);
  seed.fill(0);
  return kp;
}

/** Every keypair a node derives from its master seed.
 *
 *  `channel` is the node's NETWORK IDENTITY: its public half is the peer id, it is what
 *  the handshake signs with, and it is what `senderPk` carries on every dispatch. The
 *  master seed itself signs nothing — it only derives — so compromising any one subkey
 *  compromises that purpose and not the node. */
export interface NodeKeys {
  master: Uint8Array;
  channel: Keypair;
  guest: Keypair;
}

export function deriveNodeKeys(sodium: SubkeyCrypto, master: Uint8Array): NodeKeys {
  return {
    master,
    channel: deriveSubkey(sodium, master, SUBKEY_CHANNEL),
    guest: deriveSubkey(sodium, master, SUBKEY_GUEST),
  };
}
