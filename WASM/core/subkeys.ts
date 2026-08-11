// The node's signing keypair, derived from the one stored master seed.
//
// A node holds ONE secret on disk: a 32-byte master seed. The seed itself signs nothing —
// it only derives — and every keypair the node uses comes out of `deriveNodeKeys` under a
// distinct, versioned label. Today there is exactly one such label, `channel`, and its
// public half is the node's IDENTITY: the peer id, what the handshake signs with, what
// `senderPk` carries on every dispatch, and what the guest seam's SIGN op signs with.
//
// WHY ONE KEY, given that purpose separation is otherwise good practice. There was a
// second `guest` subkey here, so that guest SIGN structurally could not emit a channel
// signature whatever happened to the domain prefixes. It could not survive contact with
// what a signature is FOR: a signed record travels to other nodes, which know the author
// only as a peer id — a channel public key — so a record signed by a sibling subkey names
// an author no peer in the cohort has heard of. Reconciling the two would mean gossiping a
// signed guest-pk↔channel-pk binding per peer, which is a new protocol element bought to
// protect a split no node could actually deploy: both subkeys were derived at boot, from a
// seed the same process holds, and a node without the guest key cannot sign at all.
//
// So cross-purpose forgery is prevented the way the manifest/channel/guest split is already
// prevented everywhere else in the tree: every signature binds `DOMAIN_x ‖ scope ‖ msg`,
// the host chooses the domain from the slot the asking bundle occupies, and no op ever
// signs raw bytes (guest-seam.ts, `appSignScope` / `transportSignScope`). One key, one
// identity namespace, the same meaning on every target.
//
// The derivation stays: it keeps the stored secret distinct from the key that signs, keeps
// the label versioned so the peer id can be rotated without changing the key file format,
// and leaves room for a purpose that is genuinely node-local. The label set is closed here;
// a label is never constructed from runtime data, so two purposes cannot collide by
// accident.
//
// The derivation is BLAKE2b-256 over `DOMAIN_subkey ‖ label ‖ master`, fed to
// crypto_sign_seed_keypair.

import { DOMAIN_SUBKEY } from "./domains.js";
import { concatBytes, enc } from "./util.js";

/** Labels are closed, literal and versioned — never built from runtime data. Adding a
 *  purpose means adding a constant here, which is the point: the set of things this
 *  node's seed can sign for is enumerable by reading one file. */
export const SUBKEY_CHANNEL = enc.encode("seedkernel-subkey-channel-v1\0");

/** The subset of TransportCrypto this module needs. Kept narrow so subkey derivation is
 *  testable without standing up a whole crypto backend. */
export interface SubkeyCrypto {
  crypto_generichash(hashLength: number, message: Uint8Array, key: Uint8Array | null): Uint8Array;
  crypto_sign_seed_keypair(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array };
}

/** An Ed25519 keypair — the one name for this shape in the tree. It lives here, with
 *  the derivation that is the only thing in the runtime that *produces* one: every
 *  keypair a node holds comes out of `deriveNodeKeys` below. It was previously also
 *  spelled `Identity` (socket-seam.ts) and twice more as an inline literal in
 *  shell-core.ts, which is three names for one four-line record and no way to tell
 *  from a signature which of them a caller meant. */
export interface Keypair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** Derive a purpose-bound Ed25519 keypair from the node's master seed.
 *
 *  Deterministic: the same seed and label always give the same keypair, so a node
 *  rebuilds its keys at boot from the one secret it stores and there is nothing extra
 *  to persist, back up or keep in sync. Internal to this file: the public surface is
 *  `deriveNodeKeys`, which is what a host calls with the label constants above. */
function deriveSubkey(sodium: SubkeyCrypto, master: Uint8Array, label: Uint8Array): Keypair {
  if (master.length !== 32) throw new Error(`subkey: master seed must be 32 bytes (got ${master.length})`);
  const seed = sodium.crypto_generichash(32, concatBytes([DOMAIN_SUBKEY, label, master]), null);
  const kp = sodium.crypto_sign_seed_keypair(seed);
  seed.fill(0);
  return kp;
}

/** Every keypair a node derives from its master seed.
 *
 *  `channel` is the node's IDENTITY: its public half is the peer id, it is what the
 *  handshake signs with, it is what `senderPk` carries on every dispatch, and it is what
 *  an app's scoped `node/sign` signs with. A record is one record: whoever sees the
 *  signature already knows the signer as a peer. */
export interface NodeKeys {
  channel: Keypair;
}

export function deriveNodeKeys(sodium: SubkeyCrypto, master: Uint8Array): NodeKeys {
  return {
    channel: deriveSubkey(sodium, master, SUBKEY_CHANNEL),
  };
}
