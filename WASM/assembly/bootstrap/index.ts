// Bootstrap WASM module (README §6, §7). Combines signature and trust into a
// single sandbox. This file is the compiler entry point — it re-exports all
// host-callable functions from the two sub-modules.
//
// Note: registerSuiteMeta / unregisterSuiteMeta / hasSuiteMeta are deliberately
// NOT re-exported — they are bootstrap-internal helpers consumed by trust.ts
// via the import in that file. The host never calls them directly; suite
// registration goes through the signed handle_signature_register pipeline.

export {
  alloc, dealloc,
  handle_signature, get_inner_ptr, get_inner_len,
  pop_signer, get_signer_count, read_signer, signer_pubkey_len,
} from "./signature";

export {
  trust_grant, trust_revoke,
  is_trusted, is_trusted_by_current_signers,
  handle_trust_grant, set_trust_grant_id,
  handle_signature_register, set_sig_register_id,
} from "./trust";
