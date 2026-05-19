// Bootstrap WASM module (README §6). Holds only the signature module; the
// installer is a host-side module (host/installer.ts) because it has to
// instantiate WebAssembly modules — a JS-only capability.

export {
  alloc, dealloc,
  handle_signature, get_inner_ptr, get_inner_len,
  pop_signer, get_signer_count, read_signer, signer_pubkey_len,
} from "./signature";
