// Bootstrap WASM module (README §6). Holds only the signature module — a
// stateless, standard scratch-ABI handler (§4). The signer stack and the
// push/dispatch/pop lifecycle live host-side (§6.5); the installer is host-side
// too (host/installer.ts) because it instantiates WebAssembly, a JS-only capability.

export { scratch, handle } from "./signature";
