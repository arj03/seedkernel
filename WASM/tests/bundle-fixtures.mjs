import { signBundle } from "../build/host/bundle-author.js";
import { verifyBundle } from "../build/host/bundle.js";

// Manifest shape tests need signed bodies, but never instantiate their empty programs.
export function signTestBundle(sodium, keys, manifest, guest = new Uint8Array(),
  modules = Array.isArray(manifest.modules) ? manifest.modules.map(() => new Uint8Array()) : []) {
  return signBundle(sodium, keys, manifest, guest, modules);
}

// Suite and shape errors remain visible; only failed authentication yields null.
export function verifyTestBundle(sodium, blob) {
  try { return verifyBundle(sodium, blob); }
  catch (e) {
    if (e.message === "bundle: signature invalid") return null;
    throw e;
  }
}
