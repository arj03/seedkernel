// Realms on WebAssembly (§12.3): `bootShell`'s default realm factory, for a node assembled
// without a platform. Guests run on the package's qjs.wasm, the engine every target runs,
// over the engine table in platform-web.ts.

import { engineRealms } from "./engine-realm.js";
import { webEngine } from "./platform-web.js";
import type { RealmFactory } from "./realm-queue.js";

let qjsBytes: Promise<Uint8Array> | undefined;
/** qjs.wasm, shipped beside the package's other wasm (browser/). */
function loadQjs(): Promise<Uint8Array> {
  const url = new URL("../../browser/qjs.wasm", import.meta.url);
  const node = (globalThis as { process?: { versions?: { node?: string } } }).process?.versions?.node;
  return qjsBytes ??= node
    ? import("node:fs/promises").then(({ readFile }) => readFile(url)).then((b) => new Uint8Array(b))
    : fetch(url).then((r) => {
      // A page that does not serve the file answers with an error page, which would
      // otherwise reach the compiler and fail there as a bad module.
      if (!r.ok) throw new Error(`engine: ${url.href} was not served (HTTP ${r.status})`);
      return r.arrayBuffer();
    }).then((b) => new Uint8Array(b));
}

/** This target's realm factory (§12.3). A module call is asynchronous here (a worker), so
 *  it is billed to the calling invocation. */
export const createWebRealm: RealmFactory = async (opts) =>
  engineRealms(webEngine, await loadQjs(), { billModules: true })(opts);
