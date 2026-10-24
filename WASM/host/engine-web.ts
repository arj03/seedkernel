// Realms on WebAssembly (§12.3): `bootShell`'s default realm factory, for a node assembled
// without a platform. Guests run on the qjs.wasm in the package's host blob, the engine
// every target runs, over the engine table in platform-web.ts.

import { engineRealms } from "./engine-realm.js";
import { syncWebEngine } from "./platform-web.js";
import { readHostBlob } from "./host-blob.js";
import type { RealmFactory } from "./realm-queue.js";

let qjsBytes: Promise<Uint8Array> | undefined;
/** qjs.wasm, out of the package's host blob (build/host.skb, beside build/host/). */
function loadQjs(): Promise<Uint8Array> {
  const url = new URL("../host.skb", import.meta.url);
  const node = globalThis.process?.versions?.node;
  return qjsBytes ??= (node
    ? import("node:fs/promises").then(({ readFile }) => readFile(url)).then((b) => new Uint8Array(b))
    : fetch(url).then((r) => {
      // A page that does not serve the file answers with an error page, which would
      // otherwise reach the blob reader and fail there as a bad blob.
      if (!r.ok) throw new Error(`engine: ${url.href} was not served (HTTP ${r.status})`);
      return r.arrayBuffer();
    }).then((b) => new Uint8Array(b))).then((blob) => readHostBlob(blob).qjs, (err) => {
      // A failed read is not cached, so the next realm tries again.
      qjsBytes = undefined;
      throw err;
    });
}

/** This target's realm factory (§12.3). A module call is asynchronous here (a worker), so
 *  it is billed to the calling invocation. */
export const createWebRealm: RealmFactory = async (opts) =>
  engineRealms(syncWebEngine, await loadQjs())(opts);
