// Node.js: the default transport bundle (§12.6) out of the package's own host blob, which
// carries it as its `transport` part. A host takes it from the blob it runs
// (platform.ts `standUp`); this is for Node code that installs or inspects it by hand.

import { packageHostBlob } from "./crypto-node.js";
import { readHostBlob } from "./host-blob.js";

/** The local service id the default transport claims, for `Shell.call`. A replacement
 *  transport may name its own. */
export { TRANSPORT_SERVICE } from "./host-blob.js";

/** The default transport bundle's bytes, a fresh copy per call. */
export function transportBundleBytes(): Uint8Array {
  return readHostBlob(packageHostBlob()).transport.slice();
}
