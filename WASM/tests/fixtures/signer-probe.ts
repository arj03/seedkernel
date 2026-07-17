// Test fixture: the thinnest possible app built on the §3.2 handler helper
// (assembly/seedkernel/handler.ts) — the helper's only executable coverage.
//
// It exists to pin the helper's contract, which is otherwise all-or-nothing at
// runtime and silent when broken:
//   - configure() plants the route name and nothing else (route-only payload)
//   - loadTopSignerPubkey() resolves `signature.signer` from the name the helper
//     bakes in itself. If that literal ever drifts from the host's
//     deriveBootstrapName("signature.signer"), the query returns -1 and a real
//     app (chat) would silently stop rendering — here it fails a test instead.
//
// On each message it looks up the current dispatch's top signer and forwards
// the raw pubkey to the configured route, so the test reads back exactly the
// key that signed the envelope.

import {
  init, isConfigured, loadTopSignerPubkey, forwardToHost,
  PRIV_USER_OFF, PK_LEN,
} from "../../assembly/seedkernel/handler";

export { configure } from "../../assembly/seedkernel/handler";

const SCRATCH_SIZE: i32 = 0x20000; // 128 KB
const PRIVATE_SIZE: i32 = 0x20000; // 128 KB

export let scratch: i32 = 0;
let priv: i32 = 0;
scratch = heap.alloc(SCRATCH_SIZE) as i32;
priv = heap.alloc(PRIVATE_SIZE) as i32;
init(scratch, priv);

export function handle(input_len: i32): i32 {
  if (!isConfigured()) return 0;

  // Clobbers scratch with the signer-stack response, so nothing may be staged
  // there across this call — this fixture reads no input, so there is nothing
  // to lose.
  const pkSrc = loadTopSignerPubkey();
  if (pkSrc < 0) return 0;

  // Stage the pubkey in private memory before forwarding: forwardToHost's own
  // kernel.call would otherwise overwrite it mid-flight (it lives in scratch).
  const staged = priv + PRIV_USER_OFF;
  memory.copy(staged, pkSrc, PK_LEN);
  forwardToHost(staged, PK_LEN);
  return 0;
}
