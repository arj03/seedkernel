// `host` (§12.9): hand the loader a host blob to run next. Offered only where the loader
// has host slots to keep it in.
import { EMPTY } from "../host/util.js";
import type { ServiceHandlers } from "../host/guest-seam.js";

/** The loader's host slots (§12.9): keep a host blob as the one to run next, or refuse it
 *  with the reason. */
export interface HostStaging {
  stage(blob: Uint8Array): void | Promise<void>;
}

export function hostService(staging: HostStaging): ServiceHandlers<"host"> {
  return {
    "host/stage": async (payload) => { await staging.stage(payload); return EMPTY; },
  };
}
