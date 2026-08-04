// transport-harness.mjs — shared plumbing for the transport-bundle tests.
//
// The transport is a signed bundle whose guest program holds the AKE, record
// layer, routing and request/response layer. Tests drive it through the real
// host stack — shell → driver (TransportHost) → guest realm — with in-process
// channel pairs standing in for sockets, so the properties pinned here are
// properties of the shipped bundle, not of a parallel reimplementation.

import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const imp = (p) => import(pathToFileURL(join(root, p)).href);

export const { loadSodium, generateKeyPair } = await imp("build/host/node.js");
export const sodium = await loadSodium();
export const { createShell } = await imp("build/host/shell-core.js");
export const { createSafeRealm } = await imp("build/host/safe-js.js");
export const { policyFromJson } = await imp("build/host/policy.js");
export const { FreshnessMarks, verifyBundle } = await imp("build/host/bundle.js");
export const { KernelHost } = await imp("build/host/kernel-host.js");
export const { CLOSE_REASON, TransportHost, LoopbackChannels } = await imp("build/host/transport-host.js");
export const { TRANSPORT_BUNDLE_B64 } = await imp("build/host/transport-bundle.js");

export const transportBlob = Uint8Array.from(Buffer.from(TRANSPORT_BUNDLE_B64, "base64"));

/** The author of the artifact-shipped transport bundle, read OUT of the artifact
 *  rather than restated. A fresh clone mints its own transport author, so anything
 *  that names a fixed id — or scrapes the generated header — is drift waiting to
 *  happen. */
export function transportAuthor() {
  return Buffer.from(verifyBundle(sodium, transportBlob).author).toString("hex");
}

/** The policy every harness node runs under: the transport author is admitted
 *  for the transport role (the app-allowlist entry is parsePolicy's minimum). */
export function transportPolicy(authorHex) {
  return policyFromJson(JSON.stringify({
    authors: [authorHex],
    roles: { transport: [authorHex] },
  }));
}

/** One transport host: a shell over a fresh identity + the transport bundle. The
 *  driver (shell.net) is the node's network. Options pass through to the shell's
 *  platform (admitPeer for the peer whitelist, networkKey, contactSecret, channels)
 *  and to the shell's createShell opts (requestDeadlineMs, transportHalfOpen). */
export async function makeTransportHost(opts = {}) {
  const identity = opts.identity ?? generateKeyPair();
  const shell = createShell({
    platform: {
      sodium: opts.sodium ?? sodium,
      identity,
      kernel: new KernelHost(),
      freshnessStore: new FreshnessMarks(),
      channels: opts.channels,
      listen: opts.listen,
      networkKey: opts.networkKey,
      contactSecret: opts.contactSecret,
      admitPeer: opts.admitPeer,
      connsPerPeer: opts.connsPerPeer,
      createRealm: async (o) => createSafeRealm(o),
    },
    admit: transportPolicy(opts.transportAuthorHex ?? transportAuthor()),
    requestDeadlineMs: opts.requestDeadlineMs,
    transportHalfOpen: opts.transportHalfOpen,
  });
  await shell.loadBundleBlob(opts.transportBlob ?? transportBlob);
  return { shell, driver: shell.net, identity };
}

/** Await a condition with a deadline — the tests' tick, bounded. */
export async function until(fn, ms = 3000, what = "condition") {
  const start = Date.now();
  for (;;) {
    if (fn()) return;
    if (Date.now() - start > ms) throw new Error("timeout waiting for " + what);
    await new Promise((r) => setTimeout(r, 2));
  }
}
