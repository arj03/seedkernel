// Node CLI entry for the seedkernel-shell: the shared operator flow (`cli.ts`) bound to
// the Node platform. Kept separate from shell-node.ts so that stays a pure library module with
// no argv-sniffing auto-run guard.
//
//   node build/host/main-node.js --policy ./allowed-keys.json --dir ./data \
//        --listen 0.0.0.0:7000 [--guest-timeout 5000] [--guest-memory 64]
//
// Everything below is platform: files, stdout, entropy, and "stand a node up on Node".
// Which flags exist and what the node does with them is `cli.ts`, the same module the
// native binary runs inside QuickJS.
import { readFileSync } from "node:fs";
import { runCli, type CliHost, type NodeSetup } from "./cli.js";
import { bootNodeShell } from "./shell-node.js";
import { writeFileAtomic } from "./fs-node.js";
import { loadCrypto } from "./crypto-node.js";
import { errMessage } from "../core/util.js";

async function nodeHost(): Promise<CliHost> {
  const sodium = await loadCrypto();
  return {
    banner: "seedkernel-shell",
    argv: process.argv.slice(2),
    // null for absent, per the `CliFiles` contract: the `--key` path takes that branch
    // on a first boot and mints a seed instead of failing.
    readFile(path) {
      try { return new Uint8Array(readFileSync(path)); }
      catch { return null; }
    },
    // Atomic (fs-node.ts): what this writes is the node's master seed, and a seed
    // half-written on a first boot is a node whose identity changes when it restarts.
    writeFile: writeFileAtomic,
    // STDERR, not stdout: stdout carries an app's raw `--op` response bytes, which an
    // operator line landing in it would corrupt.
    log(line) { console.error(line); },
    stdout(bytes) { process.stdout.write(bytes); },
    // Whatever was piped in, or empty. Reading fd 0 throws rather than blocking when stdin
    // is a terminal nobody redirected, which is the same answer: no argument.
    stdin() {
      try { return new Uint8Array(readFileSync(0)); }
      catch { return new Uint8Array(0); }
    },
    sodium,
    async standUp(cfg: NodeSetup) {
      // NodeShellOptions is NodeSetup plus this platform's optional members, so the config
      // crosses unchanged — no field-by-field copy to fall out of step.
      return bootNodeShell(cfg);
    },
  };
}

export async function main(): Promise<void> {
  const { serving, close } = await runCli(await nodeHost());
  if (!serving) { close(); return; }
  process.on("SIGINT", () => { close(); process.exit(0); });
}

main().catch((e) => { console.error("ERROR: " + errMessage(e)); process.exit(1); });
