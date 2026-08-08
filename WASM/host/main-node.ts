// Node CLI entry for the seedkernel-shell: the shared operator flow (`cli.ts`) bound to
// the Node platform. Kept separate from main.ts so that stays a pure library module with
// no argv-sniffing auto-run guard.
//
//   node build/host/main-node.js --policy ./allowed-keys.json --dir ./data \
//        --listen 0.0.0.0:7000 [--guest-timeout 5000] [--guest-memory 64]
//
// Everything below is platform: files, stdout, entropy, and "stand a node up on Node".
// Which flags exist, what they default to, and what the node does with them is
// `cli.ts` — the same module the native binary runs inside QuickJS.
import { readFileSync, writeFileSync, renameSync } from "node:fs";
import { runCli, type CliHost, type NodeSetup } from "./cli.js";
import { boot } from "./main.js";
import { loadCrypto } from "./crypto-node.js";
import { errMessage } from "../core/util.js";

/** Write atomically: a temp beside the target, then a rename onto it. The two files
 *  this writes — the node's master seed and a `--get --out` result — are both files a
 *  truncated version of would be worse than none, and a seed half-written on a first
 *  boot is a node whose identity changes the next time it starts. */
function writeFileAtomic(path: string, bytes: Uint8Array, mode?: number): void {
  const tmp = `${path}.${process.pid}.tmp`;
  writeFileSync(tmp, bytes, mode === undefined ? undefined : { mode });
  renameSync(tmp, path);
}

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
    writeFile: writeFileAtomic,
    log(line) { console.log(line); },
    stdout(bytes) { process.stdout.write(bytes); },
    sodium,
    async standUp(cfg: NodeSetup) {
      // ShellOptions is NodeSetup plus this platform's own optional members, so the
      // config crosses unchanged — no field-by-field copy to fall out of step.
      return boot(cfg);
    },
  };
}

export async function main(): Promise<void> {
  const { serving, close } = await runCli(await nodeHost());
  if (!serving) { close(); return; }
  process.on("SIGINT", () => { close(); process.exit(0); });
}

main().catch((e) => { console.error("ERROR: " + errMessage(e)); process.exit(1); });
