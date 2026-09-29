// Node CLI entry: the shared operator flow (`cli.ts`) bound to the Node platform. Kept
// apart from shell-node.ts so that one stays a library module with no auto-run guard.
//
//   node build/host/main-node.js --policy ./allowed-keys.json --dir ./data \
//        --listen 0.0.0.0:7000 [--guest-timeout 5000] [--guest-memory 64]
//
// This file supplies only the platform: files, stdio, crypto, and booting a node on
// Node. Flags and what they do live in `cli.ts`, which the native binary also runs.
import { readFileSync } from "node:fs";
import { runCli, type CliHost } from "./cli.js";
import { bootNodeShell, nodeFiles } from "./shell-node.js";
import { loadCrypto } from "./crypto-node.js";
import { errMessage } from "../services/util.js";

async function nodeHost(): Promise<CliHost> {
  const sodium = await loadCrypto();
  return {
    ...nodeFiles,
    banner: "seedkernel-shell",
    argv: process.argv.slice(2),
    // stderr, because stdout carries an app's raw `--op` response bytes.
    log(line) { console.error(line); },
    stdout(bytes) { process.stdout.write(bytes); },
    // Whatever was piped in, or empty. Reading fd 0 throws instead of blocking when stdin
    // is an unredirected terminal, which also means no argument.
    stdin() {
      try { return new Uint8Array(readFileSync(0)); }
      catch { return new Uint8Array(0); }
    },
    sodium,
    // bootNodeShell takes NodeSetup directly, so new config fields pass through
    // without changes here.
    standUp: bootNodeShell,
  };
}

export async function main(): Promise<void> {
  const { serving, close } = await runCli(await nodeHost());
  if (!serving) { close(); return; }
  process.on("SIGINT", () => { close(); process.exit(0); });
}

main().catch((e) => { console.error("ERROR: " + errMessage(e)); process.exit(1); });
