#!/usr/bin/env node
// One node of a NAT lab sim: runs the native binary on the relay, watches the link lines
// the CLI prints (`  link   <key> direct|relayed|gone`), and says what it saw as NDJSON on
// stdout for patchbay's captures. The node's own console goes to stderr unchanged.
//
//   node probe.mjs <seedkernel> [--deadline 20] [--linger 2] -- <seedkernel flags…>
//
//   {"kind":"up","key":"<hex>"}                       the node's key, once it has booted
//   {"kind":"route","peer":"<hex>","route":"direct"}  each change in how a peer is reached
//   {"kind":"result","route":"direct","ms":812}       once: direct, relayed or none
//
// The result comes the moment a peer goes direct, with `ms` from the first relayed link
// (or from boot when there was none), and the node then runs `--linger` seconds more so
// the far end can see the path too. With no direct path by `--deadline` seconds, the
// result is the best route seen (relayed, or none if nothing ever linked) and the probe
// exits. It always exits 0: the sim's asserts and run.sh judge the outcome, not this.
//
// A fresh key and data directory per run, so a sim never inherits an identity.
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInterface } from "node:readline";

const argv = process.argv.slice(2);
const sep = argv.indexOf("--");
if (sep < 1) {
  console.error("usage: probe.mjs <seedkernel> [--deadline s] [--linger s] -- <flags…>");
  process.exit(2);
}
const [bin, ...opts] = argv.slice(0, sep);
const nodeArgs = argv.slice(sep + 1);
const opt = (name, def) => {
  const i = opts.indexOf(`--${name}`);
  return i >= 0 ? Number(opts[i + 1]) : def;
};
const deadlineS = opt("deadline", 20), lingerS = opt("linger", 2);

const emit = (o) => process.stdout.write(JSON.stringify(o) + "\n");
const dir = mkdtempSync(join(tmpdir(), "natlab-"));
const child = spawn(bin, ["--key", join(dir, "node.key"), "--dir", join(dir, "data"), ...nodeArgs],
  // Not stdout: it carries only an `--op` answer, which a probe never asks for, and a node
  // holding patchbay's pipe would keep a sim waiting on it if the probe were killed first.
  { stdio: ["ignore", "ignore", "pipe"] });

const started = Date.now();
let firstLinked = null, best = "none", done = false;
const routes = new Map();

function finish(route) {
  if (done) return;
  done = true;
  emit({ kind: "result", route, ms: Date.now() - (firstLinked ?? started) });
  setTimeout(stop, route === "direct" ? lingerS * 1000 : 0);
}
function stop() {
  child.kill("SIGINT");
  setTimeout(() => child.kill("SIGKILL"), 2000).unref();
}

createInterface({ input: child.stderr }).on("line", (line) => {
  process.stderr.write(line + "\n");
  const up = /^seedkernel-\S+ ([0-9a-f]{64})$/.exec(line);
  if (up) { emit({ kind: "up", key: up[1] }); return; }
  const link = /^\s+link\s+([0-9a-f]{64}) (direct|relayed|gone)$/.exec(line);
  if (!link) return;
  const [, peer, route] = link;
  if (routes.get(peer) === route) return;
  routes.set(peer, route);
  emit({ kind: "route", peer, route });
  if (route !== "gone" && firstLinked === null) firstLinked = Date.now();
  if (route === "relayed" && best === "none") best = "relayed";
  if (route === "direct") finish("direct");
});

const deadline = setTimeout(() => finish(best), deadlineS * 1000);
child.on("exit", (code, signal) => {
  clearTimeout(deadline);
  if (!done) {
    process.stderr.write(`probe: node exited early (${signal ?? code})\n`);
    finish(best);
  }
  rmSync(dir, { recursive: true, force: true });
  process.exit(0);
});
for (const s of ["SIGINT", "SIGTERM"]) process.on(s, stop);
