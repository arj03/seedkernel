// Host updates through the Node loader (host/loader-node.ts, §12.9): an app stages a signed
// host blob over the `host` service, the running host checks it, the loader tries it once,
// commits it after a health window, and drops it for the committed host when it fails
// first. The native loader keeps
// the same rules (native/hostslots.go); its tests check them in Go.
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { testkit } from "./testkit.mjs";
import { authorBundle, guestOpFraming, imp, root, sodium, testAuthor, toHex } from "./fixtures.mjs";

const { ok, summary } = testkit();
const { verifyHostBlob } = await imp("build/host/host-blob.js");
const { Loader } = await imp("build/host/slots.js");
const { signHostBlob, hybridAuthorKeysFromSeed } = await imp("build/scripts/bundle-author.js");
const loader = join(root, "build/host/loader-node.js");
const work = mkdtempSync(join(tmpdir(), "seedkernel-updates-"));
const HEALTH_MS = 400;

// Hosts from this clone's host author, as the genesis blob is, at chosen versions.
const genesis = verifyHostBlob(sodium, readFileSync(join(root, "build/host.skb")));
const hostKeys = hybridAuthorKeysFromSeed(sodium, Buffer.from(readFileSync(join(root, "host-author.key"), "utf8").trim(), "hex"));
const hostBlob = (version, keys = hostKeys, script = genesis.script, abi = genesis.manifest.abi) => signHostBlob(sodium, keys, { version, abi },
  { script, qjs: genesis.qjs, sodium: genesis.sodium, mldsa: genesis.mldsa });

const author = testAuthor();
writeFileSync(join(work, "updater.skb"), authorBundle(sodium, author, {
  app: "updater", version: 1, modules: [], guestRequires: ["host"],
  guestSource: `${guestOpFraming()}
    async function handle(arg) {
      const { op, args } = readOp(arg.subarray(32));
      if (op === "stage") await host.call("host/stage", args);
      return new Uint8Array([1]);
    }`,
}).blob);
writeFileSync(join(work, "policy.json"), JSON.stringify({ authors: [toHex(author.id)] }));
const dir = join(work, "data");
const slot = (name) => join(work, "data.host", name);

/** Run the loader on this node's data directory. */
function start(args, stdin) {
  const child = spawn(process.execPath, [loader, "--policy", join(work, "policy.json"), "--dir", dir,
    "--key", join(work, "node.key"), "--bundle", join(work, "updater.skb"), ...args],
  { cwd: work, env: { ...process.env, SEEDKERNEL_HOST_HEALTH_MS: String(HEALTH_MS) } });
  let err = "";
  child.stderr.on("data", (b) => { err += b; });
  child.stdin.end(stdin ?? Buffer.alloc(0));
  const until = (re) => new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`no ${re} in:\n${err}`)), 20000);
    const look = () => { if (re.test(err)) { clearTimeout(t); resolve(); } };
    child.stderr.on("data", look);
    look();
  });
  const exit = new Promise((resolve) => child.on("exit", (code) => resolve({ code, err })));
  return { child, until, exit, log: () => err };
}
/** Stage a blob through the updater app, as a one-op run. */
const stage = (blob, mode = "next") => start(["--host-updates", mode, "--op", "stage"], blob).exit;
/** Serve until `re` shows, then stop. */
async function serveUntil(re, args = []) {
  const node = start(["--listen", "127.0.0.1:0", ...args]);
  await node.until(re);
  node.child.kill();
  await node.exit;
  return node.log();
}

try {
  console.log("Test: staging is the operator's to allow");
  let r = await stage(hostBlob(2), "off");
  ok(r.code !== 0 && /updates are off/.test(r.err), "with updates off, a staged host is refused");
  ok(!existsSync(slot("pending.skb")), "…and nothing is kept");

  console.log("Test: a staged host is tried once, then committed after its health window");
  r = await stage(hostBlob(2));
  ok(r.code === 0 && /staged v2/.test(r.err), `a newer host from the host author is staged (${r.err.trim().split("\n").pop()})`);
  let log = await serveUntil(/committed after/);
  ok(/trying v2 \(committed is v1\)/.test(log), "the next start tries it");
  ok(existsSync(slot("committed.skb")) && !existsSync(slot("pending.skb")) && !existsSync(slot("tried")),
    "it is committed after serving through the window");
  ok(verifyHostBlob(sodium, readFileSync(slot("committed.skb"))).manifest.version === 2, "the committed host is v2");

  console.log("Test: the floor and the author");
  r = await stage(hostBlob(2));
  ok(r.code !== 0 && /v2 is not above v2/.test(r.err), "the committed version is the floor");
  const stranger = hybridAuthorKeysFromSeed(sodium, new Uint8Array(32).fill(9));
  r = await stage(hostBlob(5, stranger));
  ok(r.code !== 0 && /not the running host's author/.test(r.err), "another author's host is refused");
  r = await stage(readFileSync(join(work, "updater.skb")));
  ok(r.code !== 0 && /host: signature invalid/.test(r.err), "an app bundle does not pass as a host");
  const tampered = hostBlob(7);
  tampered[tampered.length - 1] ^= 1;
  r = await stage(tampered);
  ok(r.code !== 0 && /host: signature invalid/.test(r.err), "a tampered host is refused");
  ok(!existsSync(slot("pending.skb")), "…and none of the refused ones is kept");

  console.log("Test: a host that fails before it is committed is dropped for the committed one");
  r = await stage(hostBlob(3, hostKeys, new TextEncoder().encode('throw new Error("broken host");')));
  ok(r.code === 0, "a newer host is staged, whatever it does");
  log = await serveUntil(/listening on/);
  ok(/trying v3/.test(log) && /discarded the pending host: broken host/.test(log),
    "it fails to boot and is discarded");
  ok(!existsSync(slot("pending.skb")) && !existsSync(slot("tried")), "…pending and its mark are gone");
  ok(verifyHostBlob(sodium, readFileSync(slot("committed.skb"))).manifest.version === 2, "v2 stays committed and serves");

  console.log("Test: a host that was tried and never committed is not tried again");
  writeFileSync(slot("pending.skb"), hostBlob(4));
  writeFileSync(slot("tried"), new Uint8Array(0));
  log = await serveUntil(/listening on/);
  ok(/discarded the pending host: it was tried and never committed/.test(log), "the mark means it died in its trial");
  ok(!/trying v4/.test(log), "…so it does not run");

  console.log("Test: under now, a staged host boots at once");
  const node = start(["--listen", "127.0.0.1:0", "--host-updates", "now", "--op", "stage"], hostBlob(6));
  await node.until(/committed after/);
  node.child.kill();
  await node.exit;
  ok(/staged v6/.test(node.log()) && /trying v6/.test(node.log()), "the node reboots into it in the same process");
  ok(verifyHostBlob(sodium, readFileSync(slot("committed.skb"))).manifest.version === 6, "…and commits it");

  // The loader's own answers, which both loaders act on: the process test above stages
  // during the operator flow only.
  console.log("Test: under now, the loader boots a staged host at once while the node serves, else once the flow ends");
  const memFiles = (mem) => ({
    mkdir() {},
    read: (p) => mem.get(p) ?? null,
    write: (p, b) => { mem.set(p, b); },
    remove: (p) => mem.delete(p),
    size: (p) => (mem.has(p) ? mem.get(p).length : -1),
  });
  const l = new Loader(memFiles(new Map()), ["--host-updates", "now", "--dir", "mem"], readFileSync(join(root, "build/host.skb")), "0",
    () => {}, () => {});
  l.choose();
  ok(!l.stage(hostBlob(8)) && l.ended(true), "staged during the operator flow, it boots once a serving flow has ended");
  l.choose();
  ok(!l.ended(true), "…and the host it boots serves");
  ok(l.stage(hostBlob(9)), "staged while the node serves, it boots at once");
  l.choose();
  ok(!l.stage(hostBlob(10)) && !l.ended(false), "staged during a flow that does not serve, it waits for the next start");

  console.log("Test: the health window commits the host it tried, not one that host staged meanwhile");
  const mem = new Map();
  let window = () => {};
  const n = new Loader(memFiles(mem), ["--host-updates", "next", "--dir", "mem"], readFileSync(join(root, "build/host.skb")), "0",
    () => {}, (ms, fn) => { window = fn; });
  n.choose();
  n.ended(true);
  n.stage(hostBlob(2));
  n.choose();
  n.ended(true);
  n.stage(hostBlob(3));
  window();
  const version = (env) => env && verifyHostBlob(sodium, env).manifest.version;
  ok(version(mem.get("mem.host/committed.skb")) === 2 && version(mem.get("mem.host/pending.skb")) === 3,
    "the tried host is committed, and the one it staged stays pending");
  ok(version(n.choose()) === 3 && mem.has("mem.host/tried"), "…for a trial of its own at the next start");

  console.log("Test: a committed host that cannot be read stops the boot, since the floor is lost with it");
  const throwsOn = (fn) => { try { fn(); return ""; } catch (err) { return err.message; } };
  const genesisEnv = readFileSync(join(root, "build/host.skb"));
  const broken = new Map([["mem.host/committed.skb", hostBlob(4).subarray(0, 4000)]]);
  const b = new Loader(memFiles(broken), ["--dir", "mem"], genesisEnv, "0", () => {}, () => {});
  ok(/^committed\.skb: host: .*; restore it, or remove it to boot v\d+$/.test(throwsOn(() => b.choose())),
    "a truncated committed.skb is refused, not passed over for the genesis blob");
  // There, by its size, but every read fails, as one the process may not open does.
  const u = new Loader({ ...memFiles(broken), read: () => null }, ["--dir", "mem"], genesisEnv, "0", () => {}, () => {});
  ok(/^committed\.skb: cannot be read;/.test(throwsOn(() => u.choose())), "…and so is one that is there but unreadable");

  console.log("Test: --host refuses a file that is no host blob, whichever loader reads it");
  const files = memFiles(new Map([["junk.skb", new Uint8Array(100)], ["old.skb", hostBlob(1, hostKeys, genesis.script, genesis.manifest.abi + 1)]]));
  ok(/^host: /.test(throwsOn(() => new Loader(files, ["--host", "junk.skb"], genesisEnv, "0", () => {}, () => {}))),
    "a file that does not frame as one");
  ok(/^--host: old\.skb is not for platform ABI/.test(throwsOn(() => new Loader(files, ["--host", "old.skb"], genesisEnv, "0", () => {}, () => {}))),
    "a blob for another platform ABI");

  console.log("Test: --host runs a blob by the operator's choice, from any author");
  writeFileSync(join(work, "stranger.skb"), hostBlob(1, stranger));
  log = await serveUntil(/listening on/, ["--host", join(work, "stranger.skb")]);
  ok(!/trying|discarded/.test(log), "the slots are not consulted");
} finally {
  rmSync(work, { recursive: true, force: true });
}
summary("host updates");
