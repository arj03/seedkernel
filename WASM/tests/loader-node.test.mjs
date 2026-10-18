// The Node loader (host/loader-node.ts) as an operator runs it: two processes on the
// platform ABI, each running the host script the native binary runs. One serves a signed
// app; the other installs the same app, calls the app's private module locally, then sends
// it a request over a real socket. Everything above the ABI is the native suite's code, so
// this covers what is Node's own: sockets, files, modules, the engine table and crypto.
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { testkit } from "./testkit.mjs";
import { authorBundle, forwarderBytes, guestOpFraming, root, sodium, testAuthor, toHex } from "./fixtures.mjs";

const { ok, summary } = testkit();
const loader = join(root, "build/host/loader-node.js");
const work = mkdtempSync(join(tmpdir(), "seedkernel-loader-"));

const author = testAuthor();
const app = authorBundle(sodium, author, {
  app: "probe", version: 1, protocols: ["probe"],
  modules: [{ name: "fwd", wasm: forwarderBytes }],
  guestRequires: ["_net"],
  guestSource: `${guestOpFraming()}
    function handle(arg) {
      const caller = callerOf(arg);
      const p = arg.subarray(32);
      if (!caller.fromHost) return host.call("fwd", p);
      const { op, args } = readOp(p);
      if (op === "send") return host.call("_net", writeOp("send", args));
      return host.call("fwd", args);
    }`,
});
writeFileSync(join(work, "app.skb"), app.blob);
writeFileSync(join(work, "policy.json"), JSON.stringify({ authors: [toHex(author.id)] }));

/** Start a loader; `until` resolves with the first stderr line matching it. */
function start(name, args, stdin) {
  const child = spawn(process.execPath, [loader, "--policy", join(work, "policy.json"),
    "--dir", join(work, name), "--key", join(work, name + ".key"), "--bundle", join(work, "app.skb"), ...args],
  { cwd: work });
  let err = "";
  const out = [];
  child.stderr.on("data", (b) => { err += b; });
  child.stdout.on("data", (b) => { out.push(b); });
  child.stdin.end(stdin ?? Buffer.alloc(0));
  const until = (re) => new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`${name}: no ${re} in:\n${err}`)), 20000);
    const look = () => {
      const m = err.match(re);
      if (m) { clearTimeout(t); resolve(m); }
    };
    child.stderr.on("data", look);
    look();
  });
  const exit = new Promise((resolve) => child.on("exit", (code) => resolve({ code, out: Buffer.concat(out), err })));
  return { child, until, exit };
}

/** The transport's `send` op argument: [noReply u8][to][proto][payload], each u32-prefixed. */
function sendArgs(to, proto, payload) {
  const parts = [to, new TextEncoder().encode(proto), payload];
  const out = Buffer.alloc(1 + parts.reduce((n, p) => n + 4 + p.length, 0));
  let at = 1;
  for (const p of parts) { out.writeUInt32BE(p.length, at); out.set(p, at + 4); at += 4 + p.length; }
  return out;
}

try {
  console.log("Test: the Node loader runs the host script on the platform ABI");
  const local = start("local", ["--op", "fwd"], Buffer.from([7, 8, 9]));
  const localDone = await local.exit;
  ok(localDone.code === 0, `a local op exits cleanly (stderr: ${localDone.err.trim().split("\n").pop()})`);
  ok(/^seedkernel-shell [0-9a-f]{64}$/m.test(localDone.err), "the banner names this loader and the node key");
  ok(localDone.out.equals(Buffer.from([7, 8, 9])), "the app's private module answers through the engine and module table");

  const holder = start("holder", ["--listen", "127.0.0.1:0"]);
  const [, holderKey] = await holder.until(/^seedkernel-shell ([0-9a-f]{64})$/m);
  const [, port] = await holder.until(/listening on :(\d+)/);
  ok(Number(port) > 0, "the holder serves on a bound port");

  const payload = Uint8Array.of(1, 2, 3);
  const sender = start("sender", ["--peers", `${holderKey}@tcp://127.0.0.1:${port}`, "--op", "send"],
    sendArgs(Buffer.from(holderKey, "hex"), "probe", payload));
  const sent = await sender.exit;
  ok(sent.code === 0, `the sender exits cleanly (stderr: ${sent.err.trim().split("\n").pop()})`);
  ok(sent.out.equals(Buffer.from([1, 1, 2, 3])),
    `a request crosses a socket, the handshake and the holder's module (got ${[...sent.out]})`);
  holder.child.kill();
  await holder.exit;
} finally {
  rmSync(work, { recursive: true, force: true });
}
summary("node loader");
