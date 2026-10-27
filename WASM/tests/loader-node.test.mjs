// The Node loader (host/loader-node.ts) as an operator runs it: two processes on the
// platform ABI, each running the host script the native binary runs. One serves a signed
// app; the other installs the same app, calls the app's private module locally, then sends
// it a request over a real socket. Everything above the ABI is the native suite's code, so
// this covers what is Node's own: sockets, files, modules, the engine table and crypto.
import { existsSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { testkit } from "./testkit.mjs";
import { sendArgs } from "./transport-harness.mjs";
import { authorBundle, forwarderBytes, guestOpFraming, sodium, spawnLoader, testAuthor, toHex } from "./fixtures.mjs";

const { ok, summary } = testkit();
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

/** Start the loader for node `name`, serving the app. */
const start = (name, args, stdin) => spawnLoader(["--policy", join(work, "policy.json"), "--dir", join(work, name),
  "--key", join(work, name + ".key"), "--bundle", join(work, "app.skb"), ...args], { cwd: work, stdin });

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
    sendArgs(holderKey, payload, { proto: "probe" }));
  const sent = await sender.exit;
  ok(sent.code === 0, `the sender exits cleanly (stderr: ${sent.err.trim().split("\n").pop()})`);
  ok(sent.out.equals(Buffer.from([1, 1, 2, 3])),
    `a request crosses a socket, the handshake and the holder's module (got ${[...sent.out]})`);

  console.log("Test: an --op on a serving node's directory reaches that node (control endpoint)");
  const [, controlPath] = await holder.until(/control (\S+) \(/);
  ok(controlPath === join(work, "holder.control") && existsSync(controlPath), "the holder's control socket sits beside its directory");
  if (process.platform !== "win32") ok((statSync(controlPath).mode & 0o777) === 0o600, "owner-only");
  const op = (dir, stdin) => spawnLoader(["--dir", join(work, dir), "--op", "fwd"], { cwd: work, stdin }).exit;
  const viaControl = await op("holder", Buffer.from([4, 5, 6]));
  ok(viaControl.code === 0 && viaControl.out.equals(Buffer.from([4, 5, 6])),
    `the running holder answers, with no --bundle or --key (stderr: ${viaControl.err.trim().split("\n").pop()})`);
  ok(!existsSync(join(work, "seedkernel.key")), "and no second node, so no key of its own");
  const mixed = await spawnLoader(["--dir", join(work, "holder"), "--bundle", join(work, "app.skb"), "--op", "fwd"],
    { cwd: work, stdin: Buffer.from([8]) }).exit;
  ok(mixed.code !== 0 && /reading no --bundle/.test(mixed.err) && mixed.out.length === 0,
    "an --op that also names a bundle is refused while the node serves, not half obeyed");
  const second = spawnLoader(["--policy", join(work, "policy.json"), "--dir", join(work, "holder"), "--key", join(work, "second.key"),
    "--bundle", join(work, "app.skb"), "--listen", "127.0.0.1:0"], { cwd: work });
  const [, why] = await second.until(/control unavailable: (.*)/);
  ok(/already listens/.test(why), "a second node on the same directory leaves the live socket alone");
  second.child.kill();
  await second.exit;
  ok((await op("holder", Buffer.from([7]))).out.equals(Buffer.from([7])), "which still reaches the first");
  holder.child.kill();
  await holder.exit;
  const stale = await op("holder", Buffer.from([1]));
  ok(stale.code !== 0 && /no node is serving/.test(stale.err), "once it stops, its socket reaches nothing");
  if (process.platform === "win32") {
    writeFileSync(join(work, "other.control"), "notes");
    const foreign = await op("other", Buffer.from([1]));
    ok(foreign.code !== 0 && /native node's control socket/.test(foreign.err),
      "on Windows a control file naming no pipe is refused, never read as nobody serving");
  }
  const again = start("holder", ["--listen", "127.0.0.1:0"]);
  await again.until(/control (\S+) \(/);
  ok((await op("holder", Buffer.from([9]))).out.equals(Buffer.from([9])), "and a node starting there again replaces the stale one");
  again.child.kill();
  await again.exit;
} finally {
  rmSync(work, { recursive: true, force: true });
}
summary("node loader");
