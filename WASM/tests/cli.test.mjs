// The operator flow (host/cli.ts): the flag set, defaults, key file, the order a node
// does things in, and the lines it prints. One implementation = one place to test it; the
// native target inherits every case by running the same module. `standUp` is stubbed —
// under test is the flow, not the assembly of a node (transport.test.mjs and the Go
// suite drive that for real).
import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { testkit } from "./testkit.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const imp = (p) => import(pathToFileURL(join(root, p)).href);

const { loadCrypto } = await imp("build/host/crypto-node.js");
const sodium = await loadCrypto();
const { runCli, parseArgs, parseHex32, loadedLine, DEFAULT_DIR, DEFAULT_KEY } = await imp("build/host/cli.js");
const { deriveNodeKey } = await imp("build/core/subkeys.js");
const { toHex } = await imp("build/core/util.js");

const { ok, throws, summary } = testkit();
const work = mkdtempSync(join(tmpdir(), "seedkernel-cli-"));
const utf8 = new TextEncoder();

console.log("\n— argument parsing —");
// An unknown flag is an ERROR, not an ignored token: a mistyped --polcy would otherwise
// build a deny-all node that boots, serves and installs nothing, which is
// indistinguishable from a policy doing its job.
throws(() => parseArgs(["--polcy", "x"]), "an unknown flag is refused");
throws(() => parseArgs(["--policy"]), "a flag with no value is refused");
throws(() => parseArgs(["--policy", "--dir"]), "a flag followed by another flag is refused");
throws(() => parseArgs(["bundle.skb"]), "a bare positional argument is refused");
ok(parseArgs(["--dir", "/tmp/x"]).get("dir") === "/tmp/x", "--name value parses");
ok(parseArgs(["--dir=/tmp/x"]).get("dir") === "/tmp/x", "--name=value parses");
ok(parseArgs([]).size === 0, "no arguments is not an error");

console.log("\n— 32-byte hex —");
const good = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
ok(toHex(parseHex32(good, "--key")) === good, "64 hex characters decode to the 32 bytes");
ok(toHex(parseHex32(` ${good}\n`, "--key")) === good, "surrounding whitespace is tolerated");
// fromHex maps a non-hex pair to 0, so a loose decode would boot the node under a
// DIFFERENT identity, or gate it on a contact secret nobody can produce (§12.6.2 — a
// gated node refuses callers in silence, so this is the only place to be told).
throws(() => parseHex32("zzzz" + "0".repeat(60), "--key"), "non-hex is refused rather than zero-filled");
throws(() => parseHex32(good.slice(0, 62), "--key"), "31 bytes is refused");
throws(() => parseHex32(good + "ab", "--key"), "33 bytes is refused");
throws(() => parseHex32("ab".repeat(64), "--key"), "a 64-byte ed25519 secret key is refused");

console.log("\n— the operator flow —");

/** A CliHost over in-memory files and a stubbed node, recording everything printed. */
function fakeHost(argv, { port = 0, wsPort = 0, shell = {}, linkAvailable = true } = {}) {
  const lines = [];
  const written = new Map();
  const host = {
    banner: "seedkernel-test",
    argv,
    lines,
    written,
    stood: null,
    readFile(path) {
      if (written.has(path)) return written.get(path);
      try { return new Uint8Array(readFileSync(path)); } catch { return null; }
    },
    writeFile(path, bytes) { written.set(path, bytes); },
    log(line) { lines.push(line); },
    stdout(bytes) { host.out = bytes; },
    /** `--op`'s argument. Nothing in these cases pipes one in, which is the same answer
     *  a real target gives for a terminal stdin: this op takes no argument. */
    stdin: () => new Uint8Array(0),
    sodium,
    async standUp(cfg) {
      host.stood = cfg;
      return { shell: {
        resolve: () => "_net",
        revoke: () => [],
        uninstall: () => false,
        // The one door the operator flow reaches the network through. `null` is the whole
        // of "this node has no transport" as the CLI sees it.
        call: () => (linkAvailable ? Promise.resolve(new Uint8Array(0)) : null),
        loadBundleBlob: async () => { throw new Error("no bundle in this test"); },
        invoke: async () => new Uint8Array(0),
        close: () => { host.closed = true; },
        ...shell,
      }, transport: { port, wsPort } };
    },
  };
  return host;
}

// A first boot mints the master seed, persists it, and derives the node's identity from
// it — one 32-byte secret on disk, and the peer id is its CHANNEL subkey (§12.6.2b).
{
  const keyPath = join(work, "minted.key");
  const host = fakeHost(["--key", keyPath]);
  await runCli(host);
  const minted = host.written.get(keyPath);
  ok(minted !== undefined, "an absent --key file is minted, not an error");
  const seedHex = new TextDecoder().decode(minted);
  ok(/^[0-9a-f]{64}$/.test(seedHex), "the minted key file holds 64 hex characters");
  const key = deriveNodeKey(sodium, parseHex32(seedHex, "--key"));
  ok(host.lines[0] === `seedkernel-test ${toHex(key.publicKey)}`,
    "the banner line reports the derived key as the peer id");
  // ONE identity: the key that reaches standUp — and so `node/identity`, `node/sign` and
  // the handshake — is the same key the banner prints as the peer id. A node that signed
  // a record with anything else would name an author no peer in its cohort has heard of.
  ok(toHex(host.stood.identity.publicKey) === toHex(key.publicKey),
    "the node's identity is the peer id, not a sibling key");
}

// Defaults: one --dir and one --key on every target, or the same command line runs two
// different nodes over two different stores.
{
  const host = fakeHost(["--key", join(work, "d.key")]);
  await runCli(host);
  ok(host.stood.dir === DEFAULT_DIR, `--dir defaults to ${DEFAULT_DIR}`);
  ok(DEFAULT_KEY === "./seedkernel.key", "--key defaults to ./seedkernel.key");
  ok(host.stood.policyJson === undefined, "an absent --policy is deny-all, not a policy");
  ok(host.lines.includes("  policy (none — installs disabled)"), "and the console says so");
}

// The §12.3 guest bounds reach the shell: a bound the shell accepts but no target can set
// is a bound nobody has.
{
  const host = fakeHost(["--key", join(work, "g.key"), "--guest-timeout", "250", "--guest-memory", "8"]);
  await runCli(host);
  ok(host.stood.guestDeadlineMs === 250, "--guest-timeout reaches standUp");
  ok(host.stood.realmMemoryBytes === 8 * 1024 * 1024, "--guest-memory is read as MiB");
}
{
  const host = fakeHost(["--key", join(work, "g0.key"), "--guest-timeout", "0"]);
  await runCli(host);
  ok(host.stood.guestDeadlineMs === Infinity, "--guest-timeout 0 is Infinity — no budget, said explicitly");
}

// A transport-program knob uses the bundle's installation-local config path, not the
// socket driver's options.
{
  const host = fakeHost(["--key", join(work, "t.key"), "--request-deadline", "250"]);
  await runCli(host);
  ok(host.stood.transportConfig?.requestDeadlineMs === 250,
    "--request-deadline reaches the signed transport as transportConfig");
}

// App config belongs to the bundle named in the same invocation. It is not node setup,
// which would also feed it to the transport and every later bundle on this shell.
{
  const configPath = join(work, "app.json");
  const bundlePath = join(work, "app.skb");
  writeFileSync(configPath, JSON.stringify({ mode: "local", nested: [1, { enabled: true }] }));
  writeFileSync(bundlePath, new Uint8Array([1, 2, 3]));
  let loadOpts = null;
  const author = new Uint8Array(32).fill(0x44);
  const host = fakeHost([
    "--key", join(work, "app.key"), "--bundle", bundlePath, "--app-config", configPath,
  ], {
    shell: {
      loadBundleBlob: async (_blob, opts) => {
        loadOpts = opts;
        return { author, manifest: { app: "configured", version: 1 } };
      },
    },
  });
  await runCli(host);
  ok(host.stood.config === undefined, "--app-config is not shell-wide node setup");
  ok(loadOpts?.localConfig.mode === "local" && loadOpts.localConfig.nested[1].enabled === true,
    "--app-config is attached to the explicit bundle load as general JSON");
}
{
  const configPath = join(work, "orphan.json");
  writeFileSync(configPath, "{}");
  const host = fakeHost(["--key", join(work, "orphan.key"), "--app-config", configPath]);
  let msg = "";
  try { await runCli(host); } catch (e) { msg = String(e.message); }
  ok(msg.includes("requires --bundle") && host.stood === null,
    "--app-config without an app target is refused before a shell is stood up");
}

// --contact-secret names a FILE of hex, on every target. Passing the secret itself on the
// command line would put it in `ps` output and shell history.
{
  const secretPath = join(work, "contact.hex");
  writeFileSync(secretPath, good);
  const host = fakeHost(["--key", join(work, "c.key"), "--contact-secret", secretPath]);
  await runCli(host);
  ok(host.stood.transportConfig.contactSecret === good,
    "--contact-secret is read from the file it names, into the transport's own config");
}
{
  const badPath = join(work, "bad.hex");
  writeFileSync(badPath, "not a secret");
  const host = fakeHost(["--key", join(work, "c2.key"), "--contact-secret", badPath]);
  let threw = false;
  try { await runCli(host); } catch { threw = true; }
  ok(threw, "a malformed contact secret fails at startup, where an operator can still be told");
}
{
  const host = fakeHost(["--key", join(work, "c3.key"), "--contact-secret", join(work, "nope.hex")]);
  let msg = "";
  try { await runCli(host); } catch (e) { msg = String(e.message); }
  ok(msg.includes("--contact-secret"), "an unreadable file names the flag, not the errno");
}

// Remedies run BEFORE the bundle (§12.5): a node told to write a key off must never
// briefly install what it was told to refuse.
{
  const order = [];
  const host = fakeHost(["--key", join(work, "r.key"), "--bundle", join(work, "absent.skb"),
    "--revoke", "aa,bb", "--uninstall", "author:app"], {
    shell: {
      revoke: (hex) => { order.push("revoke:" + hex); return []; },
      uninstall: (k) => { order.push("uninstall:" + k); return false; },
      loadBundleBlob: async () => { order.push("load"); throw new Error("stop here"); },
    },
  });
  let msg = "";
  try { await runCli(host); } catch (e) { msg = String(e.message); }
  ok(order.join(" ") === "revoke:aa revoke:bb uninstall:author:app",
    "revoke and uninstall run, in flag order, before the bundle is even read");
  ok(msg.startsWith("bundle:"), "an unreadable --bundle is fatal and labelled");
  ok(host.lines.some((l) => l.includes("no apps of its were loaded")),
    "a revoke that tore nothing down says so");
}

// A node that is not listening is closed rather than left running; one that is listening
// reports itself as serving so the caller keeps the process (and, natively, the event
// loop) alive.
{
  const host = fakeHost(["--key", join(work, "s0.key")]);
  const r = await runCli(host);
  ok(r.serving === false, "no --listen ⇒ not serving");
  r.close();
  ok(host.closed === true, "and the shell is closed");
}
{
  const host = fakeHost(["--key", join(work, "s1.key"), "--listen", "127.0.0.1:0"], { port: 7777 });
  const r = await runCli(host);
  ok(r.serving === true, "a bound port ⇒ serving");
  ok(host.stood.listen.host === "127.0.0.1" && host.stood.listen.port === 0, "--listen is parsed as host:port");
  ok(host.lines.includes("  tcp    listening on :7777"), "the console reports the port actually bound");
  ok(host.lines[host.lines.length - 1] === "serving — Ctrl-C to stop", "and ends with the serving line");
}
// --peers with nothing claiming the transport's service id says what is wrong rather than
// letting the flag pass silently on a node with no network.
{
  const host = fakeHost(["--key", join(work, "p.key"), "--peers", `${good}@127.0.0.1:7000`],
    { linkAvailable: false });
  let msg = "";
  try { await runCli(host); } catch (e) { msg = String(e.message); }
  ok(msg.includes("there is nothing to dial from"), "--peers with no transport claimant explains itself");
}

console.log("\n— the load line —");
// One format on every target, so the line an operator reads is the same line the native
// tests assert on (native/testhost_test.go drives this very function).
{
  const author = new Uint8Array(32).fill(0xab);
  const key = `${toHex(author)}:chat`;
  const line = loadedLine({ key, author, manifest: { app: "chat", version: 3, protocols: ["chat-v1", "chat-v2"] } });
  ok(line === `chat v3  key ${key}  serves chat-v1, chat-v2`,
    "app, version, app key and the public protocols");
  const quiet = loadedLine({ key, author, manifest: { app: "tool", version: 1 } });
  ok(quiet.endsWith("serves (nothing — this bundle claims no protocol)"),
    "a bundle claiming no protocol says so at the load, not at the first frame");
  // The two audiences are labelled apart: a transport-shaped bundle answers nothing
  // publicly yet serves a local service, and folding the two into one list would leave a
  // reader guessing which of the names a peer can send to.
  const local = loadedLine({ key, author, manifest: { app: "transport", version: 1, services: ["_net"] } });
  ok(local.endsWith("serves (nothing — this bundle claims no protocol)  locally _net"),
    "a local service claim is shown apart from the public protocols");
}

summary("cli");
