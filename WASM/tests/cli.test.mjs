// The operator flow (host/cli.ts): flags, defaults, the key file, the order a node does
// things in, and what it prints. The native target runs the same module, so these cases
// cover it too. `standUp` is stubbed: this tests the flow, not node assembly
// (transport.test.mjs and the Go suite cover that for real).
import { fileURLToPath, pathToFileURL } from "node:url";
import { basename, dirname, join } from "node:path";
import { mkdtempSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { testkit } from "./testkit.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const imp = (p) => import(pathToFileURL(join(root, p)).href);

const { loadCrypto } = await imp("build/host/crypto-node.js");
const sodium = await loadCrypto();
const { runCli, parseArgs, parseHex32, loadedLine, DEFAULT_DIR, DEFAULT_KEY } = await imp("build/host/cli.js");
const { deriveNodeKey } = await imp("build/services/subkeys.js");
const { toHex } = await imp("build/services/util.js");

const { ok, throws, summary } = testkit();
const work = mkdtempSync(join(tmpdir(), "seedkernel-cli-"));
const utf8 = new TextEncoder();

console.log("\n— argument parsing —");
// An unknown flag is an error, not ignored: a mistyped --polcy would otherwise boot a
// deny-all node that installs nothing, indistinguishable from a working policy.
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
// different identity, or gate it on a contact secret nobody has (§12.6.3; a gated node
// refuses callers silently, so this is the only place the mistake would show).
throws(() => parseHex32("zzzz" + "0".repeat(60), "--key"), "non-hex is refused rather than zero-filled");
throws(() => parseHex32(good.slice(0, 62), "--key"), "31 bytes is refused");
throws(() => parseHex32(good + "ab", "--key"), "33 bytes is refused");
throws(() => parseHex32("ab".repeat(64), "--key"), "a 64-byte ed25519 secret key is refused");

console.log("\n— the operator flow —");

/** A CliHost over in-memory files and a stubbed node, recording everything printed. */
function fakeHost(argv, { listening = [], shell = {}, linkAvailable = true } = {}) {
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
      // Only a missing file reads as absent (the `CliFiles` contract).
      try { return new Uint8Array(readFileSync(path)); }
      catch (e) { if (e.code === "ENOENT") return null; throw e; }
    },
    writeFile(path, bytes) { written.set(path, bytes); },
    log(line) { lines.push(line); },
    stdout(bytes) { host.out = bytes; },
    /** `--op`'s argument. None of these cases pipes one in, which matches what a real
     *  target returns for a terminal stdin. */
    stdin: () => new Uint8Array(0),
    sodium,
    async standUp(cfg) {
      host.stood = cfg;
      return { shell: {
        resolve: () => "_net",
        revoke: () => [],
        uninstall: () => false,
        // The only way the operator flow reaches the network. `null` means this node has
        // no transport.
        call: () => (linkAvailable ? Promise.resolve(new Uint8Array(0)) : null),
        install: async () => { throw new Error("no bundle in this test"); },
        invoke: async () => new Uint8Array(0),
        close: () => { host.closed = true; },
        ...shell,
      }, transport: cfg.transport ? { listening } : null };
    },
  };
  return host;
}

// A first boot creates the master seed, saves it, and derives the node's identity from
// it: one 32-byte secret on disk, and the peer id is its `channel` subkey (§12.6.2b).
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
  // One identity: the key passed to standUp (and so `HOST.identity`, `node/sign` and the
  // handshake) is the key the banner prints as the peer id.
  ok(toHex(host.stood.identity.publicKey) === toHex(key.publicKey),
    "the node's identity is the peer id, not a sibling key");
}

// Defaults: the same --dir and --key on every target, or the same command line would run
// two different nodes over two different stores.
{
  const host = fakeHost(["--key", join(work, "d.key")]);
  await runCli(host);
  ok(host.stood.dir === DEFAULT_DIR, `--dir defaults to ${DEFAULT_DIR}`);
  ok(DEFAULT_KEY === "./seedkernel.key", "--key defaults to ./seedkernel.key");
  ok(host.stood.policyJson === undefined, "an absent --policy is deny-all, not a policy");
  ok(host.lines.includes("  policy (none — app installs disabled)"), "and the console says so");
}

// Network activation is independent of policy and requires an explicit network flag.
for (const flags of [[], ["--listen", "127.0.0.1:0"], ["--listen", "ws=127.0.0.1:0"], ["--peers", ""]]) {
  const host = fakeHost(["--key", join(work, "network.key"), ...flags]);
  await runCli(host);
  ok(Boolean(host.stood.transport) === (flags.length > 0), `network opt-in: ${JSON.stringify(flags)}`);
}

// The real Node adapter honors the CLI's switch, including its nullable transport result.
{
  const { bootNodeShell } = await imp("build/host/shell-node.js");
  for (const network of [false, true]) {
    const node = await bootNodeShell({
      dir: mkdtempSync(join(work, "node-")), transport: network ? {} : false,
      identity: sodium.crypto_sign_keypair(),
    });
    try {
      ok((node.transport !== null) === network, `Node adapter network=${network}`);
      ok((node.shell.resolve("_net") !== null) === network, `Node transport slot network=${network}, no policy`);
    } finally { node.shell.close(); }
  }
}

// The §12.3 guest bounds reach the shell; otherwise no operator could set them.
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
// Anything but a whole number is refused, never coerced: `Number` reads "5000ms" as NaN,
// which could mean no budget, and "64M" as a NaN heap limit, which the JS engine treats as
// no limit. Refused before a key is created or a shell started.
for (const [flag, value] of [["--guest-timeout", "5000ms"], ["--guest-timeout", "-1"],
  ["--guest-memory", "64M"], ["--guest-memory", ""], ["--guest-memory", "1.5"]]) {
  const host = fakeHost(["--key", join(work, "gbad.key"), flag, value]);
  let msg = "";
  try { await runCli(host); } catch (e) { msg = String(e.message); }
  ok(msg.startsWith(`${flag} must be a whole number`) && host.written.size === 0 && host.stood === null,
    `${flag} ${JSON.stringify(value)} is refused`);
}

// A key file that exists but cannot be read fails the boot. Treated as absent, the
// first-boot path would write a new seed over the node's identity.
{
  const keyPath = join(work, "unreadable.key");
  const host = fakeHost(["--key", keyPath]);
  host.readFile = (path) => {
    if (path === keyPath) throw Object.assign(new Error("EACCES: permission denied"), { code: "EACCES" });
    return null;
  };
  let msg = "";
  try { await runCli(host); } catch (e) { msg = String(e.message); }
  ok(msg.startsWith(`--key: cannot read ${keyPath}`) && host.written.size === 0 && host.stood === null,
    "an unreadable --key fails the boot and mints nothing over it");
}
// The Node binding keeps that contract, as native does (shell-node.ts `nodeFiles`). A
// directory at the path is a portable read failure that cannot be mistaken for ENOENT.
{
  const { nodeFiles } = await imp("build/host/shell-node.js");
  ok(nodeFiles.readFile(join(work, "never-written")) === null, "Node: only a missing file reads as absent");
  const keyDir = mkdtempSync(join(work, "keydir-"));
  throws(() => nodeFiles.readFile(keyDir), "Node: a path that exists and cannot be read throws");
  const host = fakeHost(["--key", keyDir]);
  host.readFile = nodeFiles.readFile;
  host.writeFile = nodeFiles.writeFile;
  let msg = "";
  try { await runCli(host); } catch (e) { msg = String(e.message); }
  const temps = readdirSync(work).filter((n) => n.startsWith(basename(keyDir) + ".") && n.endsWith(".tmp"));
  ok(msg.startsWith("--key: cannot read") && statSync(keyDir).isDirectory() && temps.length === 0,
    "Node: an unreadable --key fails at the read, and nothing is written beside it");
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
    "--key", join(work, "app.key"), "--bundle", bundlePath, "--local-config", configPath,
  ], {
    shell: {
      install: async (_blob, opts) => {
        loadOpts = opts;
        return { author, manifest: { app: "configured", version: 1 } };
      },
    },
  });
  await runCli(host);
  ok(host.stood.config === undefined, "--local-config is not shell-wide node setup");
  ok(loadOpts?.localConfig.mode === "local" && loadOpts.localConfig.nested[1].enabled === true,
    "--local-config is attached to the explicit bundle load as general JSON");
}
{
  const configPath = join(work, "orphan.json");
  writeFileSync(configPath, "{}");
  const host = fakeHost(["--key", join(work, "orphan.key"), "--local-config", configPath]);
  let msg = "";
  try { await runCli(host); } catch (e) { msg = String(e.message); }
  ok(msg.includes("requires --bundle") && host.stood === null,
    "--local-config without an app target is refused before a shell is stood up");
}
// Transport-only flags without a network flag would be silently ignored, so they are refused.
for (const flag of ["--transport", "--contact-secret"]) {
  const host = fakeHost(["--key", join(work, "orphan.key"), flag, join(work, "absent")]);
  let msg = "";
  try { await runCli(host); } catch (e) { msg = String(e.message); }
  ok(msg.includes(`${flag} requires`) && host.stood === null,
    `${flag} without a network flag is refused before a shell is stood up`);
}

// --contact-secret names a file of hex on every target; the secret itself on the command
// line would show up in `ps` output and shell history. `--peers ""` enables the network
// the secret configures, with no cohort to wait for.
{
  const secretPath = join(work, "contact.hex");
  writeFileSync(secretPath, good);
  const host = fakeHost(["--key", join(work, "c.key"), "--peers", "", "--contact-secret", secretPath]);
  await runCli(host);
  ok(host.stood.transport.config.contactSecret === good,
    "--contact-secret is read from the file it names, into the transport's own config");
}
// Both transport flags pass through unread: the peer grammar and the secret's encoding
// belong to the transport, which refuses malformed values at load
// (tests/transport-bundle.test.mjs), so a replacement transport needs no new binary.
{
  const badPath = join(work, "bad.hex");
  writeFileSync(badPath, "not a secret\n");
  const ref = `${good}.${good}@ws://h:1/p`;
  const host = fakeHost(["--key", join(work, "c2.key"), "--peers", `${ref},not-a-ref`, "--contact-secret", badPath]);
  await runCli(host);
  ok(host.stood.transport.config.contactSecret === "not a secret",
    "--contact-secret reaches the transport as the file says it, less its line ending");
  ok(JSON.stringify(host.stood.transport.config.peers) === JSON.stringify([ref, "not-a-ref"]),
    "--peers reaches the transport as typed");
}
{
  const host = fakeHost(["--key", join(work, "c3.key"), "--peers", "", "--contact-secret", join(work, "nope.hex")]);
  let msg = "";
  try { await runCli(host); } catch (e) { msg = String(e.message); }
  ok(msg.includes("--contact-secret"), "an unreadable file names the flag, not the errno");
}

// Remedies run before the bundle (§12.5): a node told to revoke a key must never briefly
// install what it was told to refuse.
{
  const order = [];
  const host = fakeHost(["--key", join(work, "r.key"), "--bundle", join(work, "absent.skb"),
    "--revoke", "aa,bb", "--uninstall", "chat"], {
    shell: {
      revoke: (hex) => { order.push("revoke:" + hex); return []; },
      uninstall: (k) => { order.push("uninstall:" + k); return false; },
      install: async () => { order.push("load"); throw new Error("stop here"); },
    },
  });
  let msg = "";
  try { await runCli(host); } catch (e) { msg = String(e.message); }
  ok(order.join(" ") === "revoke:aa revoke:bb uninstall:chat",
    "revoke and uninstall run, in flag order, before the bundle is even read");
  ok(msg.startsWith("bundle:"), "an unreadable --bundle is fatal and labelled");
  ok(host.lines.some((l) => l.includes("no apps of its were loaded")),
    "a revoke that tore nothing down says so");
}

// A node that is not listening is closed instead of left running; one that is listening
// reports itself as serving so the caller keeps the process (and on native, the event
// loop) alive.
{
  const host = fakeHost(["--key", join(work, "s0.key")]);
  const r = await runCli(host);
  ok(r.serving === false, "no --listen ⇒ not serving");
  r.close();
  ok(host.closed === true, "and the shell is closed");
}
{
  const host = fakeHost(["--key", join(work, "s1.key"), "--listen", "127.0.0.1:0,ws=:7001"],
    { listening: [{ label: "tcp", host: "127.0.0.1", port: 7777 }, { label: "ws", host: "0.0.0.0", port: 7001 }] });
  const r = await runCli(host);
  ok(r.serving === true, "a bound port ⇒ serving");
  const [plain, ws] = host.stood.transport.listen;
  ok(plain.label === "tcp" && plain.host === "127.0.0.1" && plain.port === 0,
    "--listen is parsed as host:port, labelled tcp when it names no label");
  ok(ws.label === "ws" && ws.host === "0.0.0.0" && ws.port === 7001,
    "a label= prefix is the listener's label, and a bare :port binds every interface");
  ok(host.lines.includes("  tcp    listening on :7777"), "the console reports the port actually bound");
  ok(host.lines.includes("  ws     listening on :7001"), "one line per listener, under its label");
  ok(host.lines[host.lines.length - 1] === "serving — Ctrl-C to stop", "and ends with the serving line");
}
// A label is checked for shape, so an address can never be read as a label.
{
  const host = fakeHost(["--key", join(work, "s2.key"), "--listen", "b@d=127.0.0.1:0"]);
  let msg = "";
  try { await runCli(host); } catch (e) { msg = String(e.message); }
  ok(msg.includes("bad label"), "a malformed --listen label is refused by name");
}
// --peers with nothing claiming the transport's service id reports the problem instead of
// passing silently on a node with no network.
{
  const host = fakeHost(["--key", join(work, "p.key"), "--peers", `${good}@127.0.0.1:7000`],
    { linkAvailable: false });
  let msg = "";
  try { await runCli(host); } catch (e) { msg = String(e.message); }
  ok(msg.includes("there is nothing to dial from"), "--peers with no transport claimant explains itself");
}
// --relay reaches the transport's `relay` op as typed, and a node on a relay serves through
// it without a listener. Only the relay is printed: the room in its path is a credential.
{
  const url = "wss://relay.example:443/secret-room";
  const calls = [];
  const host = fakeHost(["--key", join(work, "r.key"), "--relay", url], {
    shell: { call: (_svc, b) => { calls.push(new TextDecoder().decode(b)); return Promise.resolve(new Uint8Array(0)); } },
  });
  const result = await runCli(host);
  ok(calls.length === 1 && calls[0].startsWith("\x05relay") && calls[0].endsWith(url), "--relay is the transport's relay op, unread");
  ok(host.stood.transport !== false, "--relay enables the network");
  ok(result.serving, "a node on a relay keeps serving without a listener");
  ok(host.lines.some((l) => l === "  relay  wss://relay.example:443") && !host.lines.some((l) => l.includes("secret-room")),
    "the relay is printed, the room is not");
}
{
  const host = fakeHost(["--key", join(work, "r2.key"), "--relay", "ws://127.0.0.1:1/"], { linkAvailable: false });
  let msg = "";
  try { await runCli(host); } catch (e) { msg = String(e.message); }
  ok(msg.includes("nothing to join it with"), "--relay with no transport claimant explains itself");
}

console.log("\n— the load line —");
// One format on every target, so the line an operator reads is the one the native tests
// assert on (native/testhost_test.go calls this function).
{
  const author = new Uint8Array(32).fill(0xab);
  const key = "chat";
  const line = loadedLine({ key, author, manifest: { app: "chat", version: 3, protocols: ["chat-v1", "chat-v2"] } });
  ok(line === `chat v3  author ${toHex(author)}  serves chat-v1, chat-v2`,
    "app, version, author and the public protocols");
  const quiet = loadedLine({ key, author, manifest: { app: "tool", version: 1 } });
  ok(quiet.endsWith("serves (nothing — this bundle claims no protocol)"),
    "a bundle claiming no protocol says so at the load, not at the first frame");
  // The two audiences are labelled separately: a transport-like bundle serves nothing to
  // peers but does serve a local service, and one combined list would hide which names a
  // peer can send to.
  const local = loadedLine({ key, author, manifest: { app: "transport", version: 1, services: ["_net"] } });
  ok(local.endsWith("serves (nothing — this bundle claims no protocol)  locally _net"),
    "a local service claim is shown apart from the public protocols");
}

summary("cli");
