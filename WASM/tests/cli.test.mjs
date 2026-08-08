// The operator flow (host/cli.ts): the flag set, the defaults, the key file, the order
// a node does things in, and the lines it prints.
//
// This is covered here rather than per target on purpose. The flow used to exist twice —
// once in TypeScript and once again in Go — and the drift it accumulated was invisible
// precisely because each target's tests only ever exercised its own copy: `--contact-secret`
// came to name a file on one and the hex itself on the other, and `--guest-timeout` was
// reachable on neither. There is one implementation now, so there is one place to test it,
// and the native target inherits every case below by running the same module.
//
// `standUp` is stubbed. What is under test is the flow — which files are read, in what
// order things happen, what the console says — not the assembly of a node, which
// transport.test.mjs and the Go suite both drive for real.
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
const { deriveNodeKeys } = await imp("build/core/subkeys.js");
const { toHex } = await imp("build/core/util.js");

const { ok, throws, summary } = testkit();
const work = mkdtempSync(join(tmpdir(), "seedkernel-cli-"));
const utf8 = new TextEncoder();

console.log("\n— argument parsing —");
// An unknown flag is an ERROR, not an ignored token. The failure this prevents is the
// silent one: a mistyped --polcy left the old parser building a deny-all node that boots,
// serves and installs nothing, which is indistinguishable from a policy doing its job.
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
function fakeHost(argv, { port = 0, wsPort = 0, shell = {} } = {}) {
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
    sodium,
    async standUp(cfg) {
      host.stood = cfg;
      return {
        revoke: () => [],
        uninstall: () => false,
        loadBundleBlob: async () => { throw new Error("no bundle in this test"); },
        runGuest: async () => new Uint8Array(0),
        serve: async () => {},
        close: () => { host.closed = true; },
        // The node's transport driver — the one field the flow reads its ports and its
        // address book off. `null` here would be the no-transport-bundle node.
        transport: { port, wsPort },
        ...shell,
      };
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
  const keys = deriveNodeKeys(sodium, parseHex32(seedHex, "--key"));
  ok(host.lines[0] === `seedkernel-test ${toHex(keys.channel.publicKey)}`,
    "the banner line reports the channel subkey as the peer id");
  ok(toHex(keys.guest.publicKey) !== toHex(keys.channel.publicKey),
    "the guest subkey differs from the channel subkey");
  ok(host.stood.identity !== undefined && host.stood.guestIdentity !== undefined,
    "both purpose-bound keypairs reach standUp");
}

// Defaults: one --dir and one --key on every target. These differed before (./data
// natively, ./seedkernel-data on Node), so the same command line ran two different nodes
// over two different stores.
{
  const host = fakeHost(["--key", join(work, "d.key")]);
  await runCli(host);
  ok(host.stood.dir === DEFAULT_DIR, `--dir defaults to ${DEFAULT_DIR}`);
  ok(DEFAULT_KEY === "./seedkernel.key", "--key defaults to ./seedkernel.key");
  ok(host.stood.policyJson === undefined, "an absent --policy is deny-all, not a policy");
  ok(host.lines.includes("  policy (none — installs disabled)"), "and the console says so");
}

// The §12.3 guest bounds reach the shell. A bound the shell accepts but no target can
// set is a bound nobody has — which is what these were on the native target until the
// flow became shared.
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

// --contact-secret names a FILE of hex, on every target. Passing the secret itself on the
// command line would put it in `ps` output and shell history.
{
  const secretPath = join(work, "contact.hex");
  writeFileSync(secretPath, good);
  const host = fakeHost(["--key", join(work, "c.key"), "--contact-secret", secretPath]);
  await runCli(host);
  ok(toHex(host.stood.contactSecret) === good, "--contact-secret is read from the file it names");
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
// --peers with no transport bundle admitted says what is wrong, rather than throwing a
// TypeError off the null the shell hands back.
{
  const host = fakeHost(["--key", join(work, "p.key"), "--peers", `${good}@127.0.0.1:7000`],
    { shell: { transport: null } });
  let msg = "";
  try { await runCli(host); } catch (e) { msg = String(e.message); }
  ok(msg.includes("the transport bundle is not loaded"), "--peers without a transport explains itself");
}

console.log("\n— the load line —");
// One format on every target, so the line an operator reads is the same line the native
// tests assert on (native/testhost_test.go drives this very function).
{
  const author = new Uint8Array(32).fill(0xab);
  const line = loadedLine({ author, manifest: { app: "chat", version: 3, protocols: ["chat-v1", "chat-v2"] } });
  ok(line === `chat v3  key ${toHex(author)}:chat  serves chat-v1, chat-v2`, "app, version, app key and protocols");
  const quiet = loadedLine({ author, manifest: { app: "tool", version: 1 } });
  ok(quiet.endsWith("serves (nothing — this bundle claims no protocol)"),
    "a bundle claiming no protocol says so at the load, not at the first frame");
}

summary("cli");
