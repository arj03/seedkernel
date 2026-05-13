// Verifies the patched browser libsodium under Node by serving browser/
// over HTTP and using a real fetch() against it — same code path a browser
// would take, just driven from Node. Smoke-tests the 4 sodium functions
// the browser benchmark uses.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { resolve, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const browserDir = resolve(here, "../browser");

const mime = { ".mjs": "text/javascript", ".js": "text/javascript", ".wasm": "application/wasm" };
const srv = createServer(async (req, res) => {
  const path = req.url === "/" ? "/index.html" : req.url.split("?")[0];
  try {
    const buf = await readFile(resolve(browserDir, "." + path));
    const ext = path.slice(path.lastIndexOf("."));
    res.setHeader("Content-Type", mime[ext] ?? "application/octet-stream");
    res.end(buf);
  } catch { res.statusCode = 404; res.end(); }
});
await new Promise(r => srv.listen(0, "127.0.0.1", r));
const port = srv.address().port;
const base = `http://127.0.0.1:${port}/`;

// Import the wrapper as if from the served URL — but Node ESM can't import
// http:// URLs without --experimental-network-imports. So we fetch the source
// instead and import via data: URL, after rewriting the relative wasm URL to
// the absolute http:// origin.
const src = await readFile(resolve(browserDir, "libsodium-wrappers.mjs"), "utf8");
const coreSrc = await readFile(resolve(browserDir, "libsodium-core.mjs"), "utf8");

// Rewrite the relative core import to the absolute HTTP origin too.
const wrapperRewritten = src
  .replace('"./libsodium-core.mjs"', JSON.stringify(base + "libsodium-core.mjs"))
  .replace('./libsodium.wasm', base + "libsodium.wasm");

// Serve the rewritten wrapper and the core under fixed names so the import
// graph can resolve.
const overrides = new Map([
  ["/wrap.mjs", { body: wrapperRewritten, type: "text/javascript" }],
  ["/libsodium-core.mjs", { body: coreSrc, type: "text/javascript" }],
]);
srv.removeAllListeners("request");
srv.on("request", async (req, res) => {
  const path = req.url.split("?")[0];
  if (overrides.has(path)) {
    const o = overrides.get(path);
    res.setHeader("Content-Type", o.type);
    res.end(o.body);
    return;
  }
  try {
    const buf = await readFile(resolve(browserDir, "." + path));
    const ext = path.slice(path.lastIndexOf("."));
    res.setHeader("Content-Type", mime[ext] ?? "application/octet-stream");
    res.end(buf);
  } catch { res.statusCode = 404; res.end(); }
});

const sodium = (await import(base + "wrap.mjs")).default;
await sodium.ready;

const { publicKey, privateKey } = sodium.crypto_sign_keypair();
const msg = new TextEncoder().encode("hello kernel.wasm");
const sig = sodium.crypto_sign_detached(msg, privateKey);
const ok = sodium.crypto_sign_verify_detached(sig, msg, publicKey);
const h = sodium.crypto_hash_sha3256(msg);

srv.close();
if (!ok) { console.error("verify failed"); process.exit(1); }
if (h.length !== 32) { console.error("hash length wrong"); process.exit(1); }
console.log("OK — signed, verified, hashed via http+fetch+instantiateStreaming");
