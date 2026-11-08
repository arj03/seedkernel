// Builds the signed transport bundle (§12.6): the guest parts, ws.wasm and
// mlkem768.wasm, signed under the hybrid suite (§12.4, §14.1). Writes build/transport.skb
// (gitignored), which the host blob carries as its `transport` part (host/host-blob.ts),
// and build/transport-web.skb, the same without quic.wasm, which the web host blob carries.
//
// The author key is `--key <seed>` or transport/author.key, generated on first build, so
// each clone has its own author (§12.5). Both halves of the hybrid key derive from it.

import { readFileSync, writeFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { readGuestSource } from "./guest-source.mjs";
import { TRANSPORT_APP_CONFIG } from "./transport-config.mjs";
import { authorBundle, buildAuthor, guestOpFraming } from "../build/scripts/bundle-author.js";
import { TRANSPORT_SERVICE } from "../build/host/host-blob.js";
import { toHex } from "../build/host/util.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");

async function main() {
  const { sodium, keys } = buildAuthor(root, "transport/author.key", process.argv.slice(2));

  const guest = readGuestSource(guestOpFraming());
  // RFC 6455 framing and the handshake KEM are bundle content.
  const wsWasm = readFileSync(join(root, "build", "ws.wasm"));
  const mlkemWasm = readFileSync(join(root, "browser", "mlkem768.wasm"));
  // The UDP paths' QUIC connection (transport/quic, scripts/build-quic.mjs).
  const quicWasm = readFileSync(join(root, "transport", "quic", "quic.wasm"));
  const sign = (modules) => authorBundle(sodium, keys, {
    app: "transport",
    version: 1,
    // Local only: a `services` claim, never a peer-reachable `protocols` one.
    services: [TRANSPORT_SERVICE],
    modules,
    guestSource: guest,
    // `link` goes only to the boot-selected transport or an explicit replacement (§12.5).
    guestRequires: ["node", "link", "timer"],
    // Signed defaults; an installation overrides any of them through LOCAL.
    guestConfig: TRANSPORT_APP_CONFIG,
  });
  const shared = [{ name: "ws", wasm: wsWasm }, { name: "mlkem", wasm: mlkemWasm }];
  const { blob, author } = sign([...shared, { name: "quic", wasm: quicWasm }]);
  // `author` is the key-set hash (bundle.ts `hybridAuthorId`), not the Ed25519 key.
  writeFileSync(join(root, "build", "transport.skb"), blob);
  console.log(`  transport bundle: build/transport.skb (${blob.length} B)`);
  // A page has no datagram sockets, so its UDP code never runs and needs no QUIC module.
  const web = sign(shared).blob;
  writeFileSync(join(root, "build", "transport-web.skb"), web);
  console.log(`  transport bundle: build/transport-web.skb (${web.length} B), no quic`);
  console.log(`  transport author: ${toHex(author)} (hybrid 0x02)`);
  console.log(`  ed25519 half:     ${toHex(keys.ed.publicKey)}`);
}

main().catch((e) => { console.error(e); process.exit(1); });
