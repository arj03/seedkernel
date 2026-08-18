// net-rtc.test.mjs — RtcNetwork's speculative-entry cap (§12.6.1).
//
// The relay can force a node to allocate peer entries by naming arbitrary `from` values
// in hellos AND in SDP offers, and every entry carries an RTCPeerConnection (ICE agents,
// sockets) — so every path that CREATES an entry must answer to the same
// MAX_UNAUTHED_PEERS bound. Pinned with a stub connection factory and a stub driver:
// net-rtc is browser-native, but its browser globals are referenced only inside methods,
// so it runs under Node.
//
// Run: node tests/net-rtc.test.mjs   (after `npm run build`)

import { fileURLToPath, pathToFileURL } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const imp = (p) => import(pathToFileURL(join(root, p)).href);
const { RtcNetwork } = await imp("build/host/net-rtc.js");
import { testkit } from "./testkit.mjs";

const { test, assert, summary } = testkit();

// The cap the transport relay is bound to (net-rtc.ts). A peer with an entry
// already — pre- or post-auth — is never counted against it, so a genuine fleet
// is unconstrained; only NEW speculative entries are.
const MAX_UNAUTHED_PEERS = 256;
const peerId = (n) => String(n).padStart(64, "0");

console.log("\nRtcNetwork speculative-entry cap (§12.6.1)\n");

await test("offers cannot force more than MAX_UNAUTHED_PEERS peer entries", async () => {
  // The old cap applied to the broadcast-hello path only: an offer from an
  // arbitrary `from` created an entry (and an RTCPeerConnection) unconditionally.
  const signaling = { send() {}, onMessage() {}, close() {} };
  const pcs = { n: 0 };
  const driver = {
    peerId: peerId(0),
    setPeerHooks() {},
    openLink() { return { linkId: 1, send() {}, close() {} }; },
  };
  const net = new RtcNetwork({
    driver,
    signaling,
    peerConnectionFactory: () => {
      pcs.n++;
      return {
        signalingState: "stable",
        remoteDescription: null,
        addEventListener() {},
        createDataChannel() { return { binaryType: "arraybuffer", send() {}, close() {}, addEventListener() {} }; },
        async setRemoteDescription() {},
        async setLocalDescription() {},
        async addIceCandidate() {},
        close() {},
      };
    },
  });

  // A flood of offers naming distinct strangers: the 256th entry may be created,
  // the rest must be dropped without allocating a connection.
  const offer = (from) => ({ type: "sdp", from, sdp: { type: "offer", sdp: "x" } });
  for (let i = 1; i <= 300; i++) await net.onSignal(offer(peerId(i)));
  assert(net.peers.size === MAX_UNAUTHED_PEERS,
    `offers must cap peer entries at ${MAX_UNAUTHED_PEERS}, got ${net.peers.size}`);
  assert(pcs.n === MAX_UNAUTHED_PEERS,
    `the connection factory must be reached exactly as many times, got ${pcs.n}`);

  // An entry that already exists is still served — the cap is on creation.
  await net.onSignal(offer(peerId(1)));
  assert(net.peers.size === MAX_UNAUTHED_PEERS, "a repeat offer must not create a second entry");
  assert(pcs.n === MAX_UNAUTHED_PEERS, "a repeat offer must not open a second connection");

  // The hello path answers to the same cap — including DIRECTED hellos, which name
  // us too and could spam a slot just as well as broadcast ones.
  for (let i = 301; i <= 350; i++) {
    await net.onSignal({ type: "hello", from: peerId(i), to: driver.peerId });
  }
  assert(net.peers.size === MAX_UNAUTHED_PEERS, `hellos must not exceed the same cap (got ${net.peers.size})`);
  assert(pcs.n === MAX_UNAUTHED_PEERS, "and no further connections may have been opened");

  net.close();
});

summary("net-rtc speculative-entry cap");
