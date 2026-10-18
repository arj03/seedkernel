// The host script's entry (§12.9): the host over a loader's globals (abi.ts), its
// dispatchers where the loader calls them, and the names the native tests drive.
import { platformHost } from "./platform.js";
import type { PlatformBridge, PlatformFs, PlatformNet, PlatformUdp } from "./abi.js";

declare const bridge: PlatformBridge;
declare const __fs: PlatformFs;
declare const __net: PlatformNet;
declare const __udp: PlatformUdp;

const host = platformHost({ bridge, fs: __fs, net: __net, udp: __udp });
Object.assign(globalThis, {
  __netDeliver: host.__netDeliver,
  __netClosed: host.__netClosed,
  __netAccept: host.__netAccept,
  __udpDeliver: host.__udpDeliver,
});

export const runMain = host.runMain;
export const standUp = host.standUp;
export const createRealm = host.createRealm;
export const sodium = host.sodium;
export const platformChannels = host.channels;
export const platformDatagrams = host.datagrams;
export const platformModules = host.modules;
