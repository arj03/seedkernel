// The host script's entry (§12.9): where a loader meets the script, so the ABI version is
// checked here; the host over the loader's globals (abi.ts); the operator flow where the
// loader calls it; and the names the native tests drive.
import { platformHost } from "./platform.js";
import { runCli } from "./cli.js";
import { u8 } from "./util.js";
import {
  PLATFORM_ABI,
  type PlatformBridge, type PlatformDispatchers, type PlatformFs, type PlatformNet, type PlatformUdp,
} from "./abi.js";

declare const bridge: PlatformBridge;
declare const __fs: PlatformFs;
declare const __net: PlatformNet;
declare const __udp: PlatformUdp;

if (bridge.abi !== PLATFORM_ABI) {
  throw new Error(`host: this loader implements platform ABI ${bridge.abi}, the host needs ${PLATFORM_ABI}`);
}
const host = platformHost({ bridge, fs: __fs, net: __net, udp: __udp });

/** Run the operator flow, over this platform as cli.ts needs it; cli.ts makes every
 *  decision. The loader reads back whether to keep running. */
export const runMain: PlatformDispatchers["runMain"] = async () => {
  const { serving, close } = await runCli({
    read: (path, maxBytes) => __fs.read(path, maxBytes),
    write: (path, bytes, durable) => __fs.write(path, bytes, durable),
    banner: bridge.banner,
    argv: JSON.parse(bridge.argv()) as string[],
    log(line) { bridge.log(line); },
    stdout(bytes) { bridge.stdout(bytes); },
    stdin() { return u8(bridge.stdin()); },
    sodium: host.sodium,
    standUp: host.standUp,
    local: host.channels().local,
  });
  if (!serving) close();
  return serving;
};

export const standUp = host.standUp;
export const createRealm = host.createRealm;
export const sodium = host.sodium;
export const platformChannels = host.channels;
export const platformModules = host.modules;
