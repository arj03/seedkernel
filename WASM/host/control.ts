// The control endpoint (§12.8): a serving node takes `--op` calls from its local operator,
// so a tool reaches the running node's app instead of booting a second node over its
// directory. It is a local socket beside the data directory, owner-only, and nothing
// listens on the network: being this user is the authority it asks for.
//
//   node      [0] on connect, before the caller sends anything
//   request   [len u32][appLen u8][app][op frame]   (len counts from appLen)
//   answer    [status u8][len u32][bytes]   status 0: the app's answer; 1: an error, as text
//
// One request per connection.
import { errMessage, enc, dec, readU32BE, writeU32BE, u8 } from "./util.js";
import type { LocalChannels, RawLink } from "../services/socket-seam.js";
import type { AppHandle } from "./shell-core.js";

/** The largest request: a whole-file op argument, held whole in memory (briefly twice, as
 *  its slices are joined). */
export const CONTROL_MAX_BYTES = 1 << 30;
const STATUS_OK = 0, STATUS_ERROR = 1;

/** Beside the data directory, as the freshness store is. */
export function controlPathFor(dir: string): string {
  return dir.replace(/[/\\]+$/, "") + ".control";
}

/** Bytes from a stream link, read as they are needed. */
function reader(link: RawLink) {
  const chunks: Uint8Array[] = [];
  let have = 0, want = 0, closed = false;
  let wake: (() => void) | null = null;
  link.onData((b) => {
    chunks.push(u8(b));
    have += b.length;
    if (have >= want) wake?.();
    link.setReadable?.(true);
  });
  link.onClose(() => { closed = true; wake?.(); });
  return {
    /** The next n bytes, or null if the link closed first. */
    async take(n: number): Promise<Uint8Array | null> {
      while (have < n && !closed) {
        want = n;
        await new Promise<void>((r) => { wake = r; });
        wake = null;
      }
      if (have < n) return null;
      const out = new Uint8Array(n);
      for (let at = 0; at < n;) {
        const c = chunks[0], k = Math.min(c.length, n - at);
        out.set(c.subarray(0, k), at);
        at += k;
        if (k === c.length) chunks.shift(); else chunks[0] = c.subarray(k);
      }
      have -= n;
      return out;
    },
  };
}

function frame(status: number, bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(5 + bytes.length);
  out[0] = status;
  writeU32BE(out, 1, bytes.length);
  out.set(bytes, 5);
  return out;
}

export interface ControlOptions {
  dir: string;
  local: LocalChannels;
  /** The app a request names, or the node's only app when it names none. */
  app(name: string): AppHandle | undefined;
}

/** Listen for control requests beside `dir`. Answers the socket's path. */
export async function serveControl(o: ControlOptions): Promise<string> {
  const path = controlPathFor(o.dir);
  await o.local.listenLocal(path, (link) => { void answer(link).catch(() => link.close(false)); });
  return path;

  async function answer(link: RawLink): Promise<void> {
    const r = reader(link);
    link.send(Uint8Array.of(0));
    const head = await r.take(4);
    const len = head ? readU32BE(head, 0) : 0;
    if (len < 1 || len > CONTROL_MAX_BYTES) return link.close(false);
    const body = await r.take(len);
    if (!body || 1 + body[0] > body.length) return link.close(false);
    const name = dec.decode(body.subarray(1, 1 + body[0]));
    let out: Uint8Array;
    try {
      const app = o.app(name);
      if (!app) throw new Error(name ? `no app ${name} on this node` : "name the app: this node has none or several");
      out = frame(STATUS_OK, await app.invoke(body.subarray(1 + body[0])));
    } catch (e) {
      out = frame(STATUS_ERROR, enc.encode(errMessage(e)));
    }
    link.send(out);
    link.close(true);
  }
}

/** A link to the node serving `dir` once that node has spoken, or null when none does.
 *  Nothing goes out before: a socket nobody serves never speaks. */
async function reach(o: Pick<ControlOptions, "dir" | "local">) {
  const link = o.local.connectLocal(controlPathFor(o.dir));
  const r = reader(link);
  const hello = await r.take(1);
  if (hello && hello[0] === 0) return { link, r };
  link.close(false);
  return null;
}

/** Whether a node serves `dir`, asked without sending it anything. */
export async function controlServes(o: Pick<ControlOptions, "dir" | "local">): Promise<boolean> {
  const node = await reach(o);
  node?.link.close(false);
  return node !== null;
}

/** One op to the node serving `dir`: its answer, or null when no node serves there.
 *  Throws when the app failed the call or the node dropped it. */
export async function controlInvoke(
  o: Pick<ControlOptions, "dir" | "local">, app: string, opFrame: Uint8Array,
): Promise<Uint8Array | null> {
  const name = enc.encode(app);
  if (name.length > 255) throw new Error("control: app name too long");
  if (1 + name.length + opFrame.length > CONTROL_MAX_BYTES) throw new Error("control: argument too large");
  const node = await reach(o);
  if (!node) return null;
  const { link, r } = node;
  const head = new Uint8Array(5 + name.length);
  writeU32BE(head, 0, 1 + name.length + opFrame.length);
  head[4] = name.length;
  head.set(name, 5);
  link.send(head);
  link.send(opFrame);
  const status = await r.take(5);
  const body = status && await r.take(readU32BE(status, 1));
  link.close(false);
  if (!status || !body) throw new Error("control: the node closed the call before answering");
  if (status[0] !== STATUS_OK) throw new Error(dec.decode(body));
  return body;
}
