// The loader's host slots (§12.9): which host blob a node boots, and the trial that commits
// a staged one or drops it. One implementation for both loaders: the Node loader imports
// it, and the native binary runs it as build/loader.js in a QuickJS realm of its own. It
// never runs in the host's realm, so a broken host cannot break its own rollback, and it
// only ever comes from what the loader was built with, never from a staged blob.
//
//   - a floor, the committed host's version: nothing at or below it is booted;
//   - a staged blob is tried once: marked tried before it boots, so a crash is not retried;
//   - it is committed only after a health window it served through with no fatal error,
//     and anything that fails before that is discarded and the committed host booted again.
//
// The running host checked a staged blob's signatures, author, ABI and version before it
// handed it over (host-blob.ts `checkStagedHost`). The slots sit beside the data
// directory, as the freshness store does: <dir>.host/committed.skb, pending.skb, tried.

import { readHostBlob } from "./host-blob.js";
import { PLATFORM_ABI } from "./abi.js";

/** Whole files, answered in the call: a loader's own. */
export interface SlotFiles {
  mkdir(dir: string): void;
  /** `null` when absent or larger than `maxBytes`. */
  read(path: string, maxBytes: number): ArrayBuffer | Uint8Array | null;
  /** Atomic. */
  write(path: string, bytes: Uint8Array): void;
  remove(path: string): boolean;
  /** -1 when absent. */
  size(path: string): number;
}

/** The loader's own flags, out of what the host sees. */
export interface LoaderFlags {
  rest: string[];
  hostFile?: string;
  updates: string;
}

/** Take the loader's flags out of the command line, as `--name value` or `--name=value`:
 *  - `--host <file>` boots that blob instead of the slots' choice, by the operator's
 *    explicit choice, unchecked and from any author;
 *  - `--host-updates off|next|now` is whether a running host may stage a new one, and when
 *    it runs: refused (the default), at the next start, or at once. */
export function loaderFlags(argv: string[]): LoaderFlags {
  const out: LoaderFlags = { rest: [], updates: "off" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const eq = a.indexOf("=");
    const name = a.startsWith("--") ? a.slice(2, eq < 0 ? undefined : eq) : "";
    if (name !== "host" && name !== "host-updates") {
      out.rest.push(a);
      continue;
    }
    let value = eq < 0 ? undefined : a.slice(eq + 1);
    if (value === undefined) {
      if (i + 1 >= argv.length) throw new Error(`--${name} needs a value`);
      value = argv[++i];
    }
    if (name === "host") out.hostFile = value;
    else out.updates = value;
  }
  return out;
}

/** The arguments less `--op`: a host booted after an operator flow ran, in the same
 *  process, does not repeat its one-shot op. */
export function withoutOp(args: string[]): string[] {
  return args.filter((a, i) => a !== "--op" && !a.startsWith("--op=") && args[i - 1] !== "--op");
}

/** The host's --dir, which the slots sit beside, or the CLI's default (cli.ts DEFAULT_DIR). */
export function dataDirOf(args: string[]): string {
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--dir" && i + 1 < args.length) return args[i + 1];
    if (args[i].startsWith("--dir=")) return args[i].slice("--dir=".length);
  }
  return "./data";
}

/** No host blob is larger than this. */
const MAX_BLOB_BYTES = 64 << 20;

interface Slot { env: Uint8Array; version: number }

export class HostSlots {
  private readonly dir: string;
  private readonly genesis: number;
  /** How long a pending host serves before it is committed. */
  readonly windowMs: number;
  private trying = false;
  /** Counts boots, so a health timer from an earlier boot commits nothing. */
  private gen = 0;

  /** `healthMs` is SEEDKERNEL_HOST_HEALTH_MS, which shortens the window for tests. */
  constructor(private readonly files: SlotFiles, dataDir: string, private readonly mode: string,
    genesis: Uint8Array, healthMs: string | undefined, private readonly log: (line: string) => void) {
    if (!["off", "next", "now"].includes(mode)) throw new Error(`--host-updates must be off, next or now (got "${mode}")`);
    this.windowMs = healthMs ? Number(healthMs) : 30_000;
    if (!(this.windowMs >= 0)) throw new Error(`SEEDKERNEL_HOST_HEALTH_MS: not a number of ms (got "${healthMs}")`);
    this.dir = dataDir.replace(/[/\\]+$/, "") + ".host";
    this.genesis = readHostBlob(genesis).manifest.version;
  }

  private path(name: string) { return `${this.dir}/${name}`; }

  /** A slot's blob, or null when it is absent or not for this loader's ABI. */
  private load(name: string): Slot | null {
    const raw = this.files.read(this.path(name), MAX_BLOB_BYTES);
    if (raw === null) return null;
    const env = raw instanceof Uint8Array ? raw : new Uint8Array(raw);
    try {
      const { manifest } = readHostBlob(env);
      if (manifest.abi === PLATFORM_ABI) return { env, version: manifest.version };
      this.log(`ignored ${name}: it needs platform ABI ${manifest.abi}, this loader implements ${PLATFORM_ABI}`);
    } catch (err) {
      this.log(`ignored ${name}: ${err instanceof Error ? err.message : String(err)}`);
    }
    return null;
  }

  /** The committed host when it is newer than the genesis blob, which a newer loader can be;
   *  `env` null is the genesis blob. */
  private base(): { env: Uint8Array | null; version: number } {
    const c = this.load("committed.skb");
    return c && c.version > this.genesis ? c : { env: null, version: this.genesis };
  }

  private discard(reason: string) {
    this.files.remove(this.path("pending.skb"));
    this.files.remove(this.path("tried"));
    this.trying = false;
    this.log(`discarded the pending host: ${reason}`);
  }

  /** The blob the next boot runs, or null for the genesis blob. A pending blob is tried
   *  once: the mark is written before it boots, so finding the mark means it never got as
   *  far as committing. */
  choose(): Uint8Array | null {
    this.gen++;
    this.trying = false;
    const base = this.base();
    if (this.files.size(this.path("pending.skb")) < 0) return base.env;
    if (this.files.size(this.path("tried")) >= 0) {
      this.discard("it was tried and never committed");
      return base.env;
    }
    const p = this.load("pending.skb");
    if (!p || p.version <= base.version) {
      this.discard("it is not above the floor");
      return base.env;
    }
    try {
      this.files.write(this.path("tried"), new Uint8Array(0));
    } catch (err) {
      this.log(`cannot mark v${p.version} tried, so it is not run: ${err instanceof Error ? err.message : String(err)}`);
      return base.env;
    }
    this.trying = true;
    this.log(`trying v${p.version} (committed is v${base.version})`);
    return p.env;
  }

  /** Whether a failure is a pending host's, which is then dropped: the caller boots the
   *  committed host instead of giving up. */
  failed(reason: string): boolean {
    if (!this.trying) return false;
    this.discard(reason);
    return true;
  }

  /** How the booted host's operator flow ended. A pending host that serves is committed
   *  once it has served for the window: the answer is the boot to pass to `commit` then.
   *  One that only ran an op and exited proved nothing either way, so it is left pending,
   *  untried, for the next start. */
  started(serving: boolean): number | null {
    if (!this.trying) return null;
    if (!serving) {
      this.files.remove(this.path("tried"));
      this.trying = false;
      return null;
    }
    return this.gen;
  }

  /** Make the pending host the committed one, which raises the floor to it. A crash between
   *  the write and the removal leaves pending at the floor, which the next start drops. */
  commit(gen: number): void {
    if (!this.trying || this.gen !== gen) return;
    const p = this.files.read(this.path("pending.skb"), MAX_BLOB_BYTES);
    if (p === null) return;
    try {
      this.files.write(this.path("committed.skb"), p instanceof Uint8Array ? p : new Uint8Array(p));
    } catch (err) {
      this.log(`cannot commit the pending host: ${err instanceof Error ? err.message : String(err)}`);
      return;
    }
    this.files.remove(this.path("pending.skb"));
    this.files.remove(this.path("tried"));
    this.trying = false;
    this.log(`committed after ${this.windowMs}ms`);
  }

  /** Keep a blob the running host checked as pending; answers whether to boot it now. */
  stage(env: Uint8Array): boolean {
    if (this.mode === "off") throw new Error("host: updates are off on this node (--host-updates next|now)");
    const { manifest } = readHostBlob(env);
    this.files.mkdir(this.dir);
    this.files.write(this.path("pending.skb"), env);
    this.files.remove(this.path("tried"));
    this.log(`staged v${manifest.version}`);
    return this.mode === "now";
  }
}
