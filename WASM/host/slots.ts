// The loader's decisions (§12.9): the host's arguments, which host blob each boot runs, and
// the trial that commits a staged one or drops it. One implementation for both loaders: the
// Node loader imports it, into the realm it runs the host in, and the native binary runs it
// as build/loader.js in a QuickJS realm of its own, never the host's, so there a broken host
// cannot break its own rollback. Each loader keeps only the booting and the clock. It only
// ever comes from what the loader was built with, never from a staged blob.
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
import { u8 } from "../services/util.js";

/** Whole files, answered in the call: a loader's own. */
export interface SlotFiles {
  mkdir(dir: string): void;
  /** `null` only when absent; one larger than `maxBytes`, or unreadable, throws. */
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
function dataDirOf(args: string[]): string {
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--dir" && i + 1 < args.length) return args[i + 1];
    if (args[i].startsWith("--dir=")) return args[i].slice("--dir=".length);
  }
  return "./data";
}

/** No host blob is larger than this. */
const MAX_BLOB_BYTES = 64 << 20;

interface Slot { env: Uint8Array; version: number }

export class Loader {
  /** What the host sees: the command line less the loader's flags, and less `--op` once a
   *  host has run (`ended`). */
  hostArgs: string[];
  /** How long a pending host serves before it is committed. */
  readonly windowMs: number;
  /** `--host`'s blob, which every boot runs instead of the slots' choice. */
  private readonly fixed: Uint8Array | null = null;
  private readonly mode: string;
  private readonly dir: string;
  private readonly genesis: Slot;
  /** The pending host on trial, which its health window commits. */
  private trial: Slot | null = null;
  /** Set once the booted host's operator flow has ended with the node serving. */
  private serving = false;
  /** A host staged under "now" while the operator flow ran, booted once it ends. */
  private bootAfterFlow = false;
  /** Counts boots, so a health timer from an earlier boot commits nothing. */
  private gen = 0;

  /** `healthMs` is SEEDKERNEL_HOST_HEALTH_MS, which shortens the window for tests; `after`
   *  is the loader's clock, which runs the window. */
  constructor(private readonly files: SlotFiles, argv: string[], genesis: Uint8Array, healthMs: string | undefined,
    private readonly log: (line: string) => void, private readonly after: (ms: number, fn: () => void) => void) {
    const flags = loaderFlags(argv);
    this.hostArgs = flags.rest;
    this.mode = flags.updates;
    if (!["off", "next", "now"].includes(this.mode)) throw new Error(`--host-updates must be off, next or now (got "${this.mode}")`);
    this.windowMs = healthMs ? Number(healthMs) : 30_000;
    if (!(this.windowMs >= 0)) throw new Error(`SEEDKERNEL_HOST_HEALTH_MS: not a number of ms (got "${healthMs}")`);
    if (flags.hostFile !== undefined) {
      const raw = files.read(flags.hostFile, MAX_BLOB_BYTES);
      if (raw === null) throw new Error(`--host: cannot read ${flags.hostFile}`);
      this.fixed = u8(raw);
      // Read here, so a file that is no host blob fails alike on every loader.
      if (readHostBlob(this.fixed).manifest.abi !== PLATFORM_ABI) throw new Error(`--host: ${flags.hostFile} is not for platform ABI ${PLATFORM_ABI}`);
      // Its slots are never consulted, so there is nowhere to stage a successor.
      this.mode = "off";
    }
    this.dir = dataDirOf(this.hostArgs).replace(/[/\\]+$/, "") + ".host";
    this.genesis = { env: genesis, version: readHostBlob(genesis).manifest.version };
  }

  private path(name: string) { return `${this.dir}/${name}`; }

  /** A slot's blob, or null when it is absent or not for this loader's ABI. A committed
   *  host that is there but broken throws: it is the floor, which genesis may be below. */
  private load(name: string): Slot | null {
    try {
      const raw = this.files.read(this.path(name), MAX_BLOB_BYTES);
      if (raw === null) return null;
      const env = u8(raw);
      const { manifest } = readHostBlob(env);
      if (manifest.abi === PLATFORM_ABI) return { env, version: manifest.version };
      this.log(`ignored ${name}: it needs platform ABI ${manifest.abi}, this loader implements ${PLATFORM_ABI}`);
    } catch (err) {
      const why = err instanceof Error ? err.message : String(err);
      if (name === "committed.skb") throw new Error(`${name}: ${why}; restore it, or remove it to boot v${this.genesis.version}`);
      this.log(`ignored ${name}: ${why}`);
    }
    return null;
  }

  /** The committed host when it is newer than the genesis blob, which a newer loader can be. */
  private base(): Slot {
    const c = this.load("committed.skb");
    return c && c.version > this.genesis.version ? c : this.genesis;
  }

  private discard(reason: string) {
    this.files.remove(this.path("pending.skb"));
    this.files.remove(this.path("tried"));
    this.trial = null;
    this.log(`discarded the pending host: ${reason}`);
  }

  /** The blob the next boot runs. A pending blob is tried once: the mark is written before
   *  it boots, so finding the mark means it never got as far as committing. */
  choose(): Uint8Array {
    this.serving = false;
    if (this.fixed) return this.fixed;
    this.gen++;
    this.trial = null;
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
    this.trial = p;
    this.log(`trying v${p.version} (committed is v${base.version})`);
    return p.env;
  }

  /** Whether a failure is a pending host's, which is then dropped: the caller boots the
   *  committed host instead of giving up. */
  failed(reason: string): boolean {
    if (!this.trial) return false;
    this.discard(reason);
    return true;
  }

  /** How the booted host's operator flow ended. A host booted after it, in the same
   *  process, does not repeat its one-shot `--op`. A pending host that serves is committed
   *  once it has served for the window. One that only ran an op and exited proved nothing
   *  either way, so it is left pending, untried, for the next start. Answers whether to boot
   *  again at once, for a host staged under "now" while the flow ran. */
  ended(serving: boolean): boolean {
    this.hostArgs = withoutOp(this.hostArgs);
    const again = serving && this.bootAfterFlow;
    this.bootAfterFlow = false;
    this.serving = serving && !again;
    if (this.trial && !serving) {
      this.files.remove(this.path("tried"));
      this.trial = null;
    } else if (this.trial && !again) {
      const gen = this.gen;
      this.after(this.windowMs, () => this.commit(gen));
    }
    return again;
  }

  /** Make the host on trial the committed one, which raises the floor to it. One it staged
   *  meanwhile stays pending, for a trial of its own. A crash between the write and the
   *  removal leaves pending at the floor, which the next start drops. */
  private commit(gen: number): void {
    const trial = this.trial;
    if (!trial || this.gen !== gen) return;
    try {
      this.files.write(this.path("committed.skb"), trial.env);
    } catch (err) {
      this.log(`cannot commit the pending host: ${err instanceof Error ? err.message : String(err)}`);
      return;
    }
    if (this.load("pending.skb")?.version === trial.version) {
      this.files.remove(this.path("pending.skb"));
      this.files.remove(this.path("tried"));
    }
    this.trial = null;
    this.log(`committed after ${this.windowMs}ms`);
  }

  /** Keep a blob the running host checked as pending. Answers whether to boot it now, which
   *  is under "now" while the node serves; one staged while the operator flow runs boots
   *  once the flow ends (`ended`). */
  stage(env: Uint8Array): boolean {
    if (this.mode === "off") throw new Error("host: updates are off on this node (--host-updates next|now)");
    const { manifest } = readHostBlob(env);
    this.files.mkdir(this.dir);
    this.files.write(this.path("pending.skb"), env);
    this.files.remove(this.path("tried"));
    this.log(`staged v${manifest.version}`);
    if (this.mode !== "now") return false;
    if (!this.serving) this.bootAfterFlow = true;
    return this.serving;
  }
}
