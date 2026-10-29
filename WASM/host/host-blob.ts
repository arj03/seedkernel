// The host blob (§12.9): everything a loader runs, signed as one. A suite 0x02 envelope
// (bundle.ts) under `DOMAIN_host`, whose body is u32-length-prefixed parts:
//
//   manifest   JSON: {"version": n, "abi": n}
//   script     the host script (build/host.js), UTF-8
//   qjs        qjs.wasm, the engine guest realms run on (and, on native, the host realm)
//   sodium     libsodium.wasm, the host's crypto
//   mldsa      mldsa65.wasm, the host's ML-DSA-65 verifier
//
// The running host checks a blob before it hands it to the loader (`checkStagedHost`), with
// its own crypto, as it checks an app bundle. A loader holds no crypto: it reads the layout
// (`readHostBlob`) of what is in its slots, which only a host put there. The native loader
// reads the same layout in Go (native/hostblob.go).

import { DOMAIN_HOST } from "./domains.js";
import { dec, isRecord, toHex } from "./util.js";
import { bodyReader, envelopeBody, verifyEnvelope, type ManifestVerifier } from "./bundle.js";

/** What a host blob declares about itself. */
export interface HostManifest {
  /** Monotonic per author: a host stages none at or below its own. */
  version: number;
  /** The platform ABI the script needs (abi.ts `PLATFORM_ABI`). */
  abi: number;
}

/** The parts of a host blob, in body order after the manifest. */
export interface HostParts {
  script: Uint8Array;
  qjs: Uint8Array;
  sodium: Uint8Array;
  mldsa: Uint8Array;
}

export interface HostBlob extends HostParts {
  manifest: HostManifest;
}

export const HOST_PART_NAMES = ["script", "qjs", "sodium", "mldsa"] as const;

/** Split a host blob without authenticating it. The parts alias `env`. */
export function readHostBlob(env: Uint8Array): HostBlob {
  return parseBody(envelopeBody(env, "host"));
}

function parseBody(body: Uint8Array): HostBlob {
  const parts = bodyReader(body, "host");
  let manifest: unknown;
  try {
    manifest = JSON.parse(dec.decode(parts.next()));
  } catch {
    throw new Error("host: malformed manifest (not JSON)");
  }
  if (!isRecord(manifest) || !Number.isSafeInteger(manifest.version) || (manifest.version as number) < 1
    || !Number.isSafeInteger(manifest.abi) || (manifest.abi as number) < 1) {
    throw new Error("host: the manifest needs a positive integer version and abi");
  }
  const out = { manifest: { version: manifest.version as number, abi: manifest.abi as number } } as HostBlob;
  for (const name of HOST_PART_NAMES) out[name] = parts.next();
  if (!parts.done()) throw new Error("host: trailing bytes in body");
  return out;
}

/** Authenticate a host blob and split it; the parts alias `env`. */
export function verifyHostBlob(crypto: ManifestVerifier, env: Uint8Array): HostBlob & { author: Uint8Array } {
  const { author, body } = verifyEnvelope(crypto, env, DOMAIN_HOST, "host");
  return { author, ...parseBody(body) };
}

/** Whether the running host (`running`, its own blob) may stage `env` as its successor:
 *  signed by the same author, for this loader's ABI, and newer than itself. A loader boots
 *  nothing at or below its committed host, which is never newer than the running one. */
export function checkStagedHost(crypto: ManifestVerifier, running: Uint8Array, abi: number, env: Uint8Array): void {
  const self = verifyHostBlob(crypto, running);
  const h = verifyHostBlob(crypto, env);
  if (toHex(h.author) !== toHex(self.author)) {
    throw new Error(`host: signed by ${toHex(h.author)}, not the running host's author`);
  }
  if (h.manifest.abi !== abi) {
    throw new Error(`host: the blob needs platform ABI ${h.manifest.abi}, this loader implements ${abi}`);
  }
  if (h.manifest.version <= self.manifest.version) {
    throw new Error(`host: v${h.manifest.version} is not above v${self.manifest.version}`);
  }
}
