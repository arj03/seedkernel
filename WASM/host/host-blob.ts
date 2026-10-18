// The host blob (§12.9): everything a loader runs, signed as one. A suite 0x02 envelope
// (bundle.ts) under `DOMAIN_host`, whose body is u32-length-prefixed parts:
//
//   manifest   JSON: {"version": n, "abi": n}
//   script     the host script (build/host.js), UTF-8
//   qjs        qjs.wasm, the engine guest realms run on (and, on native, the host realm)
//   sodium     libsodium.wasm, the host's crypto
//   mldsa      mldsa65.wasm, the host's ML-DSA-65 verifier
//
// A loader checks a blob before running any of it (abi.ts): both signatures, the author
// against the host it already runs, `abi` against its own, `version` against its floor.
// The native loader does the same in Go (native/hostblob.go), so both read this layout.

import { DOMAIN_HOST } from "../services/domains.js";
import { dec } from "../services/util.js";
import { bodyReader, isJsonObject, verifyEnvelope, type ManifestAuthorKeys, type ManifestVerifier } from "./bundle.js";

/** What a host blob declares about itself. */
export interface HostManifest {
  /** Monotonic per author: a loader runs none at or below its floor. */
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

export interface VerifiedHost extends HostParts {
  author: Uint8Array;
  authorKeys: ManifestAuthorKeys;
  manifest: HostManifest;
}

export const HOST_PART_NAMES = ["script", "qjs", "sodium", "mldsa"] as const;

/** Authenticate a host blob and split it. It says nothing about whether this loader should
 *  run it: the author, ABI and floor are the loader's to check. */
export function verifyHostBlob(crypto: ManifestVerifier, env: Uint8Array): VerifiedHost {
  const { author, authorKeys, body } = verifyEnvelope(crypto, env, DOMAIN_HOST, "host");
  const parts = bodyReader(body, "host");
  let manifest: unknown;
  try {
    manifest = JSON.parse(dec.decode(parts.next()));
  } catch {
    throw new Error("host: malformed manifest (not JSON)");
  }
  if (!isJsonObject(manifest) || !Number.isSafeInteger(manifest.version) || (manifest.version as number) < 1
    || !Number.isSafeInteger(manifest.abi) || (manifest.abi as number) < 1) {
    throw new Error("host: the manifest needs a positive integer version and abi");
  }
  const out = {} as HostParts;
  for (const name of HOST_PART_NAMES) out[name] = new Uint8Array(parts.next());
  if (!parts.done()) throw new Error("host: trailing bytes in body");
  return { author, authorKeys, manifest: { version: manifest.version as number, abi: manifest.abi as number }, ...out };
}
