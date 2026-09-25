// What this node holds (§12.10): the installed slots and the three claim books that route
// into them. The books are projections of the installed manifests, and every rule about
// what may be installed beside what lives here.
import { type LoadedBundle, type PureModules } from "./bundle.js";
import { isOccupiedService } from "../services/domains.js";
import { DEFAULT_MAX_APP_SLOTS } from "./wasm-limits.js";
import type { Fs } from "../services/fs.js";
import type { SignScope } from "./guest-seam.js";
import type { Realm } from "./realm-queue.js";
import type { RealmTimers } from "./realm-timers.js";

/** Observe a slot's own answer to a peer-inbound frame, after it resolves. */
export type InboundObserver = (claim: string, from: Uint8Array, answer: Uint8Array) => void;

/** One installed app. `realm` is null only while its install is standing it; a slot
 *  enters the table with its realm standing. */
export interface AppSlot {
  verifiedBundle: LoadedBundle;
  pureModules: PureModules;
  fsScope?: Fs;
  /** The fs prefix this slot's view is scoped under (`appScopeFor`). */
  appScope: string;
  /** The one scope `node/sign`/`node/verify` are wired to (`slotSignScope`). */
  signingScope: SignScope;
  realm: Realm | null;
  /** Set once the freshness mark and claims have committed; until then the seam refuses
   *  every call (`seamFor`). */
  active: boolean;
  /** Per slot: a timer is a pending re-entry into this realm, so disposal cancels exactly
   *  its own. */
  timers: RealmTimers;
  /** This install's answer observer; a replacement carries its own or none. */
  onInbound?: InboundObserver;
}

/** The installed set and its books. The only writes are a whole install, a whole removal,
 *  or emptying it. */
export function createSlotTable(maxSlots = DEFAULT_MAX_APP_SLOTS) {
  const slots: AppSlot[] = [];
  /** Which book holds a name is its reach (§12.10): `peer` from `protocols`, `local` from
   *  `services`. Uniqueness is per book; a name in both is reachable either way. */
  const peer = new Map<string, AppSlot>();
  const local = new Map<string, AppSlot>();
  /** Occupied host services a manifest requires (today `link`): their events have one
   *  sink, so one holder per name. */
  const occupied = new Map<string, AppSlot>();
  const labelOf = (slot: AppSlot): string => slot.verifiedBundle.manifest.app;
  /** Each signed list paired with its book. Occupied services first, so a would-be
   *  transport is told the rule it broke. */
  const booksOf = (manifest: LoadedBundle["manifest"]): readonly (readonly [Map<string, AppSlot>, readonly string[], string])[] => [
    [occupied, manifest.guest.requires.filter(isOccupiedService), "requires"],
    [peer, manifest.protocols ?? [], "protocols"],
    [local, manifest.services ?? [], "services"],
  ];
  const release = (slot: AppSlot) => {
    for (const [book, names] of booksOf(slot.verifiedBundle.manifest)) {
      for (const claim of names) {
        if (book.get(claim) === slot) book.delete(claim);
      }
    }
  };
  return {
    /** A slot's `app` label (§12.4): its install key and fs/signing namespace. */
    labelOf,
    get: (app: string): AppSlot | undefined => slots.find((slot) => labelOf(slot) === app),
    /** Every installed slot, in install order. */
    all: (): readonly AppSlot[] => slots,
    /** Who serves this claim, peer-reachable name first. */
    owner: (claim: string): AppSlot | undefined => peer.get(claim) ?? local.get(claim),
    peerClaimant: (claim: string): AppSlot | undefined => peer.get(claim),
    localClaimant: (serviceId: string): AppSlot | undefined => local.get(serviceId),
    /** The slot holding an occupied host service, e.g. the raw-link binding. */
    occupant: (service: string): AppSlot | undefined => occupied.get(service),
    /** Every claim this node serves as `[claim, owner label]`, peer-reachable first. */
    routes: (): [string, string][] =>
      [...peer, ...local].map(([claim, slot]): [string, string] => [claim, labelOf(slot)]),
    /** Refuse a candidate that contests a label or claim another slot holds, or that would
     *  exceed the slot cap (§12.10). Asked before candidate code runs and again at commit.
     *  A replacement may take its predecessor's label and claims, which must still be live.
     *  `selected` is the boot's transport selection: the one way to take a free occupied
     *  service. */
    refuseConflicts(loaded: LoadedBundle, replacement?: AppSlot, selected = false): void {
      if (replacement && !slots.includes(replacement))
        throw new Error("shell: replacement target changed while the candidate was loading");
      // One slot per label, whoever authored it; a standing label changes hands only
      // through an install that names it.
      const app = loaded.manifest.app;
      const installed = slots.find((slot) => labelOf(slot) === app);
      if (installed && installed !== replacement)
        throw new Error(`shell: '${app}' is already installed — install with { replaces: '${app}' } to take over its slot`);
      for (const [book, names, audience] of booksOf(loaded.manifest)) {
        for (const claim of names) {
          const claimant = book.get(claim);
          if (claimant && claimant !== replacement)
            throw new Error(`shell: ${audience} claim '${claim}' is already held by '${labelOf(claimant)}' — install with { replaces: '${labelOf(claimant)}' } to take it over`);
          // An occupied service carries authority no app policy grants (§12.5).
          if (!claimant && book === occupied && !selected)
            throw new Error(`shell: "${claim}" is taken only by the boot's transport selection, or by an install replacing its current holder`);
        }
      }
      // Every per-realm ceiling is multiplied by the realm count (§12.3), so it is capped.
      if (!replacement && slots.length >= maxSlots)
        throw new Error(`shell: this node already holds its ${maxSlots} app slots — uninstall one before installing another`);
    },
    /** Install `slot` with every claim its manifest names, in the replaced slot's place if
     *  there is one. The caller tears the replaced slot down. */
    commit(slot: AppSlot, replacement?: AppSlot): void {
      if (replacement) {
        release(replacement);
        slots[slots.indexOf(replacement)] = slot;
      }
      else slots.push(slot);
      for (const [book, names] of booksOf(slot.verifiedBundle.manifest)) {
        for (const claim of names) book.set(claim, slot);
      }
    },
    /** Drop the slot holding this label and release its claims. */
    remove(app: string): AppSlot | undefined {
      const at = slots.findIndex((slot) => labelOf(slot) === app);
      if (at < 0) return undefined;
      const [slot] = slots.splice(at, 1);
      release(slot);
      return slot;
    },
    /** Empty the table, handing back everything that was in it. */
    clear(): AppSlot[] {
      const gone = [...slots];
      slots.length = 0;
      peer.clear();
      local.clear();
      occupied.clear();
      return gone;
    },
  };
}
