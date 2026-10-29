// The installed slots and the three claim books that route to them (§12.10). The books
// are derived from the installed manifests. Every rule about what may be installed next
// to what lives here.
import { type LoadedBundle } from "./bundle.js";
import { isOccupiedService } from "./domains.js";
import { DEFAULT_MAX_APP_SLOTS } from "./wasm-limits.js";

/** What the table reads of a slot: the manifest its claims come from. */
export interface Slot {
  verifiedBundle: LoadedBundle;
}

/** The installed set and its books. The only writes are a whole install, a whole removal,
 *  or emptying it. */
export function createSlotTable<S extends Slot>(maxSlots = DEFAULT_MAX_APP_SLOTS) {
  const slots: S[] = [];
  /** Which book holds a name is its reach (§12.10): `peer` from `protocols`, `local` from
   *  `services`. Uniqueness is per book; a name in both is reachable either way. */
  const peer = new Map<string, S>();
  const local = new Map<string, S>();
  /** Occupied host services a manifest requires (currently `link`). Their events go to
   *  one place, so each has one holder. */
  const occupied = new Map<string, S>();
  const labelOf = (slot: S): string => slot.verifiedBundle.manifest.app;
  /** Each signed list paired with its book. Occupied services first, so a candidate
   *  transport is told which rule it broke. */
  const booksOf = (manifest: LoadedBundle["manifest"]): readonly (readonly [Map<string, S>, readonly string[], string])[] => [
    [occupied, manifest.guest.requires.filter(isOccupiedService), "requires"],
    [peer, manifest.protocols ?? [], "protocols"],
    [local, manifest.services ?? [], "services"],
  ];
  const release = (slot: S) => {
    for (const [book, names] of booksOf(slot.verifiedBundle.manifest)) {
      for (const claim of names) {
        if (book.get(claim) === slot) book.delete(claim);
      }
    }
  };
  const get = (app: string): S | undefined => slots.find((slot) => labelOf(slot) === app);
  return {
    /** A slot's `app` label (§12.4): its install key and fs/signing namespace. */
    labelOf,
    get,
    /** Every installed slot, in install order. */
    all: (): readonly S[] => slots,
    /** Who serves this claim, peer-reachable name first. */
    owner: (claim: string): S | undefined => peer.get(claim) ?? local.get(claim),
    peerClaimant: (claim: string): S | undefined => peer.get(claim),
    localClaimant: (serviceId: string): S | undefined => local.get(serviceId),
    /** The slot holding an occupied host service, e.g. the raw-link binding. */
    occupant: (service: string): S | undefined => occupied.get(service),
    /** Every claim this node serves as `[claim, owner label]`, peer-reachable first. */
    routes: (): [string, string][] =>
      [...peer, ...local].map(([claim, slot]): [string, string] => [claim, labelOf(slot)]),
    /** Refuse a candidate that contests a label or claim another slot holds, or that would
     *  exceed the slot cap (§12.10). Asked before candidate code runs and again at commit.
     *  A replacement may take its predecessor's label and claims, which must still be live.
     *  `selected` is the boot's transport selection: the one way to take a free occupied
     *  service. */
    refuseConflicts(loaded: LoadedBundle, replacement?: S, selected = false): void {
      if (replacement && !slots.includes(replacement))
        throw new Error("shell: replacement target changed while the candidate was loading");
      // One slot per label, whoever authored it; a standing label changes hands only
      // through an install that names it.
      const app = loaded.manifest.app;
      const installed = get(app);
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
    commit(slot: S, replacement?: S): void {
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
    remove(app: string): S | undefined {
      const slot = get(app);
      if (!slot) return undefined;
      slots.splice(slots.indexOf(slot), 1);
      release(slot);
      return slot;
    },
    /** Empty the table, handing back everything that was in it. */
    clear(): S[] {
      const gone = [...slots];
      slots.length = 0;
      peer.clear();
      local.clear();
      occupied.clear();
      return gone;
    },
  };
}
