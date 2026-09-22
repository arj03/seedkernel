// What this node holds (§12.10): the installed slots and the three claim books that route
// into them. All three are projections of the installed manifests — nothing to persist or
// keep in step — and every rule about what may be installed beside what lives here, so no
// caller can set a claim past them.
import { type LoadedBundle, type PureModules } from "./bundle.js";
import { isOccupiedService } from "../core/domains.js";
import { DEFAULT_MAX_APP_SLOTS } from "../core/wasm-limits.js";
import type { Fs } from "../core/fs.js";
import type { SignScope } from "./guest-seam.js";
import type { Realm } from "./realm-queue.js";
import type { RealmTimers } from "./realm-timers.js";

/** Observe a slot's own answer to a PEER-inbound frame, after it resolves. */
export type InboundObserver = (claim: string, from: Uint8Array, answer: Uint8Array) => void;

/** A slot's realm. Nullable for exactly the window between the holder being made and the
 *  factory resolving, inside one `install` — a slot only enters the table with its
 *  realm standing, and teardown reads the settled handle synchronously, because the
 *  callers that dispose are deciding right then what the node holds. */
export interface AppSlot {
  verifiedBundle: LoadedBundle;
  pureModules: PureModules;
  fsScope?: Fs;
  /** The fs keyspace prefix this slot's view is scoped under (bundle.ts `appScopeFor`) —
   *  computed once per load and carried on the returned `AppHandle`, so a caller's cold
   *  read of the raw backend needs the derivation the shell already did. */
  appScope: string;
  /** THE one scope this slot's `node/sign`/`node/verify` are wired to (`slotSignScope`,
   *  guest-seam.ts): the slot's own `DOMAIN_guest ‖ app` when it is an ordinary app, its
   *  `DOMAIN_link_scope` when it reaches `link` — a fact of the slot, not a second name. */
  signingScope: SignScope;
  realm: Realm | null;
  /** Set once this slot's freshness mark and claims have committed; until then its seam
   *  refuses the calls disposing the slot could not take back (`seamFor`). */
  active: boolean;
  /** This realm's deadlines. Per SLOT rather than per shell, because a timer is a pending
   *  re-entry into one particular realm: the cap is then one guest's to spend, and
   *  disposing that realm cancels exactly its own (`disposeSlot`). */
  timers: RealmTimers;
  /** THIS load's answer observer, or absent. Carried on the slot rather than read from the
   *  load call's own options at call time, because a peer-inbound frame can land at any
   *  point after commit, long after that call returned. A replacement load's slot gets its
   *  own value or none — never the outgoing slot's. */
  onInbound?: InboundObserver;
}

/** The installed set and the three books that reach into it. Reads are the routing
 *  lookups; the only writes are a whole install, a whole removal, or emptying it. */
export function createSlotTable(maxSlots = DEFAULT_MAX_APP_SLOTS) {
  const slots: AppSlot[] = [];
  /** Two audiences, two books (§12.10): `peer` from every installed manifest's `protocols`,
   *  `local` from its `services`. Which book holds a name IS its reach, so an inbound frame
   *  is one lookup and nothing tests the manifest a second time. Materialized rather than
   *  scanned because each is read once per delivery. A name in both is a bundle saying
   *  "reachable either way", so uniqueness is enforced per book, never across them. */
  const peer = new Map<string, AppSlot>();
  const local = new Map<string, AppSlot>();
  /** The third book: the occupied host services a manifest requires (`isOccupiedService`,
   *  today `link`). Their events have one sink, so a second holder would silently take the
   *  node's sockets off the first — one owner per name, which is a claim's rule. */
  const occupied = new Map<string, AppSlot>();
  const labelOf = (slot: AppSlot): string => slot.verifiedBundle.manifest.app;
  /** Each signed list paired with the book it claims in, so every caller iterating a
   *  bundle's claims covers all three. Occupied services first, so a would-be transport
   *  claiming the holder's service id is told the rule it broke. */
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
    /** A slot's manifest `app` label (§12.4) — what it installs under, and the name of its
     *  fs and signing namespaces. */
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
    /** Refuse a candidate that contests the label or a claim another slot holds, or that
     *  would exceed the slot cap (§12.10). Asked before candidate code runs and again in the
     *  commit window, because another load may take a free claim while this candidate is
     *  being built. Per BOOK: the same name under `protocols` and `services` is two claims,
     *  not a contest. A replacement may take the selected predecessor's label and claims,
     *  and must still target that exact live slot at commit. `selected` is the boot's
     *  transport selection: the one way to take an occupied service nothing holds. */
    refuseConflicts(loaded: LoadedBundle, replacement?: AppSlot, selected = false): void {
      if (replacement && !slots.includes(replacement))
        throw new Error("shell: replacement target changed while the candidate was loading");
      // One slot per label, whoever authored it, and an install that names no predecessor
      // takes a FREE one: a label already here changes hands only through an install that
      // says so. So a second install of a running app is refused rather than silently
      // taking it over, and every rule below has exactly one incumbent to weigh — the
      // named predecessor.
      const app = loaded.manifest.app;
      const installed = slots.find((slot) => labelOf(slot) === app);
      if (installed && installed !== replacement)
        throw new Error(`shell: '${app}' is already installed — install with { replaces: '${app}' } to take over its slot`);
      for (const [book, names, audience] of booksOf(loaded.manifest)) {
        for (const claim of names) {
          const claimant = book.get(claim);
          if (claimant && claimant !== replacement)
            throw new Error(`shell: ${audience} claim '${claim}' is already held by '${labelOf(claimant)}' — install with { replaces: '${labelOf(claimant)}' } to take it over`);
          // An occupied service carries authority no app policy grants (§12.5), so a FREE
          // one is not free for the taking: only the boot's selection takes it, and after
          // that it changes hands only with its holder's slot.
          if (!claimant && book === occupied && !selected)
            throw new Error(`shell: "${claim}" is taken only by the boot's transport selection, or by an install replacing its current holder`);
        }
      }
      // Realms are the multiplicand every per-realm ceiling is multiplied by (§12.3), so an
      // install list nobody counts would leave each of those ceilings a floor rather than a
      // bound. A replacement takes the slot it already holds and is never refused here.
      if (!replacement && slots.length >= maxSlots)
        throw new Error(`shell: this node already holds its ${maxSlots} app slots — uninstall one before installing another`);
    },
    /** Install `slot` and hand it every claim its manifest names, taking the selected
     *  predecessor's place in the list when there is one. Nothing comes back: the only slot
     *  a commit can displace is the one the caller itself selected, so the caller already
     *  holds what it has to tear down. */
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
