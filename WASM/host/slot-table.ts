// What this node holds (§12.10): the installed slots and the two claim books that route
// into them. Both books are projections of the installed manifests — nothing to persist or
// keep in step — and every rule about what may be installed beside what lives here, so no
// caller can set a claim past them.
import { appKeyFor, reachesLink, type LoadedBundle, type PureModules } from "./bundle.js";
import { DEFAULT_MAX_APP_SLOTS } from "../core/wasm-limits.js";
import type { Fs } from "../core/fs.js";
import type { SignScope } from "./guest-seam.js";
import type { Realm } from "./realm-queue.js";
import type { RealmTimers } from "./realm-timers.js";

/** Observe a slot's own answer to a PEER-inbound frame, after it resolves. */
export type InboundObserver = (claim: string, from: Uint8Array, answer: Uint8Array) => void;

/** A slot's realm. Nullable for exactly the window between the holder being made and the
 *  factory resolving, inside one `loadBundleBlob` — a slot only enters the table with its
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
   *  guest-seam.ts): the slot's own `DOMAIN_guest ‖ author ‖ app` when it is an ordinary
   *  app, its `DOMAIN_link_scope` when it reaches `link` — a fact of the
   *  slot, not a second name. */
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

/** The installed set and the two audiences that reach into it. Reads are the routing
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
  const keyOf = (slot: AppSlot): string => appKeyFor(slot.verifiedBundle.author, slot.verifiedBundle.manifest.app);
  /** Whether `slot` holds the raw-link binding. Exclusive, like a claim: the driver has ONE
   *  event sink, so two holders are not a composition — the second would take the node's
   *  sockets off the first, silently. A pure function of the signed manifest, so there is
   *  nothing here to store or keep in step — the search below IS the binding's holder. */
  const hasLink = (slot: AppSlot): boolean => reachesLink(slot.verifiedBundle.manifest);
  /** Each signed list paired with the book it claims in, so every caller iterating a
   *  bundle's claims covers both audiences. */
  const booksOf = (manifest: LoadedBundle["manifest"]): readonly (readonly [Map<string, AppSlot>, readonly string[], string])[] => [
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
    /** `<author hex>:<app>` (§12.4) — a slot's audit identity, and the key it installs under. */
    keyOf,
    hasLink,
    get: (key: string): AppSlot | undefined => slots.find((slot) => keyOf(slot) === key),
    /** Every installed slot, in install order. */
    all: (): readonly AppSlot[] => slots,
    /** Who serves this claim, peer-reachable name first. */
    owner: (claim: string): AppSlot | undefined => peer.get(claim) ?? local.get(claim),
    peerClaimant: (claim: string): AppSlot | undefined => peer.get(claim),
    localClaimant: (serviceId: string): AppSlot | undefined => local.get(serviceId),
    /** Every claim this node serves as `[claim, owner key]`, peer-reachable first. */
    routes: (): [string, string][] =>
      [...peer, ...local].map(([claim, slot]): [string, string] => [claim, keyOf(slot)]),
    /** Refuse a candidate that contests a claim or the raw-link binding another identity
     *  holds, or that would exceed the slot cap (§12.10). Asked before candidate code runs
     *  and again in the commit window, because another load may take a free claim while
     *  this candidate is being built. Per BOOK: the same name under `protocols` and
     *  `services` is two claims, not a contest. A replacement may take only the selected
     *  predecessor's claims and must still target that exact live slot at commit.
     *  `selected` is the boot's transport selection: the one way to take the raw-link
     *  binding when nothing holds it. */
    refuseConflicts(loaded: LoadedBundle, key: string, replacement?: AppSlot, selected = false): void {
      if (replacement && !slots.includes(replacement))
        throw new Error("shell: replacement target changed while the candidate was loading");
      if (replacement && slots.some((slot) => keyOf(slot) === key && slot !== replacement))
        throw new Error(`shell: replacement identity '${key}' is already installed`);
      // The raw-link binding changes hands only by explicit selection (§12.5): a candidate
      // reaching `link` must replace the slot holding it or, with no holder, be the boot's
      // selected transport; and a plain load may not displace the holder, even with a
      // version that drops `link`. Refused LOUDLY, because the alternative is a node that
      // looks installed and is off the network. Asked before the claim contest, so a
      // would-be transport claiming the holder's service id is told the rule it broke.
      const holder = slots.find(hasLink);
      if (holder && holder !== replacement && (reachesLink(loaded.manifest) || keyOf(holder) === key))
        throw new Error(`shell: the transport changes only by explicit replacement of its own slot — use replaceBundle('${keyOf(holder)}', …)`);
      if (!holder && !selected && reachesLink(loaded.manifest))
        throw new Error(`shell: "link" is taken only by the boot's transport selection or explicit replacement of the current transport`);
      for (const [book, names, audience] of booksOf(loaded.manifest)) {
        for (const claim of names) {
          const incumbent = book.get(claim);
          if (incumbent && incumbent !== replacement && keyOf(incumbent) !== key) {
            throw new Error(`shell: ${audience} claim '${claim}' is already held by '${keyOf(incumbent)}'`);
          }
        }
      }
      // Realms are the multiplicand every per-realm ceiling is multiplied by (§12.3), so an
      // install list nobody counts would leave each of those ceilings a floor rather than a
      // bound. A replacement takes the slot it already holds and is never refused here.
      if (!replacement && slots.length >= maxSlots && !slots.some((installed) => keyOf(installed) === key)) {
        throw new Error(`shell: this node already holds its ${maxSlots} app slots — uninstall one before installing another`);
      }
    },
    /** Install `slot` under `key` and hand it every claim its manifest names. Returns the
     *  slot it displaced, claims already released and realm still standing — disposing that
     *  is the caller's, once it has torn down whatever else the slot held. */
    commit(slot: AppSlot, key: string, replacement?: AppSlot): AppSlot | undefined {
      const at = replacement ? slots.indexOf(replacement) : slots.findIndex((installed) => keyOf(installed) === key);
      const previous = at < 0 ? undefined : slots[at];
      if (previous) release(previous);
      if (at < 0) slots.push(slot);
      else slots[at] = slot;
      for (const [book, names] of booksOf(slot.verifiedBundle.manifest)) {
        for (const claim of names) book.set(claim, slot);
      }
      return previous;
    },
    /** Drop the slot with this key and release its claims. */
    remove(appKey: string): AppSlot | undefined {
      const at = slots.findIndex((slot) => keyOf(slot) === appKey);
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
      return gone;
    },
  };
}
