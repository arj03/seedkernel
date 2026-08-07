// Protocol bindings (§12.10) — the shared binding table.
//
// A frame names a protocol, not an app. The wire carries a protocol id (e.g.
// "chat-v1"); the receiving host resolves it through its own bindings to whichever
// app it holds. `bind` is the ONLY way a protocol gains a destination, and it is
// always an explicit operator act — nothing else touches this table. Installation
// is inert (§12.10): a bundle lands and serves nothing until the operator points a
// protocol at it, so there are no defaults to apply and no update-inheritance rules
// for a binding to derive from. The worst an unbound protocol does is resolve to
// nothing, which the transport answers with an empty body.
//
// Bindings are shell state, not loader state, and hold no security property —
// the worst a wrong binding does is deliver to the wrong app the user already
// chose to install.
//
// This module owns ONLY the proto→appKey mapping. App records (moduleName, UI
// metadata, etc.) live in the caller's own registry — the shell (chat-shell.js)
// or the native host — and Bindings resolves appKeys that the caller then looks up.

export class Bindings {
  private table = new Map<string, string>();   // protocol id → appKey

  /** Which app, if any, handles this protocol? Returns the appKey, or null. */
  boundApp(proto: string): string | null {
    return this.table.get(proto) ?? null;
  }

  bind(proto: string, appKey: string): void {
    this.table.set(proto, appKey);
  }

  unbind(proto: string): void {
    this.table.delete(proto);
  }

  /** Remove every binding belonging to appKey — used on uninstall. */
  removeApp(appKey: string): void {
    for (const [proto, key] of this.table) {
      if (key === appKey) this.table.delete(proto);
    }
  }

  /** Which protocols is this app currently bound to? */
  boundProtocols(appKey: string): string[] {
    const out: string[] = [];
    for (const [proto, key] of this.table) {
      if (key === appKey) out.push(proto);
    }
    return out;
  }

  /** Serialize bindings for persistence. */
  entries(): [string, string][] { return [...this.table]; }
}
