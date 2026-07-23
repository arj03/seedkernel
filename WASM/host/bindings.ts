// Protocol bindings (§12.10) — the shared binding table.
//
// A frame names a protocol, not an app. The wire carries a protocol id (e.g.
// "chat-v1"); the receiving host resolves it through its own bindings to whichever
// app it holds. This module implements the three binding rules every target shares:
//
//   1. Auto-bind only into a vacancy — on install, each declared protocol with no
//      binding binds to the new app.
//   2. A contested protocol is a choice, never an error — the app installs but
//      stays unbound for that protocol.
//   3. An update inherits only what it already had — new protocols land unbound.
//
// Bindings are shell state, not loader state, and hold no security property —
// the worst a wrong binding does is deliver to the wrong app the user already
// chose to install.
//
// This module owns ONLY the proto→appKey mapping. App records (handlerName, UI
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

  /** Auto-bind on install, into VACANCIES only (§12.10 rule 1). */
  autoBind(appKey: string, handles: string[]): void {
    for (const proto of handles) {
      if (!this.table.has(proto)) this.table.set(proto, appKey);
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
