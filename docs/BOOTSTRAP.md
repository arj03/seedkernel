# Seed kernel — Bootstrap

*The bootstrap sequence that composes the onion: the host instantiates the kernel, loads its admission policy, and grows the deployment from signed bundles.*

> **Part of the [seed kernel](../README.md) spec.** Section numbers are global across the doc set — a `(§X.Y)` reference points to whichever file below holds that section:
>
> [README](../README.md) §1 · [PROTOCOL](PROTOCOL.md) §2–§5, §16 · **BOOTSTRAP §9** · [RUNTIME](RUNTIME.md) §10–§12 · [SECURITY](SECURITY.md) §13–§14

---

## 9. Bootstrap Sequence

Bootstrap is the host's job, not the kernel's. The host instantiates the kernel, then optionally composes the layers above it. In the reference shell (§12.8) the whole sequence is short — the kernel table starts **empty** and grows only through signed bundles:

1. **Instantiate the kernel** (`kernel.wasm`). On its own it is a usable table: `register` and `callHandler` work with nothing else wired.
2. *(Optional — needed to grow the deployment.)* **Load the admission policy** (§12.5): the closed author set, an optional module-hash allowlist, and — where a deployment wants it — a richer `admit` callback. With no policy the deployment is frozen: an empty author set refuses every manifest and every bind (§12.5). The install records that back the policy are host-side loader state (§12.4), not a handler — there is nothing to `SetHandler`.
3. *(Optional, rare.)* **`SetHandler` for any handler the deployment wants wired by hand** — a host-JS handler or a WASM transform seeded directly, outside the loader (so with no install record, §12.4). Most deployments seed nothing here; apps arrive in bundles instead.
4. **App modules arrive in a signed bundle** (§12.4): the loader verifies the manifest, integrity-checks each module, and admits it under the policy — no further host wiring needed. A bundle may also carry a zero-authority guest, which the shell runs over the cap-bridge (§12.2–§12.3).

The kernel's role in this sequence is: store handlers and answer `find_handler`. Everything else — author identification, install records, policy gating, and all I/O — is the host. Signature verification happens once, host-side, on each bundle manifest (§12.4); there is no per-message signature and no signature handler in the table. App modules (the App layer, §5.1) are delivered in signed bundles.

### 9.1 Post-bootstrap replacement

The `SetHandler` calls available during bootstrap are not special bootstrap-only operations. The same host-side handler-management path (§3.1) remains available afterward. If a bug is found in any hand-seeded handler, or an operator must swap one out, the host replaces it directly:

```
kernel.SetHandler(name, patchedHandler)
```

This does not depend on any message pipeline — the host calls it directly. That is deliberate: emergency intervention must not require the very component that might be broken. The host controls access to `SetHandler` through its own security model (process-level permissions, operator console, HSM, or whatever is appropriate for the deployment).

Ordinary growth delivers *app* handlers in a signed bundle under the loader's policy (§12.4); a live update is just a higher-`version` bundle from the same author (§12.4, §12.5). There is no wire path that mutates the table — handlers are pure transforms (§4.2) — so every replacement, like every revocation (§12.5), is a host-side action. A deployment that wants remote-triggered replacement builds a trusted host-side path to it (a signed control bundle, an operator console over an authenticated channel), keeping both the decision and the mutation in host code.
