# Seed kernel — Registry & bootstrap

*How code is admitted and wired: the host-side module registry and its policy callback, and the bootstrap sequence that composes the onion.*

> **Part of the [seed kernel](../README.md) spec.** Section numbers are global across the doc set — a `(§X.Y)` reference points to whichever file below holds that section:
>
> [README](../README.md) §1 · [PROTOCOL](PROTOCOL.md) §2–§5, §16 · **REGISTRY §7, §9** · [RUNTIME](RUNTIME.md) §10–§12 · [SECURITY](SECURITY.md) §13–§14

---

## 7. The module registry

The module registry is host-side state, not a wire protocol. It holds the install records `(author, bytes_hash)`, runs a deployer-supplied policy callback, and exposes one operation — `installDirect(name, wasm, author)` — that the bundle loader (§12.4) calls to bind each verified module. The records are read host-side (§7.6), never over the wire — there is no dispatch path onto the registry. "Who authored this code" is already settled by the manifest signature the loader checked (§12.4), so admitting a module is just a policy check followed by `SetHandler`.

### 7.1 Install records

The registry maintains one table, the install records:

```
installations[name] → {
  author:      (algo_id, pubkey)     algo_id = 0x0000 (Ed25519)
  bytes_hash:  content hash of the installed WASM module — genesisHash(wasm)
}
```

`bytes_hash` is `genesisHash(wasm)` — the SHA-3-256 hash (§5.1) of the **WASM module bytes**, the same id a manifest's `modules[].hash` (§12.4) and a policy allowlist (§7.3) use. The registry computes it from the bytes directly; caller claims are never trusted. Being the hash of the wasm alone, it survives re-signings — one identifier across install records, allowlists, and manifests. The `author` is the Ed25519 key that signed the bundle manifest, recorded as `(0x0000, pubkey)`.

`SetHandler`-seeded handlers (§3.1) have **no row** in this table — they have no author of record. The host owns whatever metadata it cares about for them.

There is **no replay high-water table** here. Installation is a host call under the bundle loader (§12.4), not a self-authenticating wire message anyone who saw it could resend, so there is nothing to replay at this layer. Downgrade of the coherent *set* is guarded by bundle freshness (`version`, §12.4); live-traffic replay is the transport's (§12.6); and an app that relays messages transitively owns its own replay/ordering defence (§5.1).

### 7.2 `installDirect`

The registry's one binding operation, `installDirect(name, wasm, author)`:

1. Computes `bytes_hash = genesisHash(wasm)` — the content hash of the WASM module (§7.1). One identifier across install records, policy allowlists, and manifests.
2. Fetches the existing record at `name`, if any.
3. Calls the deployer-supplied **policy callback** `approveInstall(name, author, bytes_hash, wasm, existing_record_or_null) → bool`. If no callback is wired or it returns false, refuse — no bind. With no callback wired, every bind is refused; admission is opt-in for the deployment.
4. Instantiates the WASM against the standard pure-transform handler ABI (§4) and calls `SetHandler(name, instance)`.
5. Writes the install record to `installations[name]`.

The bundle loader (§12.4) calls this once per module, with the manifest author. The module bytes came from a verified local file, not a wire message, so nothing about them is size-capped or framed for transport. The policy callback runs against the *resolved* state (with `bytes_hash` already computed and any existing record fetched), so the policy never has to do that work itself.

### 7.3 The policy callback

The callback is the entire authorization story. It receives everything relevant:

- `name` — the name the module targets
- `author` — `(algo_id, pubkey)` of the manifest author
- `bytes_hash` — the content hash of the WASM about to be bound
- `wasm` — the raw WASM bytes. Pre-approved binaries match against `bytes_hash` cheaply; inspection-based policies (structural validation, instruction-set filtering, export-table checks) get the bytes directly without re-hashing.
- `existing_record_or_null` — the current installation at `name`, if any

It returns `true` to proceed with the bind or `false` to refuse. That is the full interface.

Deployers wire whatever policy fits their environment. Some examples:

- **Open registry.** `return true;` — any admitted author may bind any name. This is not wire-reachable (installation is a host call, not a message), so it is not remote code execution the way an open wire-install policy would have been. But it still means every module in every bundle the loader is handed lands unconditionally, so pair it with a closed author set (the shell's `--policy`, §12.5) — an open policy is a bring-up convenience, not a posture for a node handed bundles from untrusted sources.
- **Reference policy.** `existing == null ? deployer_first_install(...) : author == existing.author` — an author gate; see §7.4.
- **Content-hash allowlist.** `return bytes_hash ∈ approved_hashes;` — only pre-audited binaries. `bytes_hash = genesisHash(wasm)`, so an entry pins one specific binary and stays valid across re-signings.

Other common patterns: fixed author allowlists and M-of-N quorums enforced in the callback.

The callback may be arbitrarily expensive — it runs once per module at bundle-load time, not on any message hot path. A callback that consults an operator console or HSM is fine.

### 7.4 Default reference policy

The reference registry ships with a default policy that is easy to explain — "trust the original author." It has two rules, both about *who* may bind a name:

1. **First bind at a name:** the deployer's choice. The reference implementation exposes a `firstInstallPolicy(name, author, bytes_hash)` sub-callback that the deployer wires. Common values are:
   - An author allowlist (closed registry — only specified keys may claim new names).
   - A naming-convention check (e.g. names must be of the form `hash(canonical ‖ author_pubkey)`, structurally proving the author claimed the name for themselves).
   - `return true` (open registry). **Read the warning in §7.3 before using this** — an unconditional first-bind policy admits any module the loader is handed, so it belongs with a closed author set, never alone on a node handed untrusted bundles.
2. **Subsequent bind at the same name:** the module must be authored by the existing author:
   ```
   author == existing.author
   ```

   This is the reference choice, not a protocol requirement. Every bind flows through `approveInstall`, so a deployer who wants stricter update control — a quorum, or an explicit acknowledgement on every update — encodes it in the callback.

These rules give you everything you'd usually want without any extra machinery:

- **Squat-resistant.** Once an author has bound a name, no one else can take it over — their bind fails rule 2.
- **Upgrades just work.** The author ships a new bundle version signed with the same key; the binding updates in place with no further interaction.
- **Delegation is just an upgrade.** To hand a name over, the current author ships a new version whose handler treats some other key as the relevant authority going forward, and (optionally) the registry records the new author. The kernel doesn't care; the install record is the source of truth.
- **Slots seeded by `SetHandler` are refused.** If there is no record for `name` but the kernel already resolves it (`find_handler(name) ≥ 0`), the slot was seeded via host-side `SetHandler` — a deliberately hand-wired handler, outside the registry. The registry refuses to overlay it; replacing such a slot is a direct host-side `SetHandler`.

The reference policy is one specific way of saying "trust the original author." Deployments with different needs — quorum-controlled production registries, content-hash allowlists, delegation hierarchies — replace `firstInstallPolicy` or the whole callback. Everything else in the system behaves the same.

**Design note: install state is a register, not a log.** `installations[name]` holds only the current record — no `parent` hash chaining a name's versions. Backlinks earn their keep where *history* replicates through untrusted intermediaries — [SSB](https://ssbc.github.io/scuttlebutt-protocol-guide/)'s `previous` link, [Bamboo](https://github.com/AljoschaMeyer/bamboo)'s lipmaa links — verifying a log segment as complete and in-order and making equivocation provable. Both need an observer that *stores* history; a register holding only the current record has no verifier, and fork detection is impossible for a component that never holds two versions at once. Bundle `version` (§12.4) already gives per-`(author, app)` ordering and downgrade protection — SSB's sequence-number role. This is the same boundary the README draws for *messages*: a relayed-message app (a feed, a forum) that needs verifiable lineage is exactly the case for signatures + backlinks, and it builds that on top — logging its signed manifests or messages in a replicated append-only log (Bamboo is the design to borrow — entries commit to a payload hash, keeping it small) and feeding the loader or the app from it. The lineage then lives where it can be verified, and the registry stays a register.

### 7.5 Revocation

Revocation is host-side. Because a handler is a pure transform with no imports (§4.2), nothing in the sandbox can mutate the registry or the kernel table — there is no state-mutating wire handler to reach `installer.remove`, and never a "revoke message." Undoing a bind is an operator action, expressed two ways:

**Removing a bind.** The registry exposes `installer.remove(name)` as a host-side method (callable by the host directly, like `SetHandler`). It clears `installations[name]` and calls `SetHandler(name, null)`. Used by operators for emergency cleanup.

**Refusing future binds.** The policy callback (§7.3) is where a deployment expresses "this author/these bytes may not bind again" — a deny-list of `author`s or `bytes_hash`es, maintained as out-of-band state distributed by whatever channel the deployment trusts (operator console, signed update from a higher authority). This stops new binds; pair it with `installer.remove` to also clear a handler already in place.

**Post-revocation behaviour.** Removing a bind clears the slot. Anyone may then re-bind at the same name under rule 1 of the reference policy, unless the deny-list forbids it. The kernel doesn't enforce permanence; the policy callback does, if a deployment wants it.

**Compromised key recovery.** Under the strict reference policy a compromised key can keep shipping new versions of its handlers indefinitely — `author == existing.author` still matches. The protocol does not bake in a single recovery model; *who* may override the original author is a deployment policy question. Two deployer-side responses exist, and most production deployments will want both:

- **Deny-list in `approveInstall`.** Refuse binds where `author` is in a deployment-maintained revoked set. This stops new binds but does not by itself remove the compromised handler already in place.
- **Host-side `installer.remove`.** The operator clears the compromised handler directly. Pair with a deny-list so the same key cannot re-bind immediately afterward.

A deployment that wants *remote-triggered* revocation builds a trusted host-side path to `installer.remove` (an operator console over an authenticated channel, a signed control bundle) — the decision and the mutation both stay in host code, where the TCB is (§14).

### 7.6 Reading install records

The install records are read **host-side** — there is no wire query. A host holds a direct `lookup(name) → {author, bytes_hash} | null` on the registry. The only in-pipeline consumer of an install record is the policy callback (§7.3), and it already receives the resolved `existing` record, so nothing needs a round-trip to read one.

The registry has **no wire surface** — nothing dispatchable. It is pure host-side state that the bundle loader mutates through `installDirect` and the host reads through `lookup`. A deployment that wants a wire-reachable directory of installs builds one as an ordinary app handler over the host-side `lookup`.

---

## 9. Bootstrap Sequence

Bootstrap is the host's job, not the kernel's. The host instantiates the kernel, then optionally composes the layers above it. In the reference shell (§12.8) the whole sequence is short — the kernel table starts **empty** and grows only through signed bundles:

1. **Instantiate the kernel** (`kernel.wasm`). On its own it is a usable table: `register` and `callHandler` work with nothing else wired.
2. *(Optional — needed to grow the deployment.)* **Create the module registry** and wire `approveInstall(name, author, bytesHash, wasm, existing) => …`. With no registry, the deployment is frozen. With it created but no callback, every bind is refused. The registry is host-side state (§7), not a handler — there is nothing to `SetHandler`, and its records are read host-side (§7.6).
3. *(Optional, rare.)* **`SetHandler` for any handler the deployment wants wired by hand** — a host-JS handler or a WASM transform seeded directly, outside the registry (so with no install record, §7.1). Most deployments seed nothing here; apps arrive in bundles instead.
4. **App modules arrive in a signed bundle** (§12.4): the bundle loader verifies the manifest, integrity-checks each module, and calls the registry's `installDirect` — no further host wiring needed. A bundle may also carry a zero-authority guest, which the shell runs over the cap-bridge (§12.2–§12.3).

The kernel's role in this sequence is: store handlers and answer `find_handler`. Everything else — author identification, install records, policy gating, and all I/O — is the host. Signature verification happens once, host-side, on each bundle manifest (§12.4); there is no per-message signature and no signature handler in the table. App modules (the App layer, §5.1) are delivered in signed bundles.

### 9.1 Post-bootstrap replacement

The `SetHandler` calls available during bootstrap are not special bootstrap-only operations. The same host-side handler-management path (§3.1) remains available afterward. If a bug is found in any hand-seeded handler, or an operator must swap one out, the host replaces it directly:

```
kernel.SetHandler(name, patchedHandler)
```

This does not depend on any message pipeline — the host calls it directly. That is deliberate: emergency intervention must not require the very component that might be broken. The host controls access to `SetHandler` through its own security model (process-level permissions, operator console, HSM, or whatever is appropriate for the deployment).

Ordinary growth delivers *app* handlers in a signed bundle under the registry's policy (§12.4); a live update is just a higher-`version` bundle from the same author (§7.4, §12.4). There is no wire path that mutates the table — handlers are pure transforms (§4.2) — so every replacement, like every revocation (§7.5), is a host-side action. A deployment that wants remote-triggered replacement builds a trusted host-side path to it (a signed control bundle, an operator console over an authenticated channel), keeping both the decision and the mutation in host code.
