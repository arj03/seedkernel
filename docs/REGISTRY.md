# Seed kernel — Registry, bridges & bootstrap

*How code is admitted and wired: the host-side module registry and its policy callback, the I/O bridges that pin their callers, and the bootstrap sequence that composes the onion.*

> **Part of the [seed kernel](../README.md) spec.** Section numbers are global across the doc set — a `(§X.Y)` reference points to whichever file below holds that section:
>
> [README](../README.md) §1 · [PROTOCOL](PROTOCOL.md) §2–§6, §16 · **REGISTRY §7–§9** · [RUNTIME](RUNTIME.md) §10–§12 · [SECURITY](SECURITY.md) §13–§14

---

## 7. The module registry

The module registry is host-side state, not a wire protocol. It holds the install records `(author, bytes_hash)`, runs a deployer-supplied policy callback, and exposes one operation — `installDirect(name, wasm, author)` — that the bundle loader (§12.4) calls to bind each verified module. The records are read host-side (§7.6), never over the wire — there is no dispatch path onto the registry. "Who authored this code" is already settled by the manifest signature the loader checked (§6, §12.4), so admitting a module is just a policy check followed by `SetHandler`.

### 7.1 Install records

The registry maintains one table, the install records:

```
installations[name] → {
  author:      (algo_id, pubkey)
  bytes_hash:  content hash of the installed WASM module — genesisHash(wasm)
}
```

`bytes_hash` is the genesis-suite hash (§6.2) of the **WASM module** — `genesisHash(wasm)`, the same id a manifest's `modules[].hash` (§12.4) and a policy allowlist (§7.3) use. The registry computes it from the bytes directly; caller claims are never trusted. Being the hash of the wasm alone, it survives re-signings — one identifier across install records, allowlists, and manifests.

`SetHandler`-seeded bootstrap handlers have **no row** in this table. They have no author of record and their name is in no bridge's pinned-caller list (§8). The host owns whatever metadata it cares about.

There is **no replay high-water table** here. Installation is a host call under the bundle loader, not a self-authenticating wire message anyone who saw it could resend, so there is nothing to replay. App-level replay defence, when an app needs it, is the app's own concern (§4.4).

### 7.2 `installDirect`

The registry's one binding operation, `installDirect(name, wasm, author)`:

1. Computes `bytes_hash = genesisHash(wasm)` — the content hash of the WASM module (§7.1). One identifier across install records, policy allowlists, and manifests.
2. Fetches the existing record at `name`, if any.
3. Calls the deployer-supplied **policy callback** `approveInstall(name, author, bytes_hash, wasm, existing_record_or_null) → bool`. If no callback is wired or it returns false, refuse — no bind. With no callback wired, every bind is refused; admission is opt-in for the deployment.
4. Instantiates the WASM against the standard handler ABI (§4) and calls `SetHandler(name, instance)`. Suite binds (§6.4) take this same path — a suite is an ordinary handler at its slot name, with no special-casing.
5. Writes the install record to `installations[name]`.

The bundle loader (§12.4) calls this once per module, with the manifest author. The module bytes came from a verified local file, not the dispatch path, so no envelope cap or wire framing applies. The policy callback runs against the *resolved* state (with `bytes_hash` already computed and any existing record fetched), so the policy never has to do that work itself.

### 7.3 The policy callback

The callback is the entire authorization story. It receives everything relevant:

- `name` — the name the module targets
- `author` — `(algo_id, pubkey)` of the manifest author
- `bytes_hash` — the content hash of the WASM about to be bound
- `wasm` — the raw WASM bytes. Pre-approved binaries match against `bytes_hash` cheaply; inspection-based policies (e.g. structural validation, instruction-set filtering, export-table checks for suites) get the bytes directly without re-hashing.
- `existing_record_or_null` — the current installation at `name`, if any

It returns `true` to proceed with the bind or `false` to refuse. That is the full interface.

Deployers wire whatever policy fits their environment. Some examples:

- **Open registry.** `return true;` — any admitted author may bind any name. This is not wire-reachable (installation is a host call, not a message), so it is not remote code execution the way an open wire-install policy would have been. But it still means every module in every bundle the loader is handed lands unconditionally, so pair it with a closed author set (the shell's `--policy`, §12.5) — an open policy is a bring-up convenience, not a posture for a node handed bundles from untrusted sources.
- **Reference policy.** `existing == null ? deployer_first_install(...) : author == existing.author` — an author gate; see §7.4.
- **Content-hash allowlist.** `return bytes_hash ∈ approved_hashes;` — only pre-audited binaries. `bytes_hash = genesisHash(wasm)`, so an entry pins one specific binary and stays valid across re-signings.

Other common patterns: fixed author allowlists and M-of-N quorums (a composite suite that verifies several keys under one `algo_id`, §6.4).

The callback may be arbitrarily expensive — it runs once per module at bundle-load time, not on the message-dispatch hot path. A callback that consults an operator console or HSM is fine.

### 7.4 Default reference policy

The reference registry ships with a default policy that is easy to explain — "trust the original author." It has two rules, both about *who* may bind a name:

1. **First bind at a name:** the deployer's choice. The reference implementation exposes a `firstInstallPolicy(name, author, bytes_hash)` sub-callback that the deployer wires. Common values are:
   - An author allowlist (closed registry — only specified keys may claim new names).
   - A naming-convention check (e.g. names must be of the form `hash(canonical || author_pubkey)`, structurally proving the author claimed the name for themselves).
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
- **Slots seeded by `SetHandler` are refused.** If there is no record for `name` but `kernel.handlers[name]` is non-null, the slot was seeded via host-side `SetHandler` (a bootstrap entry like the signature handler). The registry refuses to overlay it. To replace such a slot, the host uses `SetHandler` directly.

The reference policy is one specific way of saying "trust the original author." Deployments with different needs — quorum-controlled production registries, content-hash allowlists, delegation hierarchies — replace `firstInstallPolicy` or the whole callback. Everything else in the system behaves the same.

**Design note: install state is a register, not a log.** `installations[name]` holds only the current record — no `parent` hash chaining a name's versions. Backlinks earn their keep where *history* replicates through untrusted intermediaries — [SSB](https://ssbc.github.io/scuttlebutt-protocol-guide/)'s `previous` link, [Bamboo](https://github.com/AljoschaMeyer/bamboo)'s lipmaa links — verifying a log segment as complete and in-order and making equivocation provable. Both need an observer that *stores* history; a register holding only the current record has no verifier, and fork detection is impossible for a component that never holds two versions at once. Bundle `version` (§12.4) already gives per-`(author, app)` ordering and downgrade protection — SSB's sequence-number role. A deployment wanting verifiable lineage should log the signed manifests in a replicated append-only log (Bamboo is the design to borrow — entries commit to a payload hash, keeping it small) and feed the loader from it; the lineage then lives where it can be verified, and the registry stays a register.

### 7.5 Revocation

There is no separate revocation cascade. Revocation is something the policy expresses, plus a small mechanism the registry exposes for undoing previous binds.

**Removing a bind.** The registry exposes `installer.remove(name)` as a host-side method (callable by the host directly, not via messages — like `SetHandler`). It clears `installations[name]` and calls `SetHandler(name, null)`. Suite slots (§6.4) are ordinary handler binds and take exactly this path. The genesis suite is never registry-managed (its handler was seeded by the host via `SetHandler`, not admitted), so `installer.remove` on the genesis slot is a no-op; removing the genesis suite requires a direct host-side `SetHandler(name, null)`. Used by operators for emergency cleanup or by a message-driven revocation handler a deployer chooses to add.

**Message-driven revocation.** A deployer who wants signed messages to be able to revoke binds adds a `revoke` handler (a state mutator, so blocked from `kernel.call` and gated by signature verification at top-level dispatch, §4.4) that:

1. Identifies the author (the signer).
2. Decides — through its own logic, which the deployer writes — whether this author is permitted to revoke this name. The reference suggestion: only the current author may revoke it; in trust-chain-like deployments, an ancestor authority may revoke a descendant's binds.
3. Calls `installer.remove(name)` on approval.

**Post-revocation behaviour.** Removing a bind clears the slot. Anyone may then re-bind at the same name under rule 1 of the reference policy, or the deployer's policy can maintain a deny-list to prevent specific bytes_hashes or specific authors from reclaiming. The kernel doesn't enforce permanence; the policy callback does, if a deployment wants permanence.

**Compromised key recovery.** Under the strict reference policy a compromised key can keep shipping new versions of its handlers indefinitely — `author == existing.author` still matches. The protocol does not bake in a single recovery model; *who* may override the original author is a deployment policy question. Three deployer-side responses exist, and most production deployments will want at least one:

- **Deny-list in `approveInstall`.** Refuse binds where `author` is in a deployment-maintained revoked set. The set is out-of-band state, distributed by whatever channel the deployment trusts (operator console, gossip, signed update from a higher authority). This stops new binds but does not by itself remove the compromised handler that is already in place.
- **Host-side `installer.remove`.** The operator clears the compromised handler directly. Pair with a deny-list so the same key cannot re-bind immediately afterward.
- **A deployer-defined `revoke` handler** as described above, signed by a higher authority (operator key, M-of-N quorum). On approval it calls `installer.remove`.

### 7.6 Reading install records

The install records are read **host-side** — there is no `kernel.call` query message. A host holds a direct `lookup(name) → {author, bytes_hash} | null` on the registry. The only in-pipeline consumer of an install record is the policy callback (§7.3), and it already receives the resolved `existing` record, so nothing needs a wire round-trip to read one. Bridges don't read the registry at all — they authorize callers by pinning names (§8).

The registry has **no wire surface** — nothing dispatchable. It is pure host-side state that the bundle loader mutates through `installDirect` and the host reads through `lookup`. A deployment that wants a wire-reachable directory of installs builds one as an ordinary app handler over the host-side `lookup`.

---

## 8. I/O Bridges

A bridge is a `SetHandler`-installed handler that **pins the caller names it serves**. Bridges are the only code in the system that performs real I/O; everything else is pure computation inside the WASM sandbox.

### 8.1 Bridge authorization: pinning `kernel.caller`

A bridge authorizes each request by comparing its **immediate caller** against the set of caller names it was wired to serve. There is no capability index to consult and no per-install cap to declare: granting a handler access to a bridge *is* the operator wiring that handler's name into the bridge's pin list.

```
caller = kernel.caller()               # [name_len u8][name bytes]; [0x00] = no caller
if caller.name_len == 0: return -1     # reached by direct envelope dispatch, not by kernel.call
if caller.name ∉ my_pinned_callers: return -1
# ...perform I/O and return the result...
```

The chat shell's UI bridge is the worked example (§11): it compares `kernel.caller` against the single handler name it serves and refuses everyone else. Pinning collapses the trust flow to one decision by one decider — the operator wiring the pin — with no index in between.

**`kernel.caller` is not an author.** It returns the *name* of the immediate calling handler, not a key. A bridge whose policy depends on the **author** rather than on which handler called MUST additionally consult `signature.signer`: the two answer "which handler is asking?" versus "whose signed message kicked off this chain?". Most bridges need only the former, being pinned to handler *names*. Only the immediate caller is exposed, so the confused-deputy mistake of authorizing on a deeper frame is structurally unavailable, not merely forbidden.

**Whether the input was signed is orthogonal to whether the bridge fires.** Signing is opt-in (§2.1) and the bridge check is caller-*name*-based. So an *unsigned* envelope dispatched to a served handler drives that handler's bridge I/O with no signer set — nothing in the kernel, registry, or bridge layer requires the triggering envelope to be signed. An app author MUST NOT assume "my handler only runs on signed input"; a handler whose behaviour depends on the caller's identity MUST consult `signature.signer` itself and refuse an absent or unauthorized signer. The chat demo gets this for free only because its inbound frames are signed and the signer is pinned to the channel (§11); the core protocol does not enforce it. See §14.

### 8.2 Structural sandbox invariant

A bridge serves only the caller names it was wired with. A bootstrap handler seeded via `SetHandler` (the `signature` wrapper, a suite) is in no bridge's pin list, so every bridge check against it fails — not by a rule in its code, but because nothing pins it. That is the structural reason a compromised bootstrap handler still can't open a socket.

---

## 9. Bootstrap Sequence

Bootstrap is the host's job, not the kernel's. The host instantiates the kernel and the modules, then composes the onion.

1. Instantiate the kernel.
2. `SetHandler` for the genesis signature suite handler (verified by hash) at its suite-slot name (§6.4).
3. `SetHandler` for the `signature` wrapper and the `signature.signer` query handler.
4. *(Optional — needed to grow the deployment.)* Create the module registry and wire `approveInstall(name, author, bytesHash, wasm, existing) => …`. With no registry, the deployment is frozen. With it created but no callback, every bind is refused. The registry is host-side state (§7), not a handler — there is nothing to `SetHandler`, and its records are read host-side (§7.6).
5. *(Optional.)* `SetHandler` for I/O bridges (`net.send`, `ui.write`, `fs.read`, …). Bridges are native host code, each pinning the caller names it serves.
6. *(Optional.)* App modules (chat, …) arrive after this point in a signed bundle (§12.4): the bundle loader verifies the manifest, integrity-checks each module, and calls the registry's `installDirect` — no further host wiring needed.

The kernel's role in this sequence is: store handlers and dispatch messages. Everything else — author identification, install records, policy gating — is the host wiring modules together. Signature verification happens once at the `signature` entry point (and once, host-side, on each bundle manifest, §12.4). The bundle loader turns verified modules into `SetHandler` calls through the registry and records each module's author + bytes_hash. Bridges authorize their callers by pinning caller names (§8), independent of the registry. App modules (layer 4, §5.1) are delivered in signed bundles.

### 9.1 Post-bootstrap replacement

The `SetHandler` calls during bootstrap are not special bootstrap-only operations. The same `kernel.SetHandler(name, handler)` method (§3.1) remains available to the host after bootstrap. If a bug is found in the signature handler, a suite, or any other bootstrap handler, the host can replace it at any time:

```
kernel.SetHandler(signatureName, patchedSignatureHandler)
```

This does not depend on the message pipeline — the host calls it directly, bypassing `signature` and the registry. This is deliberate: if the component you need to fix is the one that verifies messages, no signed message can authorize the fix. The host controls access to `SetHandler` through its own security model (process-level permissions, operator console, HSM, or whatever is appropriate for the deployment).

**Message-driven replacement of bootstrap handlers.** Ordinary growth delivers *app* handlers in a signed bundle under the registry's policy (§12.4). Replacing a *bootstrap* handler (signature, a suite) is a different threat model — the reference policy refuses to bind over a slot that was seeded via `SetHandler` precisely because that's how bootstrap handlers arrive. Deployers who want signed-message authority to swap a bootstrap handler can wire a separate `bootstrap.replace` handler after bootstrap, with whatever authorization rules fit (single root key, M-of-N quorum, etc.). It is a state-mutating wire handler — added to the `kernel.call` blocklist (§4.4), gated by signature verification at top-level dispatch, and it owns its own replay defence (§4.4).

The host-level `SetHandler` path remains available regardless as the emergency fallback for cases where the message pipeline itself is compromised.
