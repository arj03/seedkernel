package main

// The host's own module loader (platform.ts over the bounded engine table), as the module
// tests drive it: a set built under a key, and calls into it by name, from the realm.

import (
	"encoding/json"
	"testing"
	"time"

	"seedkernel/qjs"
)

const moduleHarness = `
globalThis.__modSets ??= new Map();
globalThis.__buildMods = async (key, names, ...wasms) => {
  __modSets.get(key)?.dispose();
  __modSets.delete(key);
  const set = await platformModules.build(JSON.parse(names).map((name, i) => ({ name, wasm: new Uint8Array(wasms[i]) })));
  __modSets.set(key, set);
  return new Uint8Array(0);
};
globalThis.__callMod = async (key, name, payload, deadlineMs) => {
  const r = await __modSets.get(key).call(name, new Uint8Array(payload), deadlineMs);
  if (r.bytes === null) return new Uint8Array([0]);
  const out = new Uint8Array(1 + r.bytes.length);
  out[0] = 1;
  out.set(r.bytes, 1);
  return out;
};
globalThis.__hasMods = async (key) => new Uint8Array([__modSets.has(key) ? 1 : 0]);`

// buildModules builds names → wasms under key through the host's loader, replacing what
// the key held, all or none.
func buildModules(t testing.TB, key string, names []string, wasms ...[]byte) error {
	t.Helper()
	if _, err := qc.Eval("module-harness.js", moduleHarness); err != nil {
		t.Fatal("module harness:", err)
	}
	j, err := json.Marshal(names)
	if err != nil {
		t.Fatal(err)
	}
	args := []*qjs.Value{qc.NewString(key), qc.NewString(string(j))}
	for _, w := range wasms {
		args = append(args, qc.NewArrayBuffer(w))
	}
	_, err = callRealm("__buildMods", 10*time.Second, args...)
	return err
}

// callMod calls one module of a set: its answer, or nil when the call failed.
func callMod(t testing.TB, key, name string, payload []byte, deadline time.Duration) []byte {
	t.Helper()
	r, err := callRealm("__callMod", 10*time.Second, qc.NewString(key), qc.NewString(name),
		qc.NewArrayBuffer(payload), qc.NewInt64(deadline.Milliseconds()))
	if err != nil {
		t.Fatal("module call:", err)
	}
	if r[0] == 0 {
		return nil
	}
	return r[1:]
}

// hasModules reports whether key holds a set.
func hasModules(t testing.TB, key string) bool {
	t.Helper()
	r, err := callRealm("__hasMods", time.Second, qc.NewString(key))
	if err != nil {
		t.Fatal(err)
	}
	return r[0] == 1
}
