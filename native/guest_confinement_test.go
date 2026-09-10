package main

// The native confined realm is zero-authority: the quickjs-libc surface (std/os/bjson and
// the globals js_set_global_objs installs) belongs to the trusted host realm alone. The
// wasm links quickjs-libc, so what keeps the guest from reaching it is the host/guest
// context split in native/qjs/csrc/qjs.c (New_QJS's host_context argument), not any JS
// check. Without the split an admitted guest could `os.sleep()` the single event-loop
// thread past every budget, `std.exit()` the process, or `import("qjs:os")` to re-reach
// the modules after the globals were removed — all reproduced before the fix.
//
// The engine's WASI imports are confined separately, by substitution: see
// instantiateConfinedWASI (native/qjs/qjs.go) and native/qjs/confined_wasi_test.go.

import (
	"strings"
	"testing"

	"seedloader/qjs"
)

// The libc names a confined realm must not have. TextEncoder is deliberately absent: the
// native guest gets it from the shared polyfills (native-polyfills.ts), and the realm
// needs it.
var confinedLibcNames = []string{
	"os", "std", "bjson", "print", "console", "navigator", "gc", "setTimeout", "scriptArgs",
}

func TestConfinedRuntimeHasNoLibcGlobals(t *testing.T) {
	probes := make([]string, len(confinedLibcNames))
	for i, name := range confinedLibcNames {
		probes[i] = "typeof " + name
	}
	expr := "[" + strings.Join(probes, ",") + "].join(',')"

	confined, err := qjs.New(qjs.WithoutHostObjects())
	if err != nil {
		t.Fatal("qjs.New(WithoutHostObjects):", err)
	}
	defer confined.Close()
	v, err := confined.Context().Eval("confined-globals.js", qjs.Code(expr))
	if err != nil {
		t.Fatal("eval confined:", err)
	}
	want := strings.TrimSuffix(strings.Repeat("undefined,", len(confinedLibcNames)), ",")
	if got := v.String(); got != want {
		t.Fatalf("confined runtime globals: got %q, want %q", got, want)
	}
	v.Free()

	// The split must not over-remove: the trusted host realm still has the libc surface
	// the shell's platform adapters and the operator flow were built on.
	host, err := qjs.New()
	if err != nil {
		t.Fatal("qjs.New:", err)
	}
	defer host.Close()
	hv, err := host.Context().Eval("host-globals.js", qjs.Code(
		"[typeof os, typeof std, typeof console].join(',')"))
	if err != nil {
		t.Fatal("eval host:", err)
	}
	if got := hv.String(); got != "object,object,object" {
		t.Fatalf("host runtime globals: got %q, want %q", got, "object,object,object")
	}
	hv.Free()
}

func TestConfinedRealmCannotImportLibcModules(t *testing.T) {
	guestSeamRealm(t)
	if _, err := qc.Eval("confinement-seam.js", qjs.Code(
		`globalThis.__guestSeam = async () => new Uint8Array();`)); err != nil {
		t.Fatal("build seam:", err)
	}
	newTestRealmBudget(t, "{}", `
		async function handle() {
		  const report = [
		    typeof os, typeof std, typeof bjson, typeof print, typeof console,
		    typeof navigator, typeof gc, typeof setTimeout, typeof TextEncoder,
		  ];
		  for (const name of ["qjs:os", "qjs:std", "qjs:bjson"]) {
		    try { await import(name); report.push(name + ":loaded"); }
		    catch (e) { report.push(name + ":rejected"); }
		  }
		  return new TextEncoder().encode(JSON.stringify(report));
		}
	`, 5000)
	defer func() { _, _ = qc.Eval("dispose.js", qjs.Code(`__realm.dispose()`)) }()
	out, err := realmCall("confinement", nil)
	if err != nil {
		t.Fatal("realmCall:", err)
	}
	want := `["undefined","undefined","undefined","undefined","undefined","undefined","undefined","undefined","function",` +
		`"qjs:os:rejected","qjs:std:rejected","qjs:bjson:rejected"]`
	if string(out) != want {
		t.Fatalf("confined realm report:\n got %s\nwant %s", out, want)
	}
}
