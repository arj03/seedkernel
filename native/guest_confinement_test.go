package main

// A realm is zero-authority by construction: qjs.wasm links no quickjs-libc and sets no
// module loader (native/qjs/csrc/shim.c), so no realm has std/os/bjson, their globals, or a
// module name to import them by. Were they reachable, an admitted guest could `os.sleep()`
// the single event-loop thread past every budget, `std.exit()` the process, or
// `import("qjs:os")` to re-reach the modules.
//
// The engine's WASI imports refuse everything but the clock: see instantiateWASI
// (native/qjs/qjs.go) and native/qjs/wasi_test.go.

import (
	"strings"
	"testing"

	"seedloader/qjs"
)

// The libc names no realm has. The host realm has a console, timers and text codecs of its
// own (host/native-polyfills.ts, loop.go), so those are checked only on a bare runtime; a
// confined realm has none of them (TestConfinedRealmCannotImportLibcModules).
var (
	libcNames     = []string{"os", "std", "bjson", "print", "navigator", "gc", "scriptArgs"}
	loaderGlobals = []string{"console", "setTimeout", "TextEncoder", "TextDecoder"}
)

func requireUndefined(t *testing.T, c *qjs.Context, names []string) {
	t.Helper()
	probes := make([]string, len(names))
	for i, name := range names {
		probes[i] = "typeof " + name
	}
	v, err := c.Eval("libc-globals.js", "["+strings.Join(probes, ",")+"].join(',')")
	if err != nil {
		t.Fatal("eval:", err)
	}
	defer v.Free()
	want := strings.TrimSuffix(strings.Repeat("undefined,", len(names)), ",")
	if got := v.String(); got != want {
		t.Fatalf("globals %v: got %q, want %q", names, got, want)
	}
}

func TestRuntimesHaveNoLibcGlobals(t *testing.T) {
	bare, err := qjs.New()
	if err != nil {
		t.Fatal("qjs.New:", err)
	}
	defer bare.Close()
	requireUndefined(t, bare.Context(), append(libcNames, loaderGlobals...))

	bootRealm(t)
	requireUndefined(t, qc, libcNames)
}

func TestConfinedRealmCannotImportLibcModules(t *testing.T) {
	guestSeamRealm(t)
	if _, err := qc.Eval("confinement-seam.js",
		`globalThis.__guestSeam = async () => new Uint8Array();`); err != nil {
		t.Fatal("build seam:", err)
	}
	newTestRealmBudget(t, "{}", `
		async function handle() {
		  const report = [
		    typeof os, typeof std, typeof bjson, typeof print, typeof console,
		    typeof navigator, typeof gc, typeof setTimeout, typeof TextEncoder, typeof TextDecoder,
		  ];
		  for (const name of ["qjs:os", "qjs:std", "qjs:bjson"]) {
		    try { await import(name); report.push(name + ":loaded"); }
		    catch (e) { report.push(name + ":rejected"); }
		  }
		  const s = JSON.stringify(report);
		  const out = new Uint8Array(s.length);
		  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
		  return out;
		}
	`, 5000)
	defer func() { _, _ = qc.Eval("dispose.js", `__realm.dispose()`) }()
	out, err := realmCall("confinement", nil)
	if err != nil {
		t.Fatal("realmCall:", err)
	}
	// The text codecs are the host realm's alone, as on the JS targets: a guest that needs
	// them carries its own.
	want := `["undefined","undefined","undefined","undefined","undefined","undefined","undefined","undefined","undefined","undefined",` +
		`"qjs:os:rejected","qjs:std:rejected","qjs:bjson:rejected"]`
	if string(out) != want {
		t.Fatalf("confined realm report:\n got %s\nwant %s", out, want)
	}
}
