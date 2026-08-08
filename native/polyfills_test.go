package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"seedloader/qjs"
)

// TestHostConsoleReachesStderr covers a platform facility this target silently lacked.
// quickjs-ng gives the realm a `console` with `log` and nothing else, writing it to a
// WASI stdout wazero leaves disconnected — so shared host code's `console.log` went to
// nowhere and its `console.error` threw a TypeError. The one that matters is
// transport-host.ts's: it reports a guest that failed inside a `.catch` handler, so a
// wedged transport was invisible twice over, once silently and once as a different
// error. host/native-polyfills.ts replaces console over `bridge.logErr`.
//
// Asserted on stderr rather than on the bridge function, because *which* stream it lands
// on is the property: stdout carries the operator's lines and `--get`'s raw response
// bytes, and a diagnostic mixed into those corrupts a piped response.
func TestHostConsoleReachesStderr(t *testing.T) {
	bootRealm(t)
	for _, method := range []string{"log", "error", "warn", "info", "debug"} {
		out := captureStderr(t, func() {
			if _, err := qc.Eval("console.js", qjs.Code(
				`console.`+method+`("[transport] guest error in deliver: ", new Error("boom"), 7)`,
			)); err != nil {
				t.Fatalf("console.%s threw: %v", method, err)
			}
		})
		// Every argument shows up, in order and space-separated: an Error as its message
		// (JSON.stringify would render one as `{}`), a number as itself.
		if !strings.Contains(out, "guest error in deliver:") ||
			!strings.Contains(out, "boom") || !strings.Contains(out, " 7") {
			t.Fatalf("console.%s should print all its arguments to stderr, got %q", method, out)
		}
	}
}

// captureStderr redirects the process's stderr for the duration of fn and returns what
// was written. The bridge resolves `os.Stderr` per call, so swapping it here is enough.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	fn()
	os.Stderr = saved
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
