package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The `fs` seam the shared code uses (services/fs.ts) returns Uint8Array on a hit and null
// on a miss, end to end: the shared key store (services/fs-files.ts) over Go's file
// primitive (fs.go).
//
// Every call answers within the call, as `RawFiles` does on every target (services/fs.ts).
func TestFsExposedToRealm(t *testing.T) {
	bootRealm(t) // a store on a fresh temp dir, the way --dir gives one
	if _, err := qc.Eval("fs-realm-test.js", `
		const enc = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));
		const dec = (b) => { let s = ""; for (const x of b) s += String.fromCharCode(x); return s; };
		globalThis.__fsProbe = () => {
			fs.put("blk1", enc("payload-one"));
			fs.put("blk2", enc("payload-two"));
			fs.put("blk2", enc("payload-2"));
			return enc([
				dec(fs.get("blk1")),
				fs.get("nope") === null ? "null" : "notnull",
				String(fs.size("blk1")), String(fs.size("nope")),
				fs.list("blk").sort().join(","),
				String(fs.list("zzz").length),
				String(fs.delete("blk1")), String(fs.size("blk1")), String(fs.delete("blk1")),
				String(fs.stat().used),
			].join("|"));
		};
	`); err != nil {
		t.Fatalf("eval: %v", err)
	}
	got, err := callRealm("__fsProbe", 5*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	// Existence is size >= 0 (there is no `has`): present blk1 = 11, absent = -1.
	const want = "payload-one|null|11|-1|blk1,blk2|0|true|-1|false|9"
	if string(got) != want {
		t.Fatalf("fs realm round trip:\n got %q\nwant %q", string(got), want)
	}
}

// What the store finds in its directory at open: a crash's temp file is reclaimed and
// never listed, every other file counts toward `used`, and one larger than a put could
// carry is never read into memory.
func TestFsOpenOverExistingFiles(t *testing.T) {
	bootRealm(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "~blk.123"), []byte("torn"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blk"), []byte("kept"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "huge"), bytes.Repeat([]byte{1}, 16<<20+1), 0o644); err != nil {
		t.Fatal(err)
	}
	got := awaitOK(t, "open scan", `(() => {
		const f = new FilesFs(__fs, `+jsonString(dir)+`);
		const s = f.stat();
		return new TextEncoder().encode([s.used, f.list().sort().join(","), String(f.get("huge"))].join("|"));
	})()`, 5*time.Second)
	if string(got) != "16777221|blk,huge|null" {
		t.Fatalf("open over existing files: %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "~blk.123")); err == nil {
		t.Fatal("the crash's temp file was not reclaimed")
	}
}

// Containment: a key that could name something other than a plain file inside the data
// directory is refused, so nothing is written outside it. Which keys are valid is
// `isSafeFsKey` (WASM/services/fs.ts), one rule for every target, tested there.
func TestFsKeysStayInTheirDirectory(t *testing.T) {
	bootRealm(t)
	parent := t.TempDir()
	got := awaitOK(t, "unsafe keys", `(() => {
		const f = new FilesFs(__fs, `+jsonString(filepath.Join(parent, "data"))+`);
		const out = [];
		for (const k of ["", ".", "..", "a/b", "../pwned", "a\\b"]) {
			try { f.put(k, new Uint8Array([1])); out.push("accepted"); } catch { out.push("refused"); }
			out.push(String(f.size(k)), String(f.get(k)), String(f.delete(k)));
		}
		return new TextEncoder().encode(out.join(","));
	})()`, 5*time.Second)
	if strings.Contains(string(got), "accepted") || strings.Contains(string(got), "true") {
		t.Fatalf("an unsafe key resolved: %s", got)
	}
	if _, err := os.Stat(filepath.Join(parent, "pwned")); err == nil {
		t.Fatal("an unsafe key escaped the data directory")
	}
}
