package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"seedloader/qjs"
)

func TestNodeFsRoundTrip(t *testing.T) {
	fs, err := newNodeFs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if fs.has("k1") || fs.size("k1") != -1 || fs.get("k1") != nil {
		t.Fatal("a missing key should read as absent")
	}

	val := []byte("hello world")
	if err := fs.put("k1", val); err != nil {
		t.Fatal(err)
	}
	if !fs.has("k1") || fs.size("k1") != len(val) {
		t.Fatalf("after put: has=%v size=%d", fs.has("k1"), fs.size("k1"))
	}
	if got := fs.get("k1"); !bytes.Equal(got, val) {
		t.Fatalf("get = %q, want %q", got, val)
	}
	if fs.stat() != int64(len(val)) {
		t.Fatalf("stat used = %d, want %d", fs.stat(), len(val))
	}

	fs.put("k2", []byte("x"))
	fs.put("other", []byte("y"))
	if all := fs.list(""); len(all) != 3 {
		t.Fatalf("list(\"\") = %v", all)
	}
	if pref := fs.list("k"); len(pref) != 2 {
		t.Fatalf("list(\"k\") = %v", pref)
	}

	if !fs.delete("k1") || fs.has("k1") {
		t.Fatal("delete should remove the key")
	}
	if fs.delete("k1") {
		t.Fatal("delete of an absent key should report false")
	}
}

// Unsafe keys are rejected on write and never resolve on read/delete, so a guest
// cannot escape the data directory, use a path separator, or (on a Windows holder)
// address a reserved device name like CON/NUL/COM1 — case- and extension-insensitively.
func TestNodeFsRejectsUnsafeKeys(t *testing.T) {
	fs, _ := newNodeFs(t.TempDir())
	unsafe := []string{"", ".", "..", "a/b", "../escape", `a\b`, "a b", "a\x00b"}
	unsafe = append(unsafe, "CON", "nul", "Aux", "COM1", "COM0", "LPT9", "con.txt", "NUL.tar.gz")
	for _, k := range unsafe {
		if err := fs.put(k, []byte("x")); err == nil {
			t.Fatalf("put(%q) accepted an unsafe key", k)
		}
		if fs.has(k) || fs.size(k) != -1 || fs.get(k) != nil || fs.delete(k) {
			t.Fatalf("unsafe key %q resolved on read/delete", k)
		}
	}
}

func TestNodeFsNoEscape(t *testing.T) {
	parent := t.TempDir()
	fs, _ := newNodeFs(filepath.Join(parent, "data"))
	_ = fs.put("../pwned", []byte("nope")) // rejected
	if _, err := os.Stat(filepath.Join(parent, "pwned")); err == nil {
		t.Fatal("unsafe key escaped the data directory")
	}
}

// The `fs` object exposed into the realm presents the host/fs.ts shape (Uint8Array
// on a hit, null on a miss) end to end through the QuickJS shim.
func TestFsExposedToRealm(t *testing.T) {
	boot()
	if err := exposeFs(qc, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	res, err := qc.Eval("fs-realm-test.js", qjs.Code(`
		const enc = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));
		const dec = (b) => { let s = ""; for (const x of b) s += String.fromCharCode(x); return s; };
		fs.put("blk1", enc("payload-one"));
		fs.put("blk2", enc("payload-two"));
		[
			dec(fs.get("blk1")),
			fs.get("nope") === null ? "null" : "notnull",
			String(fs.has("blk1")), String(fs.has("nope")),
			String(fs.size("blk1")),
			fs.list("blk").sort().join(","),
			String(fs.delete("blk1")), String(fs.has("blk1")),
			String(fs.stat().used),
		].join("|");
	`))
	if err != nil {
		t.Fatalf("eval: %v", err)
	}
	const want = "payload-one|null|true|false|11|blk1,blk2|true|false|11"
	if got := res.String(); got != want {
		t.Fatalf("fs realm round trip:\n got %q\nwant %q", got, want)
	}
}
