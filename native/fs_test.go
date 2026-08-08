package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"seedloader/qjs"
)

func TestNodeFsRoundTrip(t *testing.T) {
	fs, err := newNodeFs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if fs.size("k1") != -1 || fs.get("k1") != nil {
		t.Fatal("a missing key should read as absent")
	}

	val := []byte("hello world")
	if err := fs.put("k1", val); err != nil {
		t.Fatal(err)
	}
	if fs.size("k1") != len(val) {
		t.Fatalf("after put: size=%d", fs.size("k1"))
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

	if !fs.delete("k1") || fs.size("k1") != -1 {
		t.Fatal("delete should remove the key")
	}
	if fs.delete("k1") {
		t.Fatal("delete of an absent key should report false")
	}
}

// Containment: a key that could name something other than a plain file inside the data
// directory is rejected on write and never resolves on read/delete. This is the whole of
// what this backend decides. WHICH keys are legal — the charset, and the Windows device
// names like CON/NUL/COM1 — is `isSafeFsKey` in WASM/core/fs.ts, one rule for every
// target, applied before a key reaches Go and tested there ("fs key space is one rule",
// WASM/tests/run.mjs). A copy of it here is what used to let the two drift.
//
// "" is in the list for a reason that is this layer's alone: filepath.Join(dir, "") is
// the data directory itself, so an unchecked empty key makes delete("") remove the store.
func TestNodeFsRejectsUnsafeKeys(t *testing.T) {
	fs, _ := newNodeFs(t.TempDir())
	unsafe := []string{"", ".", "..", "a/b", "../escape", `a\b`, "a\x00b", "a\nb"}
	for _, k := range unsafe {
		if err := fs.put(k, []byte("x")); err == nil {
			t.Fatalf("put(%q) accepted an unsafe key", k)
		}
		if fs.size(k) != -1 || fs.get(k) != nil || fs.delete(k) {
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

// The `fs` seam the shared code consumes (core/fs.ts) presents its shape — Uint8Array on
// a hit, null on a miss — end to end over Go's synchronous primitive.
//
// Every call awaits, because the seam is async on every target: a synchronous `get` is a
// shape no browser backend can implement, so it is not one the native target may offer
// either. Go still answers from the disk in the call; the wrap that makes that a promise
// is host/native-shim.ts, and this drives it rather than a copy of it.
func TestFsExposedToRealm(t *testing.T) {
	bootRealm(t) // opens a store on a fresh temp dir, the way --dir does
	if _, err := qc.Eval("fs-realm-test.js", qjs.Code(`
		const enc = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));
		const dec = (b) => { let s = ""; for (const x of b) s += String.fromCharCode(x); return s; };
		globalThis.__fsProbe = async () => {
			await fs.put("blk1", enc("payload-one"));
			await fs.put("blk2", enc("payload-two"));
			return enc([
				dec(await fs.get("blk1")),
				(await fs.get("nope")) === null ? "null" : "notnull",
				String(await fs.size("blk1")), String(await fs.size("nope")),
				(await fs.list("blk")).sort().join(","),
				String((await fs.list("zzz")).length),
				String(await fs.delete("blk1")), String(await fs.size("blk1")),
				String((await fs.stat()).used),
			].join("|"));
		};
	`)); err != nil {
		t.Fatalf("eval: %v", err)
	}
	got, err := callRealm("__fsProbe", 5*time.Second)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	// Existence is size ≥ 0 now (no `has`): present blk1 = 11, absent = -1.
	const want = "payload-one|null|11|-1|blk1,blk2|0|true|-1|11"
	if string(got) != want {
		t.Fatalf("fs realm round trip:\n got %q\nwant %q", string(got), want)
	}
}

// A realm whose store has not been opened is CLOSED — not pointed at the process's
// working directory.
//
// `--dir` is the operator's, and Go no longer reads the command line to find it: the
// shared CLI does, and calls `openStore` on its way to standing a node up. That leaves a
// window in which `__fs` exists and has no directory, and the honest answer there is an
// empty store that refuses writes. The failure this pins is the quiet one — a nil
// backend joining a key to no directory yields the key itself, i.e. blocks scattered
// into whatever directory the binary was started from.
func TestFsClosedUntilOpened(t *testing.T) {
	if err := boot(); err != nil { // deliberately no openStore
		t.Fatal("boot:", err)
	}
	if _, err := qc.Eval("fs-closed-test.js", qjs.Code(`
		globalThis.__fsClosedProbe = () => {
			let put = "accepted";
			try { __fs.put("blk", new Uint8Array([1])); } catch (e) { put = "refused"; }
			return [
				__fs.get("blk") === null ? "null" : "notnull",
				String(__fs.size("blk")),
				JSON.stringify(__fs.list("")),
				String(__fs.delete("blk")),
				String(__fs.stat().used),
				put,
			].join("|");
		};
	`)); err != nil {
		t.Fatalf("eval: %v", err)
	}
	const want = `null|-1|""|false|0|refused`
	if got := evalString(t, "__fsClosedProbe()"); got != want {
		t.Fatalf("closed store:\n got %q\nwant %q", got, want)
	}
	// And nothing was written where the process happens to be running.
	if _, err := os.Stat("blk"); err == nil {
		os.Remove("blk")
		t.Fatal("a closed store wrote into the working directory")
	}
}
