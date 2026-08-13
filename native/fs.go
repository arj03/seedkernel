// fs.go — the Go target's `fs.*` platform primitive: raw bytes under an opaque,
// flat key, one file per key under a data directory named by `__fs.open` (the storage
// twin of the net cap). The host knows nothing about content-addressing or quota —
// those are the storage guest's business, layered on top of these primitives. This
// mirrors host/fs-node.ts (NodeFs) so a Go node's on-disk store behaves like a
// Bun node's. Exposed into QuickJS as an `fs` object with the core/fs.ts `Fs`
// shape, ready for the guest seam to wire as its fs backend.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"seedloader/qjs"
)

// WHICH KEYS ARE LEGAL IS NOT DECIDED HERE. The charset, the bare-dot names and the
// Windows device names are one rule shared by every target — `isSafeFsKey` in
// WASM/core/fs.ts, applied over this backend by `validatedFs` before a key reaches Go.
// It lives there because it is a consensus predicate: which keys a node admits decides
// which blocks it stores and advertises, and a rule INVENTED here is exactly how a Go
// node and a Bun node would come to disagree about their contents.
//
// What this is, is the backstop: a key becomes a filename verbatim under f.dir, so the
// backend refuses anything it could not represent whatever admitted it. It is therefore
// the SAME predicate, transcribed — not a laxer approximation of it. A backstop weaker
// than the rule it stands behind protects against nothing: the previous one passed
// "CON", "NUL.txt" and any Unicode, so a regression in `validatedFs` would have let a
// Windows build's fs.get("CON") open the console device and hang the single event loop
// on a read that never returns. Transcribing it costs a charset loop and a name set,
// and the risk of the copy drifting is bounded by the direction of the check: this
// side may only ever be as strict or stricter, so a drift refuses a key the shared
// rule admits (a visible, local failure) rather than admitting one it refuses (a
// silent divergence in what the node stores).
//
// The empty key is covered by the charset (`+`, one character minimum) and matters
// here for a reason of this layer's own: filepath.Join(dir, "") is the DATA DIRECTORY
// itself, so an unchecked "" would make delete("") an os.Remove of the store.
// The charset's exclusion of '\n' also carries this backend's serialization: list()
// joins keys with '\n' and the shim splits on it.
func fsKeySafe(k string) bool {
	if k == "" || k == "." || k == ".." {
		return false
	}
	// The `SAFE_CHARS` charset, byte-wise: every legal character is ASCII, so a byte
	// outside the set — including every byte of a multi-byte rune — refuses the key,
	// exactly as the shared regex refuses a non-ASCII code point.
	for i := 0; i < len(k); i++ {
		c := k[i]
		ok := c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == '-'
		if !ok {
			return false
		}
	}
	return !reservedDeviceName(k)
}

// reservedDeviceNames are the names Windows resolves to a DEVICE before the request
// ever reaches a filesystem. Refused on every OS, not only Windows, because the key
// space must not depend on where a node runs — the same argument that puts the rule in
// shared JS in the first place (core/fs.ts RESERVED_DEVICE_NAMES).
var reservedDeviceNames = func() map[string]bool {
	m := map[string]bool{"CON": true, "PRN": true, "AUX": true, "NUL": true}
	for i := '0'; i <= '9'; i++ { // COM0/LPT0 are reserved on current Windows too
		m["COM"+string(i)] = true
		m["LPT"+string(i)] = true
	}
	return m
}()

// reservedDeviceName mirrors core/fs.ts isReservedDeviceName: Windows ignores the
// extension, so the stem before the FIRST '.' decides it — "NUL.txt" is still NUL.
// ToUpper is applied to a string the charset above has already proved ASCII.
func reservedDeviceName(k string) bool {
	stem := k
	if d := strings.IndexByte(k, '.'); d >= 0 {
		stem = k[:d]
	}
	return reservedDeviceNames[strings.ToUpper(stem)]
}

// fsTmpPrefix marks the scratch files put() writes before renaming onto a key. It
// carries a '~', which the shared key charset forbids, so a temp name can never collide
// with a real key — and list()/scanUsed() skip it, so an in-flight or crash-orphaned
// temp is never mistaken for a stored block.
const fsTmpPrefix = "~put-"

// stat() answers -1 free bytes: this backend cannot ask the OS for a portable free-disk
// figure, and the sentinel a guest reads is the seam's (FS_AVAILABLE_UNKNOWN,
// core/fs.ts), mapped by the shim — one value on every target, never a Go copy.

// nodeFs is driven only from the single event-loop goroutine (all JS→Go fs calls land
// there), so `used` needs no synchronization. It is the live total size of all regular
// files, seeded by one scan at open and kept current by put/delete so stat() is O(1).
type nodeFs struct {
	dir  string
	used int64
}

func newNodeFs(dir string) (*nodeFs, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	f := &nodeFs{dir: dir}
	f.used = f.scanUsed() // one O(N) walk at open; adjusted incrementally thereafter
	return f, nil
}

// scanUsed sums the size of every regular file in the data dir — the one full walk, run
// at open to seed the cached counter.
func (f *nodeFs) scanUsed() (used int64) {
	entries, _ := os.ReadDir(f.dir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if n := e.Name(); strings.HasPrefix(n, fsTmpPrefix) {
			os.Remove(filepath.Join(f.dir, n)) // temp write orphaned by an earlier crash; reclaim it
			continue
		}
		if fi, err := e.Info(); err == nil {
			used += fi.Size()
		}
	}
	return used
}

// path is the one place a key becomes a filename, so it is also the one place the
// CLOSED store is refused: `f` is nil until `__fs.open` names a directory, and a nil
// receiver here turns every get/size/delete into the same miss they answer for an
// unsafe key. Refusing at the join rather than in each binding means a future caller
// cannot reach the disk by forgetting a guard — and a nil `f.dir` would otherwise join
// to the key alone, i.e. the process's working directory.
func (f *nodeFs) path(key string) (string, bool) {
	if f == nil || !fsKeySafe(key) {
		return "", false
	}
	return filepath.Join(f.dir, key), true
}

func (f *nodeFs) get(key string) []byte {
	p, ok := f.path(key)
	if !ok {
		return nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	return b
}

func (f *nodeFs) put(key string, b []byte) error {
	// Named rather than folded into the unsafe-key error below: "no store" and "bad key"
	// are different operator mistakes, and only one of them is about the key.
	if f == nil {
		return fmt.Errorf("fs: no store opened — a node writes only after --dir is read")
	}
	p, ok := f.path(key)
	if !ok {
		return fmt.Errorf("fs: unsafe key %q", key)
	}
	// One stat of this single file (cheap, O(1)) to learn the old size, so `used` tracks
	// the delta on an overwrite — far cheaper than the O(N) directory walk stat() used to
	// do on every admission check. New key ⇒ old = -1 ⇒ the whole write counts.
	old := int64(-1)
	if fi, err := os.Stat(p); err == nil {
		old = fi.Size()
	}
	// Write atomically (writeFileAtomic): a crash mid-write must not leave a short or
	// corrupt block that size() ≥ 0 still reports as held — the node advertises it, then
	// fails the verification-fetch. A crash can at worst orphan the temp, which scanUsed
	// reclaims at open. No fsync: the property needed is crash-atomicity of the visible
	// block, not power-loss durability (a lost block is content-addressed and simply
	// re-fetched), and an fsync per put would tax the storage hot path.
	if err := writeFileAtomic(p, b, fsTmpPrefix, 0o644); err != nil {
		return err
	}
	if old >= 0 {
		f.used += int64(len(b)) - old
	} else {
		f.used += int64(len(b))
	}
	return nil
}

// writeFileAtomic writes b to path via a sibling temp file + rename, so a reader
// (or a crash) only ever sees the old or the complete new contents — never a
// truncated write. tmpPrefix names the temp file; the store passes fsTmpPrefix,
// whose '~' the shared key charset forbids, so a temp can never collide with a
// real key and list()/scanUsed() can skip it. mode 0 keeps CreateTemp's 0600 (the
// freshness store); otherwise the temp is chmod'd before the rename. Every error
// path closes the handle first, so the caller can remove the temp without leaking
// a descriptor.
func writeFileAtomic(path string, b []byte, tmpPrefix string, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), tmpPrefix+"*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if mode != 0 {
		if err := tmp.Chmod(mode); err != nil {
			tmp.Close()
			os.Remove(name)
			return err
		}
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

func (f *nodeFs) size(key string) int {
	p, ok := f.path(key)
	if !ok {
		return -1
	}
	fi, err := os.Stat(p)
	if err != nil {
		return -1
	}
	return int(fi.Size())
}

func (f *nodeFs) list(prefix string) []string {
	if f == nil {
		return nil
	}
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		return nil
	}
	out := []string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasPrefix(n, fsTmpPrefix) {
			continue // an in-flight or crash-orphaned atomic-put temp, not a real key
		}
		if prefix == "" || strings.HasPrefix(n, prefix) {
			out = append(out, n)
		}
	}
	return out
}

func (f *nodeFs) delete(key string) bool {
	p, ok := f.path(key)
	if !ok {
		return false
	}
	sz := int64(-1)
	if fi, err := os.Stat(p); err == nil {
		sz = fi.Size()
	}
	if os.Remove(p) != nil {
		return false
	}
	if sz > 0 {
		f.used -= sz
	}
	return true
}

// stat returns the cached used-bytes total (maintained by put/delete), avoiding the
// O(N) directory walk the storage guest's per-offer admission check would otherwise pay.
// A closed store holds nothing.
func (f *nodeFs) stat() int64 {
	if f == nil {
		return 0
	}
	return f.used
}

// exposeFs installs `__fs` into the realm: Go byte primitives, ArrayBuffer in and out.
// Shaping them into the async core/fs.ts `Fs` seam (Uint8Array, null for a miss) is
// host/native-shim.ts, and the key rule is applied above that again by the shell
// (`validatedFs`). Go grows with primitives; the reusable interface lives in JS.
//
// The backend starts CLOSED and is pointed at a directory by `__fs.open`. Which
// directory is the operator's `--dir`, and reading the command line is no longer
// something this side does — the shared CLI (host/cli.ts) reads it and opens the store
// before standing a node up. Until then every read answers empty and every write
// refuses, rather than a half-configured node quietly storing blocks somewhere nobody
// asked for.
func exposeFs(qc *qjs.Context) {
	var fs *nodeFs
	o := qc.NewObject()

	o.SetPropertyStr("open", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		f, err := newNodeFs(argString(t, 0))
		if err != nil {
			return nil, err // surfaces as a JS exception: an unusable --dir is fatal
		}
		fs = f
		return t.Context().NewUndefined(), nil
	}))
	o.SetPropertyStr("get", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		b := fs.get(argString(t, 0))
		if b == nil {
			return t.Context().NewNull(), nil
		}
		return t.Context().NewArrayBuffer(b), nil
	}))
	o.SetPropertyStr("put", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		b, err := qjs.JsTypedArrayToGo(t.Args()[1])
		if err != nil {
			return nil, err // non-bytes arg throws, like NodeFs — not a silent empty write
		}
		if err := fs.put(argString(t, 0), b); err != nil {
			return nil, err // surfaces as a JS exception, like NodeFs writeFileSync
		}
		return t.Context().NewUndefined(), nil
	}))
	o.SetPropertyStr("size", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		// NewInt64, not NewInt32: fs.size returns a 64-bit length, and a ≥2 GiB file
		// would wrap to a negative int32 and read back as "missing" (-1). (-1 itself,
		// the genuine miss, is unaffected.)
		return t.Context().NewInt64(int64(fs.size(argString(t, 0)))), nil
	}))
	o.SetPropertyStr("list", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		prefix := ""
		if len(t.Args()) > 0 && !t.Args()[0].IsUndefined() && !t.Args()[0].IsNull() {
			prefix = argString(t, 0)
		}
		// One \n-joined string, split back into an array by the shim: building a JS
		// array here costs an engine call (plus a C string) per key, so a content store
		// with tens of thousands of blocks paid tens of thousands of crossings per
		// listing. The shared key charset (core/fs.ts) forbids '\n', so the join is
		// unambiguous.
		return t.Context().NewString(strings.Join(fs.list(prefix), "\n")), nil
	}))
	o.SetPropertyStr("delete", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		return t.Context().NewBool(fs.delete(argString(t, 0))), nil
	}))
	o.SetPropertyStr("stat", bridgeFn(qc, func(t *qjs.This) (*qjs.Value, error) {
		s := t.Context().NewObject()
		s.SetPropertyStr("used", t.Context().NewInt64(fs.stat()))
		s.SetPropertyStr("available", t.Context().NewInt64(-1)) // unknown — the shim maps it to FS_AVAILABLE_UNKNOWN
		return s, nil
	}))
	qc.Global().SetPropertyStr("__fs", o)
}

// Go stops at the primitive. The shaping — get's null/Uint8Array, list's \n-joined string
// back into a string[] — and the wrap that presents it as the async `Fs` seam (core/fs.ts)
// both live in host/native-shim.ts. Both are adaptation rather than platform, so both
// belong on the shared side of the line: Go grows with primitives, never with logic.
