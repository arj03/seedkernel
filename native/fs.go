// fs.go — the Go target's `fs.*` platform primitive: raw bytes under an opaque,
// flat key, one file per key under a data directory (the storage twin of the net
// cap). The kernel knows nothing about content-addressing or quota —
// those are the storage guest's business, layered on top of these primitives. This
// mirrors host/fs-node.ts (NodeFs) so a Go node's on-disk store behaves like a
// Bun node's. Exposed into QuickJS as an `fs` object with the core/fs.ts `Fs`
// shape, ready for the cap-bridge to wire as its fs backend.
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
// which blocks it stores and advertises, and a second copy here is exactly how a Go
// node and a Bun node would come to disagree about their contents. This file used to
// carry that copy, under a comment saying the two had to match.
//
// What stays is containment, which is this backend's own business: a key becomes a
// filename verbatim under f.dir, so anything that could name something outside it is
// refused whatever admitted it. Defence in depth, not the rule being relied on.
// The empty key is refused first and explicitly: filepath.Join(dir, "") is the DATA
// DIRECTORY itself, so an unchecked "" would make delete("") an os.Remove of the store.
func fsKeySafe(k string) bool {
	return k != "" && k != "." && k != ".." && !strings.ContainsAny(k, `/\`) && !strings.ContainsRune(k, 0)
}

// fsTmpPrefix marks the scratch files put() writes before renaming onto a key. It
// carries a '~', which the shared key charset forbids, so a temp name can never collide
// with a real key — and list()/scanUsed() skip it, so an in-flight or crash-orphaned
// temp is never mistaken for a stored block.
const fsTmpPrefix = "~put-"

// fsMaxAvailable mirrors fs-node.ts's fallback (Number.MAX_SAFE_INTEGER): a large
// sentinel for free space, since portable free-disk queries need a syscall per OS
// and the storage guest only needs a monotone budget signal, not an exact figure.
const fsMaxAvailable = 1<<53 - 1

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

func (f *nodeFs) path(key string) (string, bool) {
	if !fsKeySafe(key) {
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
	// Write atomically: land the bytes in a temp file, then rename onto the key. os.WriteFile
	// truncates the key in place, so a crash mid-write would leave a short/corrupt block that
	// size() ≥ 0 still reports as held — the node advertises it, then fails the verification-fetch.
	// Rename swaps the whole file in one step (atomic within a dir on POSIX; MoveFileEx with
	// REPLACE_EXISTING on Windows), so a reader only ever sees the old or the complete new
	// block. A crash can at worst orphan the temp file, which scanUsed reclaims at open. We
	// skip fsync: the property needed is crash-atomicity of the visible block, not power-loss
	// durability (a lost block is content-addressed and simply re-fetched), and an fsync per
	// put would tax the storage hot path.
	tmp, err := os.CreateTemp(f.dir, fsTmpPrefix+"*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if err := writeTemp(tmp, b); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, p); err != nil {
		os.Remove(name)
		return err
	}
	if old >= 0 {
		f.used += int64(len(b)) - old
	} else {
		f.used += int64(len(b))
	}
	return nil
}

// writeTemp fills the freshly-created temp file, restores the 0o644 mode os.WriteFile
// used before (CreateTemp opens 0o600), and closes it. Every error path closes the
// handle first so the caller can remove the temp without leaking a descriptor.
func writeTemp(tmp *os.File, b []byte) error {
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	return tmp.Close()
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
func (f *nodeFs) stat() int64 { return f.used }

// exposeFs installs `__fs` into the realm: Go byte primitives, ArrayBuffer in and out.
// Shaping them into the async core/fs.ts `Fs` seam (Uint8Array, null for a miss) is
// host/native-shim.ts, and the key rule is applied above that again by the shell
// (`validatedFs`). Go grows with primitives; the reusable interface lives in JS.
func exposeFs(qc *qjs.Context, dir string) error {
	fs, err := newNodeFs(dir)
	if err != nil {
		return err
	}
	o := qc.NewObject()
	fn := func(g func(*qjs.This) (*qjs.Value, error)) *qjs.Value { return qc.Function(g) }
	str := func(t *qjs.This, i int) string { return t.Args()[i].String() }

	o.SetPropertyStr("get", fn(func(t *qjs.This) (*qjs.Value, error) {
		b := fs.get(str(t, 0))
		if b == nil {
			return t.Context().NewNull(), nil
		}
		return t.Context().NewArrayBuffer(b), nil
	}))
	o.SetPropertyStr("put", fn(func(t *qjs.This) (*qjs.Value, error) {
		b, err := qjs.JsTypedArrayToGo(t.Args()[1])
		if err != nil {
			return nil, err // non-bytes arg throws, like NodeFs — not a silent empty write
		}
		if err := fs.put(str(t, 0), b); err != nil {
			return nil, err // surfaces as a JS exception, like NodeFs writeFileSync
		}
		return t.Context().NewUndefined(), nil
	}))
	o.SetPropertyStr("size", fn(func(t *qjs.This) (*qjs.Value, error) {
		// NewInt64, not NewInt32: fs.size returns a 64-bit length, and a ≥2 GiB file
		// would wrap to a negative int32 and read back as "missing" (-1). (-1 itself,
		// the genuine miss, is unaffected.)
		return t.Context().NewInt64(int64(fs.size(str(t, 0)))), nil
	}))
	o.SetPropertyStr("list", fn(func(t *qjs.This) (*qjs.Value, error) {
		prefix := ""
		if len(t.Args()) > 0 && !t.Args()[0].IsUndefined() && !t.Args()[0].IsNull() {
			prefix = str(t, 0)
		}
		// One \n-joined string, split back into an array by the shim: building a JS
		// array here costs an engine call (plus a C string) per key, so a content store
		// with tens of thousands of blocks paid tens of thousands of crossings per
		// listing. The shared key charset (core/fs.ts) forbids '\n', so the join is
		// unambiguous.
		return t.Context().NewString(strings.Join(fs.list(prefix), "\n")), nil
	}))
	o.SetPropertyStr("delete", fn(func(t *qjs.This) (*qjs.Value, error) {
		return t.Context().NewBool(fs.delete(str(t, 0))), nil
	}))
	o.SetPropertyStr("stat", fn(func(t *qjs.This) (*qjs.Value, error) {
		s := t.Context().NewObject()
		s.SetPropertyStr("used", t.Context().NewInt64(fs.stat()))
		s.SetPropertyStr("available", t.Context().NewInt64(fsMaxAvailable))
		return s, nil
	}))
	qc.Global().SetPropertyStr("__fs", o)
	return nil
}

// Go stops at the primitive. The shaping — get's null/Uint8Array, list's \n-joined string
// back into a string[] — and the wrap that presents it as the async `Fs` seam (core/fs.ts)
// both live in host/native-shim.ts. Both are adaptation rather than platform, so both
// belong on the shared side of the line: Go grows with primitives, never with logic.
