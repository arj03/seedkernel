// fs.go — the Go target's `fs.*` platform primitive: raw bytes under an opaque,
// flat key, one file per key under a data directory (the storage twin of the net
// cap). The kernel knows nothing about content-addressing or quota —
// those are the storage guest's business, layered on top of these primitives. This
// mirrors host/fs-node.ts (NodeFs) so a Go node's on-disk store behaves like a
// Bun node's. Exposed into QuickJS as an `fs` object with the host/fs.ts `Fs`
// shape, ready for the cap-bridge to wire as its fs backend.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"seedloader/qjs"
)

// A key becomes a filename verbatim, so it must be safe + flat: no separators,
// nothing that could escape the directory. RE2 has no lookahead, so the bare dot
// names (directory references, not files) are excluded explicitly. seedstore's keys
// (hex block-ids + a short suffix) satisfy this.
var fsKeyChars = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

func fsKeySafe(k string) bool { return k != "." && k != ".." && fsKeyChars.MatchString(k) }

// fsMaxAvailable mirrors fs-node.ts's fallback (Number.MAX_SAFE_INTEGER): a large
// sentinel for free space, since portable free-disk queries need a syscall per OS
// and the storage guest only needs a monotone budget signal, not an exact figure.
const fsMaxAvailable = 1<<53 - 1

type nodeFs struct{ dir string }

func newNodeFs(dir string) (*nodeFs, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &nodeFs{dir}, nil
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
	return os.WriteFile(p, b, 0o644)
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

func (f *nodeFs) has(key string) bool { return f.size(key) >= 0 }

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
		if n := e.Name(); prefix == "" || strings.HasPrefix(n, prefix) {
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
	return os.Remove(p) == nil
}

func (f *nodeFs) stat() (used int64) {
	entries, _ := os.ReadDir(f.dir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if fi, err := e.Info(); err == nil {
			used += fi.Size()
		}
	}
	return used
}

// exposeFs installs the `fs` object into the realm: Go byte primitives (ArrayBuffer
// in / out) wrapped by a thin JS shim into the host/fs.ts `Fs` shape (Uint8Array,
// null for a miss). Keeping bytes in Go and the API shape in JS follows the project
// rule — Go grows with primitives, the reusable interface lives in JS.
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
		b, _ := qjs.JsTypedArrayToGo(t.Args()[1])
		if err := fs.put(str(t, 0), b); err != nil {
			return nil, err // surfaces as a JS exception, like NodeFs writeFileSync
		}
		return t.Context().NewUndefined(), nil
	}))
	o.SetPropertyStr("has", fn(func(t *qjs.This) (*qjs.Value, error) {
		return t.Context().NewBool(fs.has(str(t, 0))), nil
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
		arr := t.Context().NewArray()
		for _, k := range fs.list(prefix) {
			arr.Push(t.Context().NewString(k))
		}
		return arr.Value, nil
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
	if _, err := qc.Eval("fs-shim.js", qjs.Code(fsShimJS)); err != nil {
		return fmt.Errorf("fs shim: %w", err)
	}
	return nil
}

// fsShimJS shapes the Go primitives into the host/fs.ts `Fs` interface the
// cap-bridge consumes: a get miss is null, a hit is a Uint8Array. The rest
// (put/has/size/list/delete/stat) pass straight through.
const fsShimJS = `
"use strict";
(function () {
  const N = __fs;
  globalThis.fs = {
    get: (key) => { const r = N.get(key); return r === null ? null : new Uint8Array(r); },
    put: (key, bytes) => N.put(key, bytes),
    has: (key) => N.has(key),
    size: (key) => N.size(key),
    list: (prefix) => N.list(prefix),
    delete: (key) => N.delete(key),
    stat: () => N.stat(),
  };
})();
`
