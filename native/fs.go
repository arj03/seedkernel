// The `fs.*` primitive: one file per flat key under the data directory `__fs.open` names.
// Mirrors services/fs-node.ts (NodeFs).
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"seedkernel/qjs"
)

// fsKeySafe is only a containment backstop for the host's direct handle; the key policy
// is services/fs.ts isSafeFsKey. Empty names the store directory itself.
func fsKeySafe(k string) bool {
	return k != "" && k != "." && k != ".." && !strings.ContainsAny(k, `/\`)
}

// fsTmpPrefix marks put()'s temp files; '~' is outside the key charset.
const fsTmpPrefix = "~put-"

// nodeFs runs on the loop goroutine. `used` is the total size of its files, seeded at
// open and kept by put/delete.
type nodeFs struct {
	dir  string
	used int64
}

func newNodeFs(dir string) (*nodeFs, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	f := &nodeFs{dir: dir}
	used, err := f.scanUsed()
	if err != nil {
		return nil, err
	}
	f.used = used
	return f, nil
}

// scanUsed sums every regular file's size and reclaims temps orphaned by a crash.
func (f *nodeFs) scanUsed() (used int64, err error) {
	entries, err := os.ReadDir(f.dir)
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if n := e.Name(); strings.HasPrefix(n, fsTmpPrefix) {
			os.Remove(filepath.Join(f.dir, n)) // best effort
			continue
		}
		fi, err := e.Info()
		if err != nil {
			return 0, err
		}
		if fi.Mode().IsRegular() {
			used += fi.Size()
		}
	}
	return used, nil
}

// path maps a key to its file. A nil (unopened) store misses every key.
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
	if f == nil {
		return fmt.Errorf("fs: no store opened — a node writes only after --dir is read")
	}
	p, ok := f.path(key)
	if !ok {
		return fmt.Errorf("fs: unsafe key %q", key)
	}
	// Atomic but not fsynced: a lost block is re-fetched, a torn one would be served.
	old := regularSize(p)
	if err := writeFileAtomic(p, b, fsTmpPrefix, 0o644); err != nil {
		return err
	}
	f.used += int64(len(b)) - old
	return nil
}

// regularSize is the regular file at p's size, or 0.
func regularSize(p string) int64 {
	if fi, err := os.Lstat(p); err == nil && fi.Mode().IsRegular() {
		return fi.Size()
	}
	return 0
}

// writeFileAtomic writes b via a sibling temp file and rename. Mode 0 keeps CreateTemp's
// 0600.
func writeFileAtomic(path string, b []byte, tmpPrefix string, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), tmpPrefix+"*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(b)
	if err == nil && mode != 0 {
		err = tmp.Chmod(mode)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
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
			continue
		}
		if strings.HasPrefix(n, prefix) {
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
	sz := regularSize(p)
	if os.Remove(p) != nil {
		return false
	}
	f.used -= sz
	return true
}

// stat returns the cached used-bytes total.
func (f *nodeFs) stat() int64 {
	if f == nil {
		return 0
	}
	return f.used
}

// exposeFs installs `__fs`, shaped into the async `Fs` seam by host/native-shim.ts. It
// stays closed until `__fs.open` names the operator's `--dir`.
func exposeFs(qc *qjs.Context) {
	var fs *nodeFs
	o := qc.NewObject()

	o.SetPropertyStr("open", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		f, err := newNodeFs(args[0].String())
		if err != nil {
			return nil, err
		}
		fs = f
		return qc.NewUndefined(), nil
	}))
	o.SetPropertyStr("get", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		b := fs.get(args[0].String())
		if b == nil {
			return qc.NewNull(), nil
		}
		return qc.NewArrayBuffer(b), nil
	}))
	o.SetPropertyStr("put", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		// Bytes borrowed last (qjs.Value.View).
		key := args[0].String()
		b, err := args[1].View()
		if err != nil {
			return nil, err
		}
		if err := fs.put(key, b); err != nil {
			return nil, err
		}
		return qc.NewUndefined(), nil
	}))
	o.SetPropertyStr("size", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		return qc.NewInt64(int64(fs.size(args[0].String()))), nil
	}))
	o.SetPropertyStr("list", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		prefix := ""
		if len(args) > 0 && !args[0].IsUndefined() && !args[0].IsNull() {
			prefix = args[0].String()
		}
		// \n-joined, split by the shim; the key charset forbids '\n'.
		return qc.NewString(strings.Join(fs.list(prefix), "\n")), nil
	}))
	o.SetPropertyStr("delete", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		return qc.NewBool(fs.delete(args[0].String())), nil
	}))
	o.SetPropertyStr("stat", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		s := qc.NewObject()
		s.SetPropertyStr("used", qc.NewInt64(fs.stat()))
		// No portable free-disk figure; the shim maps -1 to FS_AVAILABLE_UNKNOWN.
		s.SetPropertyStr("available", qc.NewInt64(-1))
		return s, nil
	}))
	qc.Global().SetPropertyStr("__fs", o)
}
