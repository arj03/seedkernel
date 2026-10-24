// The `__fs` primitive: whole files by path (WASM/services/fs-files.ts RawFiles). The key
// store a node keeps in them is shared JS; this is only the OS underneath.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"seedkernel/qjs"
)

// writeFileAtomic writes b via a sibling temp file and rename: atomic but not fsynced, so a
// crash leaves the old file or the new one, and perhaps the temp, whose name starts with
// `~`. CreateTemp makes it 0600: readable by this user alone.
func writeFileAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "~"+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(b)
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

// exposeFs installs `__fs`, typed in host/abi.ts.
func exposeFs(qc *qjs.Context) {
	o := qc.NewObject()
	o.SetPropertyStr("mkdir", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		return nil, os.MkdirAll(args[0].String(), 0o755)
	}))
	o.SetPropertyStr("read", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		// Only absence maps to null; every other failure throws.
		path, limit := args[0].String(), args[1].Int64()
		f, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			return qc.NewNull(), nil
		} else if err != nil {
			return nil, err
		}
		defer f.Close()
		// Refused before it is read, so a file planted in the store cannot become a host
		// allocation.
		fi, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if !fi.Mode().IsRegular() || fi.Size() > limit {
			return nil, fmt.Errorf("%s: not a regular file of at most %d bytes", path, limit)
		}
		b := make([]byte, fi.Size())
		if _, err := io.ReadFull(f, b); err != nil {
			return nil, err
		}
		return qc.NewArrayBuffer(b), nil
	}))
	o.SetPropertyStr("write", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		// Bytes borrowed last (qjs.Value.View).
		path := args[0].String()
		b, err := args[1].View()
		if err != nil {
			return nil, err
		}
		return nil, writeFileAtomic(path, b)
	}))
	o.SetPropertyStr("remove", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		return qc.NewBool(os.Remove(args[0].String()) == nil), nil
	}))
	o.SetPropertyStr("size", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		fi, err := os.Stat(args[0].String())
		if err != nil || !fi.Mode().IsRegular() {
			return qc.NewInt32(-1), nil
		}
		return qc.NewInt64(fi.Size()), nil
	}))
	o.SetPropertyStr("list", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		entries, err := os.ReadDir(args[0].String())
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			if !e.IsDir() {
				names = append(names, e.Name())
			}
		}
		// \n-joined; a key cannot contain '\n'.
		return qc.NewString(strings.Join(names, "\n")), nil
	}))
	o.SetPropertyStr("available", qc.Function(func(qc *qjs.Context, args []*qjs.Value) (*qjs.Value, error) {
		// No portable free-disk figure.
		return qc.NewInt32(-1), nil
	}))
	qc.Global().SetPropertyStr("__fs", o)
}
