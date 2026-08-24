package main

// Reed–Solomon codec perf for the Go loader. RS lives in seedstore's codec.wasm;
// this benchmark signs it into a tiny app and calls it through the loaded guest, the
// same private-module path a deployment uses. The request shape matches
// seedstore/WASM/tests/bench.mjs: RS(10,6), 64 KB blocks and 640 KB of data per chunk.
//
// Opt-in, since the loader has no seedstore dependency: with SEEDSTORE_CODEC unset these
// benchmarks skip.
//
//	SEEDSTORE_CODEC=/path/to/seedstore/WASM/build/codec.wasm go test -run x -bench 'BenchmarkRS' -benchmem ./...
//
// With the variable set, every setup failure is fatal. An explicitly requested benchmark
// must not silently decline because its external artifact is stale or unusable.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	rsK  = 10        // data blocks (RS(10,6), the seedstore default §4.1)
	rsM  = 6         // parity blocks
	rsBS = 64 * 1024 // block size → 640 KB data / 384 KB parity per chunk
)

var (
	rsOnce      sync.Once
	rsAppKey    string
	rsEncodeReq []byte // [OP_ENCODE][k][m][bs BE][640 KB data]
	rsDecodeReq []byte // [OP_DECODE][k][m][bs BE][cnt][rowIdx][blocks] — block 0 lost
	rsReady     bool
	rsSetupErr  error // non-nil ⇒ SEEDSTORE_CODEC was set but unusable: fail, don't skip
)

// invokeApp prefixes the host caller identity and its test op-frame. The guest removes
// both before handing the codec its private payload. Returning the Promise is the async
// guest ABI.
const rsBenchGuestSource = `async function handle(arg) {
	const opLen = arg.length > 32 ? arg[32] : -1;
	return await host.call("codec", arg.subarray(33 + opLen));
}`

// setupRS loads a benchmark app containing codec.wasm and stages a fixed encode request
// plus a one-data-block-lost decode request. Both are validated once before timing.
func setupRS(tb testing.TB) {
	ensureBooted(tb)

	path := os.Getenv("SEEDSTORE_CODEC")
	if path == "" {
		return
	}
	codec, err := os.ReadFile(path)
	if err != nil {
		rsSetupErr = fmt.Errorf("SEEDSTORE_CODEC=%s: %w", path, err)
		return
	}

	const app = "rsbench"
	author := testAuthor(tb)
	if err := applyPolicy(`{"authors":["` + hex.EncodeToString(author.id()) + `"]}`); err != nil {
		rsSetupErr = fmt.Errorf("applyPolicy: %w", err)
		return
	}
	blob := signedModuleBundleBytes(tb, author, app, 1, rsBenchGuestSource, nil, "codec", codec)
	bundlePath := filepath.Join(tb.TempDir(), app+".skb")
	if err := os.WriteFile(bundlePath, blob, 0o644); err != nil {
		rsSetupErr = fmt.Errorf("write benchmark bundle: %w", err)
		return
	}
	if status := loadBundle(bundlePath); !strings.HasPrefix(status, app+" v") {
		rsSetupErr = fmt.Errorf("loadBundle(%s): %s", bundlePath, status)
		return
	}
	rsAppKey = appKeyFor(author.id(), app)

	data := make([]byte, rsK*rsBS)
	for i := range data {
		data[i] = byte(i*1103515245 + 12345)
	}

	rsEncodeReq = make([]byte, 7+len(data))
	rsEncodeReq[0], rsEncodeReq[1], rsEncodeReq[2] = 1, rsK, rsM // OP_ENCODE
	binary.BigEndian.PutUint32(rsEncodeReq[3:7], rsBS)
	copy(rsEncodeReq[7:], data)

	parity, err := invokeBundle(rsAppKey, rsEncodeReq)
	if err != nil {
		rsSetupErr = fmt.Errorf("encode via %s: %w", rsAppKey, err)
		return
	}
	if len(parity) != rsM*rsBS {
		rsSetupErr = fmt.Errorf("encode via %s returned %d B, want %d", rsAppKey, len(parity), rsM*rsBS)
		return
	}

	// Rows 1..k-1 plus the first parity row are the minimum basis needed to rebuild row 0.
	cnt := rsK
	rsDecodeReq = make([]byte, 8+cnt+cnt*rsBS)
	rsDecodeReq[0], rsDecodeReq[1], rsDecodeReq[2] = 2, rsK, rsM // OP_DECODE
	binary.BigEndian.PutUint32(rsDecodeReq[3:7], rsBS)
	rsDecodeReq[7] = byte(cnt)
	rows, blocks := rsDecodeReq[8:8+cnt], rsDecodeReq[8+cnt:]
	for r := 0; r < rsK-1; r++ {
		rows[r] = byte(r + 1)
		copy(blocks[r*rsBS:], data[(r+1)*rsBS:(r+2)*rsBS])
	}
	rows[rsK-1] = byte(rsK)
	copy(blocks[(rsK-1)*rsBS:], parity[:rsBS])

	out, err := invokeBundle(rsAppKey, rsDecodeReq)
	if err != nil {
		rsSetupErr = fmt.Errorf("decode via %s: %w", rsAppKey, err)
		return
	}
	if len(out) != rsK*rsBS || !bytes.Equal(out[:rsBS], data[:rsBS]) {
		rsSetupErr = fmt.Errorf("decode via %s did not reconstruct block 0 (%d B out)", rsAppKey, len(out))
		return
	}
	rsReady = true
}

func requireRS(b *testing.B) {
	b.Helper()
	rsOnce.Do(func() { setupRS(b) })
	if rsSetupErr != nil {
		b.Fatalf("SEEDSTORE_CODEC is set but the bench could not run: %v", rsSetupErr)
	}
	if !rsReady {
		b.Skip("seedstore codec not built (set SEEDSTORE_CODEC)")
	}
}

func BenchmarkRSEncode(b *testing.B) {
	requireRS(b)
	b.SetBytes(rsK * rsBS)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := invokeBundle(rsAppKey, rsEncodeReq); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRSDecode(b *testing.B) {
	requireRS(b)
	b.SetBytes(rsK * rsBS)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := invokeBundle(rsAppKey, rsDecodeReq); err != nil {
			b.Fatal(err)
		}
	}
}
