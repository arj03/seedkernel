package main

// Reed–Solomon codec perf for the Go loader. RS isn't a libsodium primitive — it
// lives in the seedstore repo's codec.wasm (AssemblyScript GF(2^8) erasure coding) —
// but the loader runs that same wasm through the installed `seedstore.codec` handler,
// so its encode/decode throughput is comparable runtime-to-runtime against the node
// numbers from seedstore/WASM/tests/bench.mjs. Same shape as that bench: RS(10,6),
// 64 KB blocks, 640 KB of data per chunk; throughput is reported over data bytes
// (b.SetBytes(k*bs)), matching bench.mjs's rate() which divides by the data size.
//
// Needs the seedstore bundle built (loader_test.go's default path, or SEEDSTORE_BUNDLE);
// the benchmarks Skip if it isn't there.
//
//	go test -run x -bench 'BenchmarkRS' -benchmem ./...

import (
	"bytes"
	"encoding/binary"
	"os"
	"strings"
	"sync"
	"testing"
)

const (
	rsK  = 10        // data blocks  (RS(10,6), the seedstore default §4.1)
	rsM  = 6         // parity blocks
	rsBS = 64 * 1024 // block size → 640 KB data / 384 KB parity per chunk
)

var (
	rsOnce      sync.Once
	rsCodecName []byte
	rsEncodeReq []byte // [OP_ENCODE][k][m][bs BE][640 KB data]
	rsDecodeReq []byte // [OP_DECODE][k][m][bs BE][cnt][rowIdx][blocks] — block 0 lost
	rsReady     bool
)

// setupRS loads the seedstore bundle (installing seedstore.codec) and stages a fixed
// encode request plus a "one data block lost" decode request — the §21 single-loss
// read path, identical to bench.mjs's decode case (surviving data rows 1..k-1 plus
// the first parity row). Both requests are validated once before timing.
func setupRS() {
	ensureBooted()
	dir := os.Getenv("SEEDSTORE_BUNDLE")
	if dir == "" {
		dir = "../../../seedstore/WASM/bundle"
	}
	if !strings.HasPrefix(loadBundle(dir), "seedstore v1") {
		return // rsReady stays false → the benchmarks Skip
	}
	rsCodecName = name("seedstore.codec")

	// 640 KB of deterministic data (content is irrelevant to RS timing; this is the
	// same cheap fill bench.mjs uses).
	data := make([]byte, rsK*rsBS)
	for i := range data {
		data[i] = byte(i*1103515245 + 12345)
	}

	rsEncodeReq = make([]byte, 7+len(data))
	rsEncodeReq[0], rsEncodeReq[1], rsEncodeReq[2] = 1, rsK, rsM // OP_ENCODE
	binary.BigEndian.PutUint32(rsEncodeReq[3:7], rsBS)
	copy(rsEncodeReq[7:], data)

	parity := run(rsCodecName, rsEncodeReq)
	if len(parity) != rsM*rsBS {
		return
	}

	// Decode with data block 0 missing: rows 1..k-1 (surviving data) + row k (first
	// parity) = k rows, the minimum basis the codec needs to rebuild all k data rows.
	cnt := rsK
	rsDecodeReq = make([]byte, 8+cnt+cnt*rsBS)
	rsDecodeReq[0], rsDecodeReq[1], rsDecodeReq[2] = 2, rsK, rsM // OP_DECODE
	binary.BigEndian.PutUint32(rsDecodeReq[3:7], rsBS)
	rsDecodeReq[7] = byte(cnt)
	rows := rsDecodeReq[8 : 8+cnt]
	blocks := rsDecodeReq[8+cnt:]
	for r := 0; r < rsK-1; r++ { // surviving data rows 1..k-1
		rows[r] = byte(r + 1)
		copy(blocks[r*rsBS:], data[(r+1)*rsBS:(r+2)*rsBS])
	}
	rows[rsK-1] = byte(rsK) // first parity row (index k)
	copy(blocks[(rsK-1)*rsBS:], parity[:rsBS])

	out := run(rsCodecName, rsDecodeReq)
	if len(out) != rsK*rsBS || !bytes.Equal(out[:rsBS], data[:rsBS]) {
		return // decode didn't reconstruct the lost block — don't report a bogus rate
	}
	rsReady = true
}

func BenchmarkRSEncode(b *testing.B) {
	rsOnce.Do(setupRS)
	if !rsReady {
		b.Skip("seedstore bundle not built (set SEEDSTORE_BUNDLE)")
	}
	b.SetBytes(rsK * rsBS)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		run(rsCodecName, rsEncodeReq)
	}
}

func BenchmarkRSDecode(b *testing.B) {
	rsOnce.Do(setupRS)
	if !rsReady {
		b.Skip("seedstore bundle not built (set SEEDSTORE_BUNDLE)")
	}
	b.SetBytes(rsK * rsBS)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		run(rsCodecName, rsDecodeReq)
	}
}
