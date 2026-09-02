package main

import (
	"os"
	"sync"
	"testing"
)

// One boot for the whole benchmark run. boot() is a process-wide singleton — a second
// one tears down the realm, and with it the module table a benchmark already staged
// its module into — so every benchmark that needs a realm shares this one. Go runs all
// tests before all benchmarks, so the fresh-realm boots the tests do are long finished
// by the time this fires.
var (
	benchBootOnce sync.Once
	benchBootErr  error
	benchDataDir  string
)

// ensureBooted stands the shared benchmark realm up (and a node in it, so a bench can
// load a bundle) on first use.
func ensureBooted(tb testing.TB) {
	tb.Helper()
	benchBootOnce.Do(func() {
		dir, err := os.MkdirTemp("", "seedloader-bench-")
		if err != nil {
			benchBootErr = err
			return
		}
		benchDataDir = dir
		if benchBootErr = boot(); benchBootErr != nil {
			return
		}
		evalString(tb, "openStore("+jsonString(dir)+")")
		cfg := nodeConfig{KeyHex: testKeyHex(tb)}
		_, benchBootErr = startNode(cfg)
	})
	if benchBootErr != nil {
		tb.Fatal("bench boot:", benchBootErr)
	}
}
