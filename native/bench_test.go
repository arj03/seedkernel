package main

import (
	"errors"
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
		// The helpers below fail with tb.Fatal, which unwinds this goroutine but leaves the
		// Once done — so hold the sentinel until the realm is actually up, or a later
		// benchmark finds benchBootErr nil and runs against a half-built realm.
		benchBootErr = errors.New("the first benchmark to stand the realm up failed")
		// The same standing-up every test does: a bench realm assembled its own way is the
		// second assembly path this target exists not to have.
		bootRealmIn(tb, dir)
		cfg := nodeConfig{KeyHex: testKeyHex(tb)}
		_, benchBootErr = startNode(cfg)
	})
	if benchBootErr != nil {
		tb.Fatal("bench boot:", benchBootErr)
	}
}
