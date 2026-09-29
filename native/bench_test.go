package main

import (
	"errors"
	"sync"
	"testing"
)

// One boot for the whole benchmark run. boot() is a process-wide singleton (a second one
// tears down the realm, and with it the module table a benchmark already loaded its module
// into), so every benchmark that needs a realm shares this one. Go runs all tests before
// all benchmarks, so the tests' own boots are finished by the time this runs.
var (
	benchBootOnce sync.Once
	benchBootErr  error
)

// ensureBooted starts the shared benchmark realm (and a node in it, so a bench can
// install a bundle) on first use.
func ensureBooted(tb testing.TB) {
	tb.Helper()
	benchBootOnce.Do(func() {
		// The helpers below fail with tb.Fatal, which unwinds this goroutine but leaves the
		// Once done, so keep the sentinel until the realm is actually up, or a later
		// benchmark finds benchBootErr nil and runs against a half-built realm.
		benchBootErr = errors.New("the first benchmark to stand the realm up failed")
		// The same boot every test does, so there is only one assembly path. bootRealm owns
		// the data directory, which keeps it alive for the benchmarks that follow.
		bootRealm(tb)
		cfg := nodeConfig{KeyHex: testKeyHex(tb)}
		_, benchBootErr = startNode(cfg)
	})
	if benchBootErr != nil {
		tb.Fatal("bench boot:", benchBootErr)
	}
}
