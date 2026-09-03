// hostcalls.go — the native registry of host calls parked for one confined realm
// (README §12.3). A guest awaiting `host.call` is heap state on both sides: the guest's
// Promise, and the host's copy of the input it was handed. This ledger bounds the second
// half, by call count and by aggregate copied bytes, and it is the AUTHORITATIVE one on
// this target — it admits ahead of the guest-to-Go copy, so a refusal costs the host
// nothing but the answer. Nothing here touches the engine, the loop or either context:
// the realm owns those, the ledger owns only the accounting.
package main

import (
	"errors"
	"fmt"
)

type hostCallLedger struct {
	live  map[int64]int64 // guest-minted call id → bytes charged to it
	bytes int64           // the sum of live's values, kept as one number
	// The ceilings arrive from the shared host (core/wasm-limits.ts) on every createRealm,
	// so Go holds no copy that could drift from the JS target's.
	maxCalls int
	maxBytes int64
}

func newHostCallLedger(maxCalls int, maxBytes int64) hostCallLedger {
	return hostCallLedger{live: map[int64]int64{}, maxCalls: maxCalls, maxBytes: maxBytes}
}

// admit charges a new call's id, its count slot and its payload width TOGETHER, which is
// the whole point of the type: neither many tiny fire-and-forget calls nor a handful of
// maximum-sized deliveries can multiply host-side buffers, and a caller cannot admit two
// of the three and copy anyway. Either everything is charged or nothing is.
func (l *hostCallLedger) admit(id, bytes int64) error {
	if _, duplicate := l.live[id]; duplicate {
		return fmt.Errorf("guest: duplicate live host call id %d", id)
	}
	if len(l.live) >= l.maxCalls {
		return fmt.Errorf("guest: too many outstanding host calls (cap %d)", l.maxCalls)
	}
	if bytes < 0 || bytes > l.maxBytes-l.bytes {
		return fmt.Errorf("guest: too many outstanding host call payload bytes (cap %d)", l.maxBytes)
	}
	l.live[id] = bytes
	l.bytes += bytes
	return nil
}

// reserve charges more to a call already admitted — a response's bytes, for the moment
// they coexist with the request that asked. A refusal leaves the existing charge intact,
// so the caller can still settle the call with an error and release it.
func (l *hostCallLedger) reserve(id, bytes int64) error {
	owned, live := l.live[id]
	if !live {
		return errors.New("guest: host call is no longer active")
	}
	if bytes < 0 || bytes > l.maxBytes-l.bytes {
		return fmt.Errorf("guest: too many outstanding host call payload bytes (cap %d)", l.maxBytes)
	}
	l.live[id] = owned + bytes
	l.bytes += bytes
	return nil
}

// release ends one call's custody and returns everything it charged. A no-op for an id
// that is not live, so a stray or duplicate settlement cannot credit the realm twice.
func (l *hostCallLedger) release(id int64) {
	owned, live := l.live[id]
	if !live {
		return
	}
	delete(l.live, id)
	l.bytes -= owned
}

// has reports whether a call is still parked — the question a settlement asks before
// spending anything on an answer nobody is waiting for.
func (l *hostCallLedger) has(id int64) bool {
	_, live := l.live[id]
	return live
}

// releaseAll drops every call's custody at once. Realm disposal: the guest that would
// have consumed the answers is gone, so what a still-pending backend holds is the host's
// own allocation, not this realm's — keeping the charge would pin the allowance of a
// realm with nothing left alive to release it.
func (l *hostCallLedger) releaseAll() {
	l.live = map[int64]int64{}
	l.bytes = 0
}
