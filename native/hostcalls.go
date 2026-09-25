// The host calls parked for one confined realm (§12.3), bounded by count and by
// aggregate copied bytes. Admission happens before the copy into the host realm.
package main

import (
	"errors"
	"fmt"
)

// parkedCall is what one call holds while it waits: its charged bytes and the invocation
// clock its answer resumes on.
type parkedCall struct {
	bytes int64
	clock *invocationClock
}

type hostCallLedger struct {
	live  map[int64]parkedCall // guest-minted call id → what it holds
	bytes int64                // the sum of live's charges
	// From host/wasm-limits.ts, per createRealm.
	maxCalls int
	maxBytes int64
}

func newHostCallLedger(maxCalls int, maxBytes int64) hostCallLedger {
	return hostCallLedger{live: map[int64]parkedCall{}, maxCalls: maxCalls, maxBytes: maxBytes}
}

// admit charges a new call's id, count slot and payload width together, or nothing.
// `clock` is the invocation its answer resumes on.
func (l *hostCallLedger) admit(id, bytes int64, clock *invocationClock) error {
	if _, duplicate := l.live[id]; duplicate {
		return fmt.Errorf("guest: duplicate live host call id %d", id)
	}
	if len(l.live) >= l.maxCalls {
		return fmt.Errorf("guest: too many outstanding host calls (cap %d)", l.maxCalls)
	}
	if err := l.charge(bytes); err != nil {
		return err
	}
	l.live[id] = parkedCall{bytes: bytes, clock: clock}
	return nil
}

// charge puts `bytes` on the realm's aggregate allowance, or refuses and charges nothing.
func (l *hostCallLedger) charge(bytes int64) error {
	if bytes > l.maxBytes-l.bytes {
		return fmt.Errorf("guest: too many outstanding host call payload bytes (cap %d)", l.maxBytes)
	}
	l.bytes += bytes
	return nil
}

// reserve charges an admitted call's answer bytes. A refusal leaves the existing charge,
// so the call can still be settled with an error.
func (l *hostCallLedger) reserve(id, bytes int64) error {
	call, live := l.live[id]
	if !live {
		return errors.New("guest: host call is no longer active")
	}
	if err := l.charge(bytes); err != nil {
		return err
	}
	call.bytes += bytes
	l.live[id] = call
	return nil
}

// release ends one call's custody and returns its charge; a no-op for a dead id.
func (l *hostCallLedger) release(id int64) {
	call, live := l.live[id]
	if !live {
		return
	}
	delete(l.live, id)
	l.bytes -= call.bytes
}

// at returns a parked call's record and whether it is still parked.
func (l *hostCallLedger) at(id int64) (parkedCall, bool) {
	call, live := l.live[id]
	return call, live
}

// releaseAll drops every call's custody, on realm disposal.
func (l *hostCallLedger) releaseAll() {
	l.live = map[int64]parkedCall{}
	l.bytes = 0
}
