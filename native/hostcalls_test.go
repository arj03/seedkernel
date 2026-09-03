package main

import "testing"

// The ledger is what stands between a guest and unbounded host-side allocation (§12.3):
// every parked host.call costs the host a copy of the input it was handed, and only these
// two ceilings bound that. The equivalent registry on the JS target is covered by
// WASM/tests/verify-hardening.mjs; these are the native one's, and they run without a
// QuickJS runtime because the ledger deliberately owns nothing but the accounting.

// sumCharged is the invariant every case below re-checks: the aggregate is exactly what
// the live calls hold, so no refusal path can leak a charge or credit one twice.
func sumCharged(t *testing.T, l *hostCallLedger) {
	t.Helper()
	var sum int64
	for _, b := range l.live {
		sum += b
	}
	if sum != l.bytes {
		t.Fatalf("aggregate %d does not match the %d bytes the %d live calls hold", l.bytes, sum, len(l.live))
	}
}

func TestHostCallLedgerCallCap(t *testing.T) {
	l := newHostCallLedger(3, 1<<20)
	for i := int64(0); i < 3; i++ {
		if err := l.admit(i, 8); err != nil {
			t.Fatalf("admit %d within the cap: %v", i, err)
		}
	}
	// The refusal must cost the host nothing: no id recorded, no bytes charged.
	if err := l.admit(99, 8); err == nil {
		t.Fatal("admitted a 4th call against a cap of 3")
	}
	if l.has(99) {
		t.Fatal("a refused call was recorded live")
	}
	if l.bytes != 24 {
		t.Fatalf("a refused admit charged bytes: %d, want 24", l.bytes)
	}
	sumCharged(t, &l)

	// Releasing one makes room again — the cap is on what is outstanding, not on how many
	// calls a realm may make over its life.
	l.release(1)
	if err := l.admit(99, 8); err != nil {
		t.Fatalf("admit after a release: %v", err)
	}
	sumCharged(t, &l)
}

func TestHostCallLedgerByteCap(t *testing.T) {
	l := newHostCallLedger(256, 100)
	if err := l.admit(1, 60); err != nil {
		t.Fatal("admit within the byte cap:", err)
	}
	if err := l.admit(2, 41); err == nil {
		t.Fatal("admitted 41 bytes with 40 left under a 100-byte cap")
	}
	if l.has(2) || l.bytes != 60 {
		t.Fatalf("a refused admit left id 2 live=%v and %d bytes charged", l.has(2), l.bytes)
	}
	// Exactly the remainder still fits: the cap is a ceiling, not a strict inequality.
	if err := l.admit(2, 40); err != nil {
		t.Fatal("admit of exactly the remaining allowance:", err)
	}
	if l.bytes != 100 {
		t.Fatalf("charged %d bytes, want the full 100", l.bytes)
	}
	sumCharged(t, &l)

	// A negative width is a bogus source read, not free space.
	if err := l.admit(3, -1); err == nil {
		t.Fatal("admitted a negative payload width")
	}
	sumCharged(t, &l)
}

func TestHostCallLedgerDuplicateID(t *testing.T) {
	l := newHostCallLedger(256, 1<<20)
	if err := l.admit(7, 10); err != nil {
		t.Fatal("first admit:", err)
	}
	// A guest re-using a live id must not be able to re-charge it or displace the entry —
	// its release would then credit the realm for bytes it still holds.
	if err := l.admit(7, 10); err == nil {
		t.Fatal("admitted a duplicate live call id")
	}
	if l.bytes != 10 {
		t.Fatalf("a refused duplicate changed the charge to %d, want 10", l.bytes)
	}
	sumCharged(t, &l)
}

func TestHostCallLedgerReserveRefusalKeepsTheCall(t *testing.T) {
	l := newHostCallLedger(256, 100)
	if err := l.admit(1, 60); err != nil {
		t.Fatal("admit:", err)
	}
	// A response too big for the remaining allowance is refused, but the call stays live
	// and keeps its original charge — the caller settles it with the error, and THAT
	// release is what returns the bytes. Dropping it here would strand the guest.
	if err := l.reserve(1, 41); err == nil {
		t.Fatal("reserved 41 bytes with 40 left")
	}
	if !l.has(1) {
		t.Fatal("a refused reserve dropped the call")
	}
	if l.bytes != 60 {
		t.Fatalf("a refused reserve changed the charge to %d, want 60", l.bytes)
	}
	if err := l.reserve(1, 40); err != nil {
		t.Fatal("reserve of exactly the remaining allowance:", err)
	}
	sumCharged(t, &l)

	// Release returns the request AND everything reserved against it.
	l.release(1)
	if l.bytes != 0 || len(l.live) != 0 {
		t.Fatalf("release left %d calls and %d bytes", len(l.live), l.bytes)
	}

	// Reserving against an id that is not live is refused rather than creating one.
	if err := l.reserve(1, 1); err == nil {
		t.Fatal("reserved against a released call")
	}
	if len(l.live) != 0 || l.bytes != 0 {
		t.Fatalf("a refused reserve created state: %d calls, %d bytes", len(l.live), l.bytes)
	}
}

func TestHostCallLedgerStrayReleaseIsANoOp(t *testing.T) {
	l := newHostCallLedger(256, 1<<20)
	if err := l.admit(1, 25); err != nil {
		t.Fatal("admit:", err)
	}
	// A settlement for an id that was never parked, and a second settlement for one
	// already released, must not credit the realm for bytes it never charged.
	l.release(404)
	l.release(1)
	l.release(1)
	if l.bytes != 0 || len(l.live) != 0 {
		t.Fatalf("stray releases left %d calls and %d bytes", len(l.live), l.bytes)
	}
	sumCharged(t, &l)

	// The allowance is fully back: a fresh call of the whole cap is admitted.
	if err := l.admit(2, 1<<20); err != nil {
		t.Fatal("the released allowance did not come back:", err)
	}
	sumCharged(t, &l)
}

func TestHostCallLedgerReleaseAll(t *testing.T) {
	l := newHostCallLedger(256, 1<<20)
	for i := int64(0); i < 10; i++ {
		if err := l.admit(i, 100); err != nil {
			t.Fatalf("admit %d: %v", i, err)
		}
	}
	if err := l.reserve(3, 50); err != nil {
		t.Fatal("reserve:", err)
	}
	l.releaseAll()
	if len(l.live) != 0 || l.bytes != 0 {
		t.Fatalf("releaseAll left %d calls and %d bytes", len(l.live), l.bytes)
	}
	// The ledger stays usable afterwards — close() is the only caller today, but a zeroed
	// map that could not be admitted into would be a trap for the next one.
	if err := l.admit(1, 100); err != nil {
		t.Fatal("admit after releaseAll:", err)
	}
	sumCharged(t, &l)
}
