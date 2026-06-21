package qjs

import (
	"strconv"
	"strings"
	"testing"
)

// TestStringNoLeak guards the JS_FreeCString release in readPackedString. Every
// Value.String() runs QJS_ToCString, which takes a reference on a JSString; without the
// matching JS_FreeCString that reference leaks and the string is never freed. Reading
// many *distinct* strings then drives the QuickJS heap — and thus wasm linear memory —
// up without bound. With the release, steady-state memory is flat.
//
// Pre-fix this grows by tens of MiB and fails; post-fix the delta is allocator slack.
func TestStringNoLeak(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping leak test in -short mode")
	}
	rt, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	c := rt.Context()

	read := func(i int) {
		v := c.NewString(strings.Repeat("x", 800) + strconv.Itoa(i))
		if got := v.String(); len(got) < 800 {
			t.Fatalf("short read: %d", len(got))
		}
		v.Free()
	}

	// Warm allocator pools so the baseline is steady state, not first-touch growth.
	for i := 0; i < 3000; i++ {
		read(i)
	}
	base := rt.mem.Size()

	const n = 40000 // ~820 bytes each ≈ ~32 MiB leaked if the ref is never dropped
	for i := 0; i < n; i++ {
		read(i)
	}
	grew := int64(rt.mem.Size()) - int64(base)

	if grew > 2<<20 { // 2 MiB headroom for allocator slack, far below a real leak
		t.Fatalf("linear memory grew %d bytes over %d string reads — JS_FreeCString release missing?", grew, n)
	}
	t.Logf("linear memory grew %d bytes over %d reads (base=%d)", grew, n, base)
}
