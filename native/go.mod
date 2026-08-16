module seedloader

go 1.25.0

require (
	github.com/tetratelabs/wazero v1.12.0
	golang.org/x/crypto v0.53.0
)

require golang.org/x/sys v0.46.0 // indirect

// The wazero fork carrying the inline back-edge check for the §4.3 module-call bound. It
// tests the module's Closed word inline on every back-edge and exits to Go only when it is
// set, plus once every 256 back-edges regardless — the rare exit is the loop's GC
// safepoint, without which a spinning module deadlocks a stop-the-world. It makes an armed
// runtime cost percent rather than multiples — see module_bound_bench_test.go.
//
// Fetched from the fork rather than a working copy: a bound only this machine can build is
// a bound nobody has, and the flag it backs (SEEDKERNEL_MODULE_DEADLINE_MS) stays opt-in
// until anyone can `go build` it. A path replace made that impossible to check out and
// verify. Pinned to a commit rather than a branch so a fork push cannot change what this
// builds; drop the replace entirely if the change lands upstream.
replace github.com/tetratelabs/wazero => github.com/arj03/wazero v0.0.0-20260816133253-a01f823c77d3
