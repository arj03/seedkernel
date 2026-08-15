module seedloader

go 1.25.0

require (
	github.com/tetratelabs/wazero v1.12.0
	golang.org/x/crypto v0.53.0
)

require golang.org/x/sys v0.46.0 // indirect

// LOCAL, NOT SHIPPABLE YET: the wazero fork carrying the inline back-edge check for the
// §4.3 module-call bound (arj03/wazero, branch inline-termination-check, proposed
// upstream). It tests the module's Closed word inline on every back-edge and exits to Go
// only when it is set, plus once every 4096 back-edges regardless — the rare exit is the
// loop's GC safepoint, without which a spinning module deadlocks a stop-the-world. It
// makes an armed runtime cost percent rather than multiples — see
// module_bound_bench_test.go. Replace with a tagged version once the branch has one, or
// drop it entirely if the change lands upstream.
replace github.com/tetratelabs/wazero => ../../wazero
