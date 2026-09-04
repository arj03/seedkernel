package main

// ── giving the mutator something to steer by ─────────────────────────────────
//
// Go's fuzzer keeps one counter per basic block of GO code, and calls an input interesting
// when it drives a counter higher than every earlier input did. Nothing this package fuzzes
// is Go: the parsers are JS inside QuickJS inside wasm, compiled by wazero at run time, and
// ws.wasm is wasm as well. None of it is instrumented, so the only gradient the mutator ever
// had was the oracles' own branches — which every seed hits within seconds. After that a run
// is uniform random mutation over a structured format. Measured before this file existed:
// 525k executions of FuzzWsDecodeOne grew its corpus by two entries, 48k of FuzzAkeAccept by
// two.
//
// So each target names the outcome its execution reached, and covPath puts that name in a Go
// block of its own — which is the one thing the fuzzer can see. An input that reaches a
// refusal no earlier input reached now enters a block no earlier input entered, and is kept.
//
// The names have to be COARSE: which refusal, which state, never a length or a count. A name
// that varies with the input makes every input look new, and the corpus fills with noise
// instead of shapes.

// covSink is what the blocks below write, so nothing folds them away.
var covSink uint32

// covBlocks is the fan-out, one function per outcome id.
//
// It is a table of functions rather than a counter because of how "interesting" is decided:
// a snapshot beats the corpus when some counter is HIGHER than the accumulated maximum, so
// one block entered a different number of times is one signal and not many — the first
// execution to enter it 64 times ends the signal for every smaller number. An id has to land
// in a block of its own, and a func literal is the shortest way to write one. Called through
// the slice, so nothing is inlined into a shared block.
//
// 64 of them, against fewer than a dozen outcome names in any one target: two names that
// collide are two outcomes the fuzzer stops telling apart, which costs a signal rather than
// correctness.
var covBlocks = [64]func(){
	func() { covSink++ }, func() { covSink++ }, func() { covSink++ }, func() { covSink++ },
	func() { covSink++ }, func() { covSink++ }, func() { covSink++ }, func() { covSink++ },
	func() { covSink++ }, func() { covSink++ }, func() { covSink++ }, func() { covSink++ },
	func() { covSink++ }, func() { covSink++ }, func() { covSink++ }, func() { covSink++ },
	func() { covSink++ }, func() { covSink++ }, func() { covSink++ }, func() { covSink++ },
	func() { covSink++ }, func() { covSink++ }, func() { covSink++ }, func() { covSink++ },
	func() { covSink++ }, func() { covSink++ }, func() { covSink++ }, func() { covSink++ },
	func() { covSink++ }, func() { covSink++ }, func() { covSink++ }, func() { covSink++ },
	func() { covSink++ }, func() { covSink++ }, func() { covSink++ }, func() { covSink++ },
	func() { covSink++ }, func() { covSink++ }, func() { covSink++ }, func() { covSink++ },
	func() { covSink++ }, func() { covSink++ }, func() { covSink++ }, func() { covSink++ },
	func() { covSink++ }, func() { covSink++ }, func() { covSink++ }, func() { covSink++ },
	func() { covSink++ }, func() { covSink++ }, func() { covSink++ }, func() { covSink++ },
	func() { covSink++ }, func() { covSink++ }, func() { covSink++ }, func() { covSink++ },
	func() { covSink++ }, func() { covSink++ }, func() { covSink++ }, func() { covSink++ },
	func() { covSink++ }, func() { covSink++ }, func() { covSink++ }, func() { covSink++ },
}

// covPath marks the outcome one execution reached. Call it ONCE per execution, with
// everything that characterizes the execution folded into the one name.
func covPath(name string) {
	// FNV-1a, so the block is a function of the name alone. A table handing out ids in
	// first-seen order would make an input's coverage depend on what ran before it, and the
	// fuzzer would chase that history rather than the input.
	h := uint32(2166136261)
	for i := 0; i < len(name); i++ {
		h = (h ^ uint32(name[i])) * 16777619
	}
	covBlocks[h&63]()
}

// covShape is what a refusal message contributes to an outcome name: the parser's own
// vocabulary with the input's own numbers and quoted names taken back out, so
// `bundle: 12 trailing bytes` and `bundle: 900 trailing bytes` are one outcome rather than
// two hundred.
func covShape(msg string) string {
	out := make([]byte, 0, len(msg))
	inQuote, inNum := false, false
	for i := 0; i < len(msg); i++ {
		c := msg[i]
		switch {
		case c == '"':
			if !inQuote {
				out = append(out, '"', 'S', '"')
			}
			inQuote = !inQuote
			inNum = false
		case inQuote:
			// dropped: a name out of the blob is the input talking, not the parser
		case c >= '0' && c <= '9':
			if !inNum {
				out = append(out, 'N')
			}
			inNum = true
		default:
			out = append(out, c)
			inNum = false
		}
	}
	return string(out)
}

// covBucket folds a count into an order of magnitude: the fuzzer should be steered by
// whether a parse produced nothing, one thing or many, never by how many.
func covBucket(n int) string {
	switch {
	case n <= 0:
		return "0"
	case n == 1:
		return "1"
	case n < 8:
		return "few"
	}
	return "many"
}
