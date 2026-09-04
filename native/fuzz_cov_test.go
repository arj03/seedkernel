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
// So a target MARKS the milestones its execution passed, and each milestone owns a Go block
// the fuzzer can see. An input that reaches a state no earlier input reached enters a block
// no earlier input entered, and is kept.
//
// MILESTONES, NOT ONE NAME PER EXECUTION. The first version of this file folded everything
// an execution did into a single string and hashed it into 64 slots. That was wrong twice:
//
//   - It lost the middle. A msg1 that got as far as the ML-KEM encapsulation and then failed
//     the identity proof reported the same "closed, nothing delivered, wrote nothing" as one
//     refused on its first length check, so the mutator was told nothing about the distance
//     between them — and distance is the only thing it can climb.
//   - It collided. A dozen names in 64 slots is a coin flip (~65% chance some pair shares a
//     slot), and a collision is two outcomes the fuzzer silently stops telling apart —
//     differently on every build, since the set of names decides which pair.
//
// Each milestone below is a named constant with a block of its own, and a target marks every
// one it passed. Names stay COARSE — which refusal, which state, never a length or a count —
// because a mark that varies with the input makes every input look new and fills the corpus
// with noise instead of shapes. Counts are marked as buckets (one, many) for that reason.
//
// Ids are per SUBJECT rather than per target function: the two WsFramer halves are two
// configurations of one class, and the AKE targets are one Link at different stages, so each
// group is shared by the targets that drive it and by nothing else. Two subjects never share
// an id — an id another subject's seed corpus already entered would start with its counter
// above zero, which is the collision problem again in a slower form.

// covSink is what the blocks below write, so nothing folds them away.
var covSink uint32

// covID is one milestone: an index into covBlocks, and nothing else.
type covID int

const (
	// ── the bundle container, §12.4 (fuzz_bundle_test.go) ─────────────────────
	covBundleSkip     covID = iota // the probe declined the input before parsing it
	covBundleRefused               // the reader threw in its own vocabulary
	covBundleOK                    // a blob came apart without a refusal
	covBundleVerified              // the manifest signature checked out
	covBundleAccepted              // policy admitted the author
	covBundleFilesNone
	covBundleFilesOne
	covBundleFilesMany

	// ── the length-prefixed codec (fuzz_framing_test.go) ──────────────────────
	covLengthOK       // every chunk accepted
	covLengthRefused  // a declared length over the pre-auth cap
	covLengthMsgOne   // one message delivered
	covLengthMsgMany  // more than one
	covLengthHeldPart // bytes still buffered when the stream ran out

	// ── WsFramer, both halves (fuzz_framing_test.go) ──────────────────────────
	covWsFramerThrew   // a refusal escaped push instead of answering false
	covWsFramerRefused // push answered false
	covWsFramerOpened  // the upgrade completed
	covWsFramerMsgOne  // one message delivered up
	covWsFramerMsgMany // more than one
	covWsFramerWrote   // something went back on the wire (the 101, or a pong)
	covWsFramerHeld    // bytes still buffered when the stream ran out

	// ── ByteParts (fuzz_framing_test.go) ──────────────────────────────────────
	covBytePartsOpsMany // a program long enough to reach compaction
	covBytePartsTook    // something was actually consumed, which moves the head
	covBytePartsGrown   // the 8 KiB accumulator boundary was crossed
	covBytePartsHeld    // bytes still buffered at the end

	// ── ws.wasm's frame decode (fuzz_ws_test.go) ──────────────────────────────
	covWsLen7   // the length was the 7-bit field
	covWsLenU16 // …the 16-bit extension
	covWsLenU64 // …the 64-bit extension
	covWsNeedMore
	covWsFrame
	covWsProtoErr
	covWsOpData     // continuation, text or binary
	covWsOpControl  // close, ping or pong
	covWsOpReserved // one of the ten opcodes that name nothing
	covWsRsvSet     // an extension bit set with no extension negotiated
	covWsFragment   // FIN clear
	covWsMasked     // the mask direction matched, so the unmask loop ran
	covWsPayload    // a frame came back carrying bytes

	// ── ws.wasm's frame encode (fuzz_ws_test.go) ──────────────────────────────
	covWsEncHead2
	covWsEncHead4
	covWsEncHead10
	covWsEncMasked
	covWsEncControl // a close or a pong rather than a message
	covWsEncRefused // a frame past the scratch it writes into

	// ── the handshake and the record layer, §12.6.2 (fuzz_ake_test.go) ────────
	//
	// The first six are what the link ENDED as; the rest are host names the execution
	// actually reached, recorded at the seam the harness already owns. ake.js is not
	// instrumented and does not need to be — the names it calls are its milestones, and
	// they are the only thing that separates a msg1 refused on its suite byte from one
	// that got a responder as far as an ML-KEM encapsulation.
	covAkeThrew
	covAkeClosed
	covAkeStalled
	covAkeWrote
	covAkeAuthed
	covAkeDelivered
	covAkeDh           // crypto/x25519/dh — key agreement over a point the input chose
	covAkeKemKeygen    // mlkem op 0
	covAkeKemEncaps    // mlkem op 1 — encapsulation against a KEM key the input chose
	covAkeKemDecaps    // mlkem op 2
	covAkeAeadSeal     // crypto/chacha20poly1305-ietf/seal
	covAkeAeadOpen     // …/open — the probe, an identity, or a record
	covAkeVerify       // node/verify — the signature check the handshake exists to make
	covAkeSign         // node/sign — this end put its own identity on the wire
	covAkeRecordOpened // a record opened and moved the receive counter

	covCount // not a milestone: how many there are
)

// covShapeBase is where the open-ended half of the table starts. Milestones are named and
// finite; a refusal MESSAGE out of the bundle reader is neither — the parser has dozens of
// them and they are the one gradient that separates its refusal sites — so those are hashed
// into a window of their own. A collision there costs one signal among refusal messages;
// before, it could cost a whole target's states.
const covShapeBase covID = 64

// The milestones must fit under the shaped window, and the whole thing must fit the table.
// Both are compile-time: a negative length is a build failure, not a silent wrap.
const _ = uint(covShapeBase - covCount)
const _ = uint(len(covBlocks) - int(covShapeBase) - covShapeSlots)

// covShapeSlots is how many blocks the shaped-message window holds.
const covShapeSlots = 64

// covBlocks is the fan-out, one function per milestone.
//
// It is a table of functions rather than a counter because of how "interesting" is decided:
// a snapshot beats the corpus when some counter is HIGHER than the accumulated maximum, so
// one block entered a different number of times is one signal and not many — the first
// execution to enter it 64 times ends the signal for every smaller number. An id has to land
// in a block of its own, and a func literal is the shortest way to write one. Called through
// the slice, so nothing is inlined into a shared block.
var covBlocks = [128]func(){
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

// covMark enters one milestone's block. Call it for EVERY milestone an execution passed,
// in any order — the point is the set, not a single verdict. Calling it once per occurrence
// rather than once per execution is fine and sometimes better: Go buckets a block's counter
// (1, 2, 3, 4-7, 8-15, …), so eight of something is already a different signal from one.
func covMark(id covID) { covBlocks[id]() }

// covMarkIf is covMark for the long runs of flags a probe's answer comes back as, so a
// caller reads as the list of milestones it is reporting.
func covMarkIf(reached bool, id covID) {
	if reached {
		covMark(id)
	}
}

// covMarkCount marks a count as a bucket. Nothing is not a milestone — it is the absence of
// one, and every other block already says so.
func covMarkCount(n int, one, many covID) {
	if n == 1 {
		covMark(one)
	} else if n > 1 {
		covMark(many)
	}
}

// covMarkShape marks a refusal MESSAGE, in the open-ended window: the parser's own
// vocabulary with the input's own numbers and quoted names taken back out, hashed. FNV-1a,
// so the block is a function of the shaped message alone — a table handing out ids in
// first-seen order would make an input's coverage depend on what ran before it, and the
// fuzzer would chase that history rather than the input.
func covMarkShape(msg string) {
	shaped := covShape(msg)
	h := uint32(2166136261)
	for i := 0; i < len(shaped); i++ {
		h = (h ^ uint32(shaped[i])) * 16777619
	}
	covBlocks[covShapeBase+covID(h%covShapeSlots)]()
}

// covShape strips an input's own contribution out of a refusal message, so
// `bundle: 12 trailing bytes` and `bundle: 900 trailing bytes` are one shape rather than two
// hundred: every run of digits becomes `N`, and everything inside a quoted run is dropped
// for a single `"S"`.
//
// The quote scan is ESCAPE-AWARE because the messages quote attacker-chosen text with
// JSON.stringify (bundle.ts: `two files named ${JSON.stringify(name)}`), which spells a
// quote inside that text as `\"`. Reading that as the closing quote puts the scan out of
// phase for the rest of the message and lets the remainder of a file name — the input
// talking, not the parser — into the shape, which is a fresh block per name and a corpus
// full of one-off entries.
//
// It cannot do better than that: a message that interpolates a name WITHOUT quoting it
// (`bundle: missing file ${file}`) has nothing marking where the input starts, and stripping
// bare identifiers would take the parser's own words with them.
func covShape(msg string) string {
	out := make([]byte, 0, len(msg))
	inQuote, inNum, esc := false, false, false
	for i := 0; i < len(msg); i++ {
		c := msg[i]
		switch {
		case esc:
			// Whatever follows a backslash is a character of the text, never punctuation:
			// dropped inside a quoted run, kept outside one, and closing nothing either way.
			esc = false
			if !inQuote {
				out = append(out, c)
				inNum = false
			}
		case c == '\\':
			esc = true
			if !inQuote {
				out = append(out, c)
				inNum = false
			}
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
