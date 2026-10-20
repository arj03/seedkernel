// The host blob (§12.9, WASM/host/host-blob.ts): what this loader runs. The loader reads
// only its framing, to find the host script and the engine it runs on; what a blob
// declares and whether to run it are the loader script's (hostslots.go), and its
// signatures are the host's to check before it stages one.
package main

import (
	"encoding/binary"
	"errors"
)

// The envelope's length, as host/bundle.ts lays it out: suite, an Ed25519 and an ML-DSA-65
// key, then a signature by each. The body follows.
const offBody = 1 + 32 + 1952 + 64 + 3309

// hostParts finds the script and the engine in env's body (manifest, script, qjs, then
// the host's crypto). Both alias env.
func hostParts(env []byte) (script string, qjsWasm []byte, err error) {
	if len(env) < offBody {
		return "", nil, errors.New("host: truncated envelope")
	}
	body := env[offBody:]
	var parts [3][]byte
	for i := range parts {
		if len(body) < 4 || uint64(binary.BigEndian.Uint32(body)) > uint64(len(body)-4) {
			return "", nil, errors.New("host: truncated body")
		}
		n := binary.BigEndian.Uint32(body)
		parts[i], body = body[4:4+n], body[4+n:]
	}
	return string(parts[1]), parts[2], nil
}
