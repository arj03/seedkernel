package main

// The symmetric primitives every target has natively, AES-256-GCM and SHA-256 (abi.ts
// `aesGcmSeal`, `aesGcmOpen`, `sha256`), and the same AES served to a private module as
// `host_crypto.*` imports, in place on its memory (quic.wasm's packet protection). Go's
// AES uses the CPU's AES and carry-less-multiply instructions.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"errors"

	"seedkernel/qjs"

	"github.com/tetratelabs/wazero/api"
)

const hostCryptoModule = "host_crypto"

// aesKeys keeps the last few keys' AES: a link alternates its send and receive keys, and
// expanding a key costs more than sealing a small record.
type aesKeys struct {
	keys [4]struct {
		k     [32]byte
		block cipher.Block
		gcm   cipher.AEAD
	}
	next int
}

func (c *aesKeys) entry(key []byte) int {
	if len(key) != 32 {
		panic(errors.New("aes: key is not 32 bytes"))
	}
	for i := range c.keys {
		if c.keys[i].block != nil && [32]byte(key) == c.keys[i].k {
			return i
		}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	i := c.next
	c.next = (c.next + 1) % len(c.keys)
	c.keys[i].k, c.keys[i].block, c.keys[i].gcm = [32]byte(key), block, nil
	return i
}

func (c *aesKeys) block(key []byte) cipher.Block { return c.keys[c.entry(key)].block }

func (c *aesKeys) gcm(key []byte) cipher.AEAD {
	e := &c.keys[c.entry(key)]
	if e.gcm == nil {
		g, err := cipher.NewGCM(e.block)
		if err != nil {
			panic(err)
		}
		e.gcm = g
	}
	return e.gcm
}

// installSymmetric puts the bridge's symmetric primitives on `b`.
func installSymmetric(qc *qjs.Context, b qjs.Value) {
	keys := &aesKeys{}
	// Key, nonce and associated data copied out first; the message borrowed last.
	args := func(args []qjs.Value) (key, nonce, ad, msg []byte, err error) {
		if key, err = args[0].Bytes(); err != nil {
			return
		}
		if nonce, err = args[1].Bytes(); err != nil {
			return
		}
		if ad, err = args[2].Bytes(); err != nil {
			return
		}
		msg, err = args[3].View()
		return
	}
	b.SetPropertyStr("aesGcmSeal", qc.Function(func(qc *qjs.Context, a []qjs.Value) (qjs.Value, error) {
		key, nonce, ad, pt, err := args(a)
		if err != nil {
			return qjs.Value{}, err
		}
		return qc.NewArrayBuffer(keys.gcm(key).Seal(nil, nonce, pt, ad)), nil
	}))
	b.SetPropertyStr("aesGcmOpen", qc.Function(func(qc *qjs.Context, a []qjs.Value) (qjs.Value, error) {
		key, nonce, ad, ct, err := args(a)
		if err != nil {
			return qjs.Value{}, err
		}
		pt, err := keys.gcm(key).Open(nil, nonce, ct, ad)
		if err != nil {
			return qc.NewNull(), nil
		}
		return qc.NewArrayBuffer(pt), nil
	}))
	b.SetPropertyStr("sha256", qc.Function(func(qc *qjs.Context, a []qjs.Value) (qjs.Value, error) {
		msg, err := a[0].View()
		if err != nil {
			return qjs.Value{}, err
		}
		sum := sha256.Sum256(msg)
		return qc.NewArrayBuffer(sum[:]), nil
	}))
}

func view(mem api.Memory, ptr uint64, n uint32) []byte {
	b, ok := mem.Read(uint32(ptr), n)
	if !ok {
		panic(errors.New("host_crypto: out of bounds"))
	}
	return b
}

// moduleCrypto answers a module's `host_crypto` imports by name, one key cache per
// instance. `dest` and the input are one buffer or two apart, as ngtcp2 passes them; a
// partial overlap panics in Go's AEAD, which traps the module.
func moduleCrypto() map[string]api.GoModuleFunc {
	keys := &aesKeys{}
	return map[string]api.GoModuleFunc{
		// (dest, key, pt, n, nonce, aad, alen): dest gets n + 16 bytes.
		"seal": func(_ context.Context, m api.Module, s []uint64) {
			mem := m.Memory()
			n := uint32(s[3])
			keys.gcm(view(mem, s[1], 32)).Seal(view(mem, s[0], n+16)[:0], view(mem, s[4], 12), view(mem, s[2], n), view(mem, s[5], uint32(s[6])))
		},
		// (dest, key, ct, n >= 16, nonce, aad, alen) -> 0, or 1 for a bad tag.
		"open": func(_ context.Context, m api.Module, s []uint64) {
			mem := m.Memory()
			n := uint32(s[3])
			if _, err := keys.gcm(view(mem, s[1], 32)).Open(view(mem, s[0], n-16)[:0], view(mem, s[4], 12), view(mem, s[2], n), view(mem, s[5], uint32(s[6]))); err != nil {
				s[0] = 1
				return
			}
			s[0] = 0
		},
		// (dest, key, block): one AES-256 block, the QUIC header-protection mask (RFC 9001
		// §5.4.3).
		"block": func(_ context.Context, m api.Module, s []uint64) {
			mem := m.Memory()
			keys.block(view(mem, s[1], 32)).Encrypt(view(mem, s[0], 16), view(mem, s[2], 16))
		},
		// (dest, msg, n): 32 bytes of SHA-256.
		"sha256": func(_ context.Context, m api.Module, s []uint64) {
			mem := m.Memory()
			sum := sha256.Sum256(view(mem, s[1], uint32(s[2])))
			copy(view(mem, s[0], 32), sum[:])
		},
	}
}
