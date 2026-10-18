package main

// Signing over the loader's libsodium, for tests that build signed fixtures. The loader
// itself only verifies.

func (s *libsodium) signDetached(msg, sk []byte) []byte {
	if len(sk) != 64 {
		panic("crypto_sign_detached: secret key must be 64 bytes")
	}
	s.arenaReset(alignUp(len(msg)) + alignUp(len(sk)) + alignUp(64))
	in, skp, sig := s.takeIn(msg), s.takeIn(sk), s.take(64)
	lo, hi := lenArgs(len(msg))
	s.mustCall("crypto_sign_detached", uint64(sig), 0 /*siglen_p=NULL*/, uint64(in), lo, hi, uint64(skp))
	return s.read(sig, 64)
}

func (s *libsodium) signKeypair() (pk, sk []byte) {
	s.arenaReset(alignUp(32) + alignUp(64))
	pkp, skp := s.take(32), s.take(64)
	s.mustCall("crypto_sign_keypair", uint64(pkp), uint64(skp))
	return s.read(pkp, 32), s.read(skp, 64)
}

func (s *libsodium) signSeedKeypair(seed []byte) (pk, sk []byte) {
	if len(seed) != 32 {
		panic("crypto_sign_seed_keypair: seed must be 32 bytes")
	}
	s.arenaReset(alignUp(32) + alignUp(64) + alignUp(len(seed)))
	pkp, skp, sp := s.take(32), s.take(64), s.takeIn(seed)
	s.mustCall("crypto_sign_seed_keypair", uint64(pkp), uint64(skp), uint64(sp))
	return s.read(pkp, 32), s.read(skp, 64)
}
