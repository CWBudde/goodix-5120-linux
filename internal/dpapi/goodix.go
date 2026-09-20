package dpapi

import "crypto/sha256"

// Goodix's gfusb.dll seals Goodix_Cache.bin with a 48-byte secondary entropy
// that it does not store directly. Instead it stores an 8-byte per-seal random
// seed after the DPAPI blob and re-derives the entropy from it on every read,
// in the routine its debug log calls generate_entropy2 (gf_production.c). This
// file reproduces that derivation exactly, so the cache can be unsealed offline.
//
// The derivation, recovered by static analysis of gfusb.dll (2026-09-20):
//
//	root    = SHA256(seed)                         // seed is 8 bytes
//	entropy = root[16:32] || SHA256(root[0:16] || K)   // 48 bytes
//
// K is a fixed 16-byte key the routine folds out of three 16-byte constants in
// the DLL's .data (at RVA 0x312cb0 / 0x312cc0 / 0x312cd0). The folding is kept
// here rather than the pre-computed K, so the value is auditable against the
// binary.
var goodixEntropyConstants = [3][16]byte{
	{0x9d, 0x79, 0x92, 0xb3, 0x84, 0x02, 0xb6, 0x6c, 0x81, 0xd1, 0xf5, 0x55, 0x21, 0x89, 0x42, 0xa9},
	{0x18, 0x48, 0xd7, 0x15, 0x50, 0xd2, 0x70, 0xd2, 0x19, 0xc8, 0x06, 0x32, 0xab, 0x4f, 0x8b, 0xb3},
	{0xe4, 0x7c, 0x89, 0x38, 0xdb, 0x52, 0x50, 0xf0, 0x20, 0x56, 0x17, 0xee, 0x17, 0xda, 0x4e, 0xb4},
}

// goodixEntropyKey folds the three .data constants into the 16-byte key K, the
// way generate_entropy2 does:
//
//	K[0:8]  = C0[0:8]  ^ C1[0:8]  ^ C0[8:16]
//	K[8:16] = C1[8:16] ^ C2[8:16] ^ C2[0:8]
func goodixEntropyKey() [16]byte {
	c0, c1, c2 := goodixEntropyConstants[0], goodixEntropyConstants[1], goodixEntropyConstants[2]
	var k [16]byte
	for i := 0; i < 8; i++ {
		k[i] = c0[i] ^ c1[i] ^ c0[i+8]
	}
	for i := 8; i < 16; i++ {
		k[i] = c1[i] ^ c2[i] ^ c2[i-8]
	}
	return k
}

// GoodixCacheEntropy expands the 8-byte cache seed into the 48-byte secondary
// entropy that unseals Goodix_Cache.bin.
func GoodixCacheEntropy(seed []byte) []byte {
	root := sha256.Sum256(seed)
	k := goodixEntropyKey()
	inner := make([]byte, 0, 16+16)
	inner = append(inner, root[:16]...)
	inner = append(inner, k[:]...)
	h := sha256.Sum256(inner)
	out := make([]byte, 0, 48)
	out = append(out, root[16:32]...)
	out = append(out, h[:]...)
	return out
}
