// Package dpapi recovers a machine-scoped DPAPI secret offline, from the
// Windows registry hives and a master-key file, with no password and no
// brute force.
//
// This is the legitimate decryption path for a secret sealed with
// CryptProtectData(CRYPTPROTECT_LOCAL_MACHINE): the boot key derived from the
// SYSTEM hive unlocks the LSA key in the SECURITY hive, which decrypts the
// DPAPI_SYSTEM secret, whose 20-byte machine half decrypts the master key,
// which decrypts the blob. Every step is deterministic and offline. It unseals
// the Goodix TLS-PSK from Goodix_Cache.bin; see PLAN.md Phase 5.
//
// Correctness is self-checking: the master-key stage and the blob stage each
// carry an HMAC that this code verifies, so a wrong key is reported as a
// mismatch rather than yielding plausible-looking garbage. The exact
// constructions follow Windows/DPAPI as implemented by impacket's dpapi.py,
// including its non-RFC PBKDF2 feedback and the 16-byte master-key HMAC tag.
//
// The package is pure computation on bytes handed to it: it opens no device,
// reads no files itself, and never logs the secrets it handles.
package dpapi

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/bits"
	"unicode/utf16"
)

// ErrHMAC is returned when a blob's Sign HMAC does not verify: the master key
// is wrong, or the blob was sealed with secondary entropy that was not
// supplied.
var ErrHMAC = errors.New("dpapi: blob HMAC mismatch (wrong master key, or missing secondary entropy)")

// Windows CALG_* algorithm identifiers.
const (
	calgSHA1   = 0x8004
	calgHMAC   = 0x8009
	calgSHA256 = 0x800c
	calgSHA512 = 0x800e
	calg3DES   = 0x6603
	calgAES128 = 0x660e
	calgAES256 = 0x6610
)

// hashInfo mirrors impacket's ALGORITHMS_DATA row for a hash algorithm:
// macLen is the truncated HMAC tag length, and blockSize the hash block size.
type hashInfo struct {
	macLen    int
	newHash   func() hash.Hash
	blockSize int
}

var hashTable = map[uint32]hashInfo{
	calgSHA1:   {20, sha1.New, 64},
	calgHMAC:   {20, sha512.New, 64}, // MasterKey.decrypt overrides the HMAC hash to SHA-1
	calgSHA256: {32, sha256.New, 64},
	calgSHA512: {16, sha512.New, 128},
}

func hashFor(alg uint32) (hashInfo, error) {
	hi, ok := hashTable[alg]
	if !ok {
		return hashInfo{}, fmt.Errorf("dpapi: unsupported hash algo 0x%x", alg)
	}
	return hi, nil
}

func cipherParams(alg uint32) (keyLen, ivLen int, err error) {
	switch alg {
	case calg3DES:
		return 24, 8, nil
	case calgAES128:
		return 16, 16, nil
	case calgAES256:
		return 32, 16, nil
	default:
		return 0, 0, fmt.Errorf("dpapi: unsupported cipher algo 0x%x", alg)
	}
}

func newBlockCipher(alg uint32, key []byte) (cipher.Block, error) {
	if alg == calg3DES {
		return des.NewTripleDESCipher(key)
	}
	return aes.NewCipher(key)
}

func cbcDecrypt(alg uint32, key, iv, ct []byte) ([]byte, error) {
	block, err := newBlockCipher(alg, key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	if len(ct) == 0 || len(ct)%bs != 0 {
		return nil, fmt.Errorf("dpapi: ciphertext %d not a multiple of block size %d", len(ct), bs)
	}
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv[:bs]).CryptBlocks(out, ct)
	return out, nil
}

// deriveKeyPBKDF2 is DPAPI's key-stretch: like PBKDF2 but, as Windows and
// impacket implement it, each round feeds the running XOR accumulator back
// into the PRF rather than the previous block.
func deriveKeyPBKDF2(newHash func() hash.Hash, passphrase, salt []byte, keyLen, count int) []byte {
	prf := func(p, s []byte) []byte {
		m := hmac.New(newHash, p)
		m.Write(s)
		return m.Sum(nil)
	}
	var out []byte
	for i := uint32(1); len(out) < keyLen; i++ {
		u := make([]byte, len(salt)+4)
		copy(u, salt)
		binary.BigEndian.PutUint32(u[len(salt):], i)
		derived := prf(passphrase, u)
		for r := 0; r < count-1; r++ {
			actual := prf(passphrase, derived)
			for j := range derived {
				derived[j] ^= actual[j]
			}
		}
		out = append(out, derived...)
	}
	return out[:keyLen]
}

// --- Boot key ---------------------------------------------------------------

var bootKeyPermutation = [16]int{0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7}

// BootKey assembles the 16-byte system boot key (SysKey) from the class-name
// strings of the four LSA sub-keys, in order JD, Skew1, GBG, Data.
func BootKey(jd, skew1, gbg, data string) ([]byte, error) {
	scrambled := make([]byte, 0, 16)
	for _, s := range []string{jd, skew1, gbg, data} {
		if len(s) < 8 {
			return nil, fmt.Errorf("dpapi: LSA class name %q too short", s)
		}
		var chunk [4]byte
		if _, err := fmt.Sscanf(s[:8], "%02x%02x%02x%02x", &chunk[0], &chunk[1], &chunk[2], &chunk[3]); err != nil {
			return nil, fmt.Errorf("dpapi: LSA class name %q not hex: %w", s, err)
		}
		scrambled = append(scrambled, chunk[:]...)
	}
	bk := make([]byte, 16)
	for i := range bk {
		bk[i] = scrambled[bootKeyPermutation[i]]
	}
	return bk, nil
}

// --- LSA secrets (Vista+ AES scheme) ---------------------------------------

// aesLSADecrypt reproduces Windows' LSA AES decryption: a per-blob key is
// SHA-256(baseKey || first-32-bytes repeated 1000 times), and the remainder is
// AES-CBC decrypted in 16-byte blocks each starting from a zero IV.
func aesLSADecrypt(baseKey, encrypted []byte) ([]byte, error) {
	if len(encrypted) < 32 {
		return nil, errors.New("dpapi: LSA blob too short")
	}
	h := sha256.New()
	h.Write(baseKey)
	for range 1000 {
		h.Write(encrypted[:32])
	}
	block, err := aes.NewCipher(h.Sum(nil))
	if err != nil {
		return nil, err
	}
	data := encrypted[32:]
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("dpapi: LSA data %d not a multiple of 16", len(data))
	}
	iv := make([]byte, 16)
	out := make([]byte, 0, len(data))
	buf := make([]byte, 16)
	for i := 0; i < len(data); i += 16 {
		cipher.NewCBCDecrypter(block, iv).CryptBlocks(buf, data[i:i+16])
		out = append(out, buf...)
	}
	return out, nil
}

// LSAKey decrypts the PolEKList value with the boot key and returns the 32-byte
// LSA key used to protect individual secrets.
func LSAKey(bootKey, polEKList []byte) ([]byte, error) {
	// PolEKList: Version(4) KeyId(16) AlgoId(4) Flags(4) EncryptedData(...)
	if len(polEKList) < 28 {
		return nil, errors.New("dpapi: PolEKList too short")
	}
	plain, err := aesLSADecrypt(bootKey, polEKList[28:])
	if err != nil {
		return nil, err
	}
	// LSA_SECRET_BLOB: Length(4) Unknown(12) Secret(Length). The 32-byte LSA
	// key sits at offset 52 within the Secret body.
	if len(plain) < 16 {
		return nil, errors.New("dpapi: decrypted PolEKList too short")
	}
	secret := plain[16:]
	if len(secret) < 52+32 {
		return nil, errors.New("dpapi: LSA key field truncated")
	}
	return append([]byte(nil), secret[52:52+32]...), nil
}

// DPAPISystem holds the machine and user 20-byte DPAPI keys.
type DPAPISystem struct {
	Machine []byte
	User    []byte
}

// DecryptDPAPISystem decrypts the DPAPI_SYSTEM secret (its CurrVal) with the
// LSA key and splits it into the machine and user keys.
func DecryptDPAPISystem(lsaKey, currVal []byte) (*DPAPISystem, error) {
	if len(currVal) < 28 {
		return nil, errors.New("dpapi: DPAPI_SYSTEM CurrVal too short")
	}
	plain, err := aesLSADecrypt(lsaKey, currVal[28:])
	if err != nil {
		return nil, err
	}
	if len(plain) < 16 {
		return nil, errors.New("dpapi: DPAPI_SYSTEM plaintext too short")
	}
	length := binary.LittleEndian.Uint32(plain[:4])
	secret := plain[16:]
	if int(length) > len(secret) {
		return nil, errors.New("dpapi: DPAPI_SYSTEM length overflows")
	}
	secret = secret[:length]
	// DPAPI_SYSTEM: Version(4) Machine(20) User(20)
	if len(secret) < 44 {
		return nil, fmt.Errorf("dpapi: DPAPI_SYSTEM secret is %d bytes, want >= 44", len(secret))
	}
	return &DPAPISystem{
		Machine: append([]byte(nil), secret[4:24]...),
		User:    append([]byte(nil), secret[24:44]...),
	}, nil
}

// --- Master key -------------------------------------------------------------

// MasterKey decrypts the master-key blob inside a master-key file, verifying
// its HMAC, and returns the 64-byte master key. keyHash is a 20-byte DPAPI
// system key (machine or user). It returns ok=false with no error when the
// HMAC does not match, so the caller can try the other key.
func MasterKey(mkFile, keyHash []byte) (key []byte, ok bool, err error) {
	mk, err := parseMasterKeyBlob(mkFile)
	if err != nil {
		return nil, false, err
	}
	hi, err := hashFor(mk.hashAlgo)
	if err != nil {
		return nil, false, err
	}
	// MasterKey.decrypt uses SHA-1 as the HMAC hash when HashAlgo is CALG_HMAC.
	newHash := hi.newHash
	if mk.hashAlgo == calgHMAC {
		newHash = sha1.New
	}
	keyLen, ivLen, err := cipherParams(mk.cryptAlgo)
	if err != nil {
		return nil, false, err
	}
	derived := deriveKeyPBKDF2(newHash, keyHash, mk.salt, keyLen+ivLen, int(mk.rounds))
	cleartext, err := cbcDecrypt(mk.cryptAlgo, derived[:keyLen], derived[keyLen:keyLen+ivLen], mk.ciphertext)
	if err != nil {
		return nil, false, err
	}
	if len(cleartext) < 16+64 {
		return nil, false, errors.New("dpapi: master-key cleartext too short")
	}
	hmacSalt := cleartext[:16]
	mkKey := cleartext[len(cleartext)-64:]
	stored := cleartext[16 : 16+hi.macLen]
	comp := dpapiHMAC(newHash, keyHash, hmacSalt, mkKey)
	if !hmac.Equal(comp[:hi.macLen], stored) {
		return nil, false, nil
	}
	return append([]byte(nil), mkKey...), true, nil
}

// dpapiHMAC is HMAC(HMAC(key, salt), value).
func dpapiHMAC(newHash func() hash.Hash, key, salt, value []byte) []byte {
	inner := hmac.New(newHash, key)
	inner.Write(salt)
	outer := hmac.New(newHash, inner.Sum(nil))
	outer.Write(value)
	return outer.Sum(nil)
}

type masterKeyBlob struct {
	salt       []byte
	rounds     uint32
	hashAlgo   uint32
	cryptAlgo  uint32
	ciphertext []byte
}

// parseMasterKeyBlob reads the 128-byte master-key-file header and the
// MasterKey sub-blob that immediately follows it.
func parseMasterKeyBlob(b []byte) (*masterKeyBlob, error) {
	const hdr = 4 + 4 + 4 + 72 + 4 + 4 + 4 + 8 + 8 + 8 + 8 // 128
	if len(b) < hdr {
		return nil, errors.New("dpapi: master-key file too short")
	}
	mkLen := binary.LittleEndian.Uint64(b[96:104])
	if mkLen < 32 || int(mkLen) > len(b)-hdr {
		return nil, fmt.Errorf("dpapi: master-key length %d implausible", mkLen)
	}
	mk := b[hdr : hdr+int(mkLen)]
	// MasterKey: Version(4) Salt(16) Rounds(4) HashAlgo(4) CryptAlgo(4) data
	return &masterKeyBlob{
		salt:       append([]byte(nil), mk[4:20]...),
		rounds:     binary.LittleEndian.Uint32(mk[20:24]),
		hashAlgo:   binary.LittleEndian.Uint32(mk[24:28]),
		cryptAlgo:  binary.LittleEndian.Uint32(mk[28:32]),
		ciphertext: append([]byte(nil), mk[32:]...),
	}, nil
}

// --- DPAPI blob (CryptProtectData output) -----------------------------------

// Blob is a parsed DPAPI protected blob.
type Blob struct {
	MasterKeyGUID string
	Description   string
	cryptAlgo     uint32
	hashAlgo      uint32
	salt          []byte // nonce for the data session key
	hmacField     []byte // the HMac field; nonce for the sign check
	data          []byte
	sign          []byte
	toSign        []byte // rawData[20 : end-of-Data], the region the Sign covers

	// SealedLen is the number of bytes the DPAPI blob itself occupies. Any
	// bytes after it in the file are a container's own trailer — for
	// Goodix_Cache.bin, the 8-byte entropy seed.
	SealedLen int
}

// ParseBlob parses a CryptProtectData blob.
func ParseBlob(b []byte) (*Blob, error) {
	r := &reader{b: b}
	r.skip(4)  // Version
	r.skip(16) // provider GUID
	r.skip(4)  // master-key version
	mkGUID := r.take(16)
	r.skip(4) // Flags
	desc := r.take(int(r.u32()))
	cryptAlgo := r.u32()
	r.skip(4) // crypt-algo key length in bits
	salt := r.take(int(r.u32()))
	r.take(int(r.u32())) // HMacKey (usually empty)
	hashAlgo := r.u32()
	r.skip(4)                       // hash-algo length in bits
	hmacField := r.take(int(r.u32())) // HMac
	dataLen := r.u32()
	data := r.take(int(dataLen))
	signedEnd := r.pos // Sign covers rawData[20:signedEnd]
	sign := r.take(int(r.u32()))
	if r.err != nil {
		return nil, fmt.Errorf("dpapi: parsing blob: %w", r.err)
	}
	if signedEnd < 20 {
		return nil, errors.New("dpapi: blob shorter than its header")
	}
	sealedLen := r.pos
	return &Blob{
		SealedLen: sealedLen,
		MasterKeyGUID: guidString(mkGUID),
		Description:   decodeUTF16(desc),
		cryptAlgo:     cryptAlgo,
		hashAlgo:      hashAlgo,
		salt:          salt,
		hmacField:     hmacField,
		data:          data,
		sign:          sign,
		toSign:        b[20:signedEnd],
	}, nil
}

// Decrypt decrypts the blob with a master key and optional entropy, then
// verifies the Sign HMAC. A verification failure is returned as an error, so a
// returned plaintext is authenticated.
func (bl *Blob) Decrypt(masterKey, entropy []byte) ([]byte, error) {
	hi, err := hashFor(bl.hashAlgo)
	if err != nil {
		return nil, err
	}
	keyLen, _, err := cipherParams(bl.cryptAlgo)
	if err != nil {
		return nil, err
	}
	// A 64-byte master key is SHA-1'd down to a 20-byte key hash first.
	keyHash := masterKey
	if len(masterKey) != 20 {
		sum := sha1.Sum(masterKey)
		keyHash = sum[:]
	}

	// Data session key = HMAC(keyHash, salt [|| entropy]); expand to cipher key.
	sk := hmac.New(hi.newHash, keyHash)
	sk.Write(bl.salt)
	if len(entropy) > 0 {
		sk.Write(entropy)
	}
	derived := blobDeriveKey(hi, bl.cryptAlgo, keyLen, sk.Sum(nil))

	// Verify the Sign HMAC first, so the plaintext we return is authenticated
	// and a wrong key or missing entropy is reported clearly rather than as a
	// padding error: Sign == HMAC(keyHash, HMac || entropy || toSign).
	mac := hmac.New(hi.newHash, keyHash)
	mac.Write(bl.hmacField)
	if len(entropy) > 0 {
		mac.Write(entropy)
	}
	mac.Write(bl.toSign)
	if !hmac.Equal(mac.Sum(nil), bl.sign) {
		return nil, ErrHMAC
	}

	iv := make([]byte, 16)
	plain, err := cbcDecrypt(bl.cryptAlgo, derived[:keyLen], iv, bl.data)
	if err != nil {
		return nil, err
	}
	return pkcs7Unpad(plain, blockSize(bl.cryptAlgo))
}

// blobDeriveKey turns the blob session key into cipher key material, matching
// DPAPI's CryptDeriveKey: hash it down if it exceeds the hash block size, and
// expand it with the ipad/opad construction (plus DES parity fix-up) only when
// it is shorter than the cipher key.
func blobDeriveKey(hi hashInfo, cryptAlgo uint32, keyLen int, sessionKey []byte) []byte {
	derived := sessionKey
	if len(derived) > hi.blockSize {
		h := hi.newHash()
		h.Write(derived)
		derived = h.Sum(nil)
	}
	if len(derived) >= keyLen {
		return derived
	}
	buf := make([]byte, hi.blockSize)
	copy(buf, derived)
	ipad := make([]byte, hi.blockSize)
	opad := make([]byte, hi.blockSize)
	for i := range hi.blockSize {
		ipad[i] = buf[i] ^ 0x36
		opad[i] = buf[i] ^ 0x5c
	}
	h1 := hi.newHash()
	h1.Write(ipad)
	h2 := hi.newHash()
	h2.Write(opad)
	out := append(h1.Sum(nil), h2.Sum(nil)...)
	if cryptAlgo == calg3DES {
		out = fixDESParity(out)
	}
	return out
}

// fixDESParity sets the low bit of each byte to make its bit count odd, as DES
// key schedules expect.
func fixDESParity(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		hi7 := v & 0xfe
		if bits.OnesCount8(hi7)%2 == 0 {
			out[i] = hi7 | 1
		} else {
			out[i] = hi7
		}
	}
	return out
}

func blockSize(alg uint32) int {
	if alg == calg3DES {
		return 8
	}
	return 16
}

func pkcs7Unpad(b []byte, block int) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("dpapi: empty plaintext")
	}
	pad := int(b[len(b)-1])
	if pad == 0 || pad > block || pad > len(b) {
		return nil, errors.New("dpapi: bad PKCS#7 padding")
	}
	for _, c := range b[len(b)-pad:] {
		if int(c) != pad {
			return nil, errors.New("dpapi: bad PKCS#7 padding")
		}
	}
	return b[:len(b)-pad], nil
}

// --- byte-reader and small helpers ------------------------------------------

type reader struct {
	b   []byte
	pos int
	err error
}

func (r *reader) skip(n int) { r.take(n) }
func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || r.pos+n > len(r.b) {
		r.err = errors.New("short read")
		return nil
	}
	s := r.b[r.pos : r.pos+n]
	r.pos += n
	return s
}
func (r *reader) u32() uint32 {
	s := r.take(4)
	if s == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(s)
}

func guidString(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16])
}

func decodeUTF16(b []byte) string {
	if len(b) < 2 {
		return ""
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	out := make([]rune, 0, len(u))
	for _, r := range utf16.Decode(u) {
		if r == 0 {
			break
		}
		out = append(out, r)
	}
	return string(out)
}
