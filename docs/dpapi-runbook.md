# DPAPI unseal runbook — Phase 5, option 1

Recovering the Goodix TLS-PSK from `C:\ProgramData\Goodix\Goodix_Cache.bin` by unsealing it offline with the
machine's own DPAPI keys. This is the non-destructive option 1 in [`PLAN.md`](../PLAN.md) Phase 5: it reads
files that are already on the machine, opens no device, touches no hardware, and leaves Windows Hello working.
There is no password prompt and no brute force — a machine-scoped DPAPI secret is decrypted deterministically
from the registry, which is exactly what the LocalSystem service does at runtime.

## Safety

- **Read-only and offline.** `cmd/goodix-dpapi` reads the two registry hives, one master-key file and the blob,
  and computes. It imports only `internal/dpapi` and `internal/winreg`, both stdlib-only; it links no USB code
  and cannot reach the embedded controller. This has nothing to do with the keyboard incident.
- **Secret-bearing output.** The recovered plaintext is the device PSK. The tool handles it the way this repo
  handles the OTP and the `0xe4` reply: by default it prints only the plaintext length and its SHA-256, writes
  the raw bytes only to a `-out` file, and prints the hex only with `-print-psk`. Send any `-out` file to a
  gitignored path (`captures/…` or a `*.bin` name). **Never commit the PSK, the master keys, the DPAPI_SYSTEM
  keys, the boot key, or the secondary entropy.**

## The chain

Each stage is verified, so a wrong input is reported rather than passed on as garbage:

1. **Boot key** (SysKey) — assembled from the class names of `ControlSet00N\Control\Lsa\{JD,Skew1,GBG,Data}`
   in the `SYSTEM` hive, descrambled by the fixed permutation.
2. **LSA key** — `Policy\PolEKList` in the `SECURITY` hive, AES-decrypted with the boot key; the 32-byte key is
   at offset 52 of the decrypted secret.
3. **DPAPI_SYSTEM** — `Policy\Secrets\DPAPI_SYSTEM\CurrVal`, AES-decrypted with the LSA key, split into the
   20-byte machine and user keys. A correct result begins with version `01000000` and is 44 bytes.
4. **Master key** — the file under `…\Microsoft\Protect\S-1-5-18\<GUID>` whose name is the blob's master-key
   GUID. Decrypted with the machine (then user) key via DPAPI's key-stretch and **verified by its own HMAC**.
   The derivation is not RFC PBKDF2: each round feeds the running XOR accumulator back into the PRF, and the
   stored HMAC tag is truncated to 16 bytes for a SHA-512 master key. This is what Windows/impacket do; getting
   it wrong verifies nothing.
5. **Blob** — `Goodix_Cache.bin`, decrypted with the master key (SHA-1'd to a 20-byte key hash first) and
   verified by its Sign HMAC over `rawData[20 : end-of-Data]`.

## Running it

```sh
go build -buildvcs=false ./cmd/goodix-dpapi
./goodix-dpapi \
  -sys  /mnt/Windows/Windows/System32/config/SYSTEM \
  -sec  /mnt/Windows/Windows/System32/config/SECURITY \
  -blob /mnt/Windows/ProgramData/Goodix/Goodix_Cache.bin \
  -mkdir /mnt/Windows/Windows/System32/Microsoft/Protect/S-1-5-18
```

Give `-mk <file>` instead of `-mkdir` to name the master-key file directly, `-entropy HEX` to supply secondary
entropy, and `-out FILE` / `-print-psk` to emit the plaintext once it decrypts.

`TestLiveMasterKeys` re-derives the chain against a mounted volume and asserts every machine master key verifies:

```sh
go test ./internal/dpapi -run TestLiveMasterKeys \
  -args -dpapi-sys /mnt/Windows/Windows/System32/config/SYSTEM \
        -dpapi-sec /mnt/Windows/Windows/System32/config/SECURITY \
        -dpapi-mkdir /mnt/Windows/Windows/System32/Microsoft/Protect/S-1-5-18
```

## Result (2026-09-20)

The chain works end to end on this machine. The boot key, LSA key and DPAPI_SYSTEM keys are recovered; every one
of the 26 machine-store `S-1-5-18` master keys (SHA-512/AES-256, 8000 rounds) verifies against its own HMAC.

`Goodix_Cache.bin` is a well-formed DPAPI blob: master-key GUID `557da6c3-0d3d-4fdf-8834-befbc7331dd6` (present
in `S-1-5-18`, created the same day, 2021-03-16), AES-256/SHA-512, 32-byte salt, 32-byte HMac field, 48-byte
ciphertext, 64-byte Sign, then 8 trailing bytes that are not the blob. Its master key is recovered and verified.

**But the blob does not decrypt with the master key alone: it was sealed with application-specific secondary
entropy** (the `pOptionalEntropy` argument to `CryptProtectData`). This is certain, not a guess — the master key
is authenticated by its own HMAC and every blob field is parsed correctly, so entropy is the only remaining free
input, and the Sign HMAC fails without it. The 8 trailing bytes of the cache file are not the entropy.

So the PSK is **not** recoverable from the cache file and the OS keys alone.

### The entropy is DRBG-generated, not a constant (static analysis, 2026-09-20)

Static analysis of `gfusb.dll` settled what the entropy is. The DPAPI calls go through one generic wrapper
(RVA `0xb490`, which logs `inbuf_len %d, entropy_len %d, len_out %d` and calls `CryptProtectData` /
`CryptUnprotectData`); the wrapper takes the entropy as an argument, so the caller builds it. The cache seal and
read code (around RVA `0x32b00`–`0x33300`, right next to the `Goodix_Cache.bin` string references) builds the
entropy with a routine whose log tag is **`generate_entropy2`** (RVA `0x32760`), and that routine uses a DRBG:
mbedTLS `CTR_DRBG`, and `CryptGenRandom` is imported. So the entropy is **program-generated, not a fixed
constant** — "extract the constant" is not the shape of the answer.

Two consequences follow. First, the read (unprotect) path cannot use fresh randomness — it has to reproduce the
seal's entropy — so the entropy is **deterministic from stored inputs on read**, and is therefore reconstructible
offline in principle. Second, reconstructing it means replaying `generate_entropy2` byte-for-byte through several
mbedTLS calls, from whatever seed it reads back (the cache file's 8 trailing bytes are the likely seed; passing
them *raw* as entropy fails, consistent with them being a seed the routine expands, not the entropy itself). That
is a real reverse-engineering effort with a real chance of a machine- or install-specific input.

The open Phase 5 decision is therefore between **(a)** finishing that derivation by static RE, and **(b)** Phase 5
option 2 — reading the PSK or the entropy from the running Windows driver, which reconstructs the entropy itself
and sidesteps the derivation. Once the entropy bytes are known by either route, `goodix-dpapi -entropy HEX`
completes the unseal in one step; the whole DPAPI chain up to that point is done and verified.

### Derivation recovered, PSK unsealed (2026-09-20)

`generate_entropy2` was then read out of the disassembly in full. It takes the 8-byte seed and produces the
48-byte entropy:

```
root    = SHA256(seed)                          // seed = 8 bytes
entropy = root[16:32] || SHA256(root[0:16] || K)   // 48 bytes
```

`K` is a fixed 16-byte key folded from three 16-byte `.data` constants (`0x312cb0`/`0x312cc0`/`0x312cd0`):
`K[0:8] = C0[0:8] ^ C1[0:8] ^ C0[8:16]` and `K[8:16] = C1[8:16] ^ C2[8:16] ^ C2[0:8]`. The hash is SHA-256,
confirmed by the routine's own "Calculate SHA256 FAILED" string. The 8-byte seed is generated once at seal time
and **stored as the 8 bytes trailing the DPAPI blob in the cache file**; on read those same bytes are expanded
back into the entropy. That is why the file has exactly 8 trailing bytes, and why passing them raw as entropy
failed — they are the seed, not the entropy.

`internal/dpapi/goodix.go` reproduces this (the three constants are kept verbatim, so `K` is auditable against
the binary), and `goodix-dpapi -goodix` reads the trailing seed, derives the entropy and unseals in one step:

```sh
./goodix-dpapi -sys … -sec … -mkdir … \
  -blob /mnt/Windows/ProgramData/Goodix/Goodix_Cache.bin -goodix -out captures/goodix-psk.bin
```

**Result: the cache unseals to a 32-byte plaintext, HMAC-verified — the device PSK.** Phase 5 option 1 is
complete: the TLS-PSK is recoverable offline from the machine's own files, non-destructively, with Windows Hello
untouched. The PSK, the 8-byte seed and the boot key are machine-specific secrets, kept out of the repository
(the PSK lands only in gitignored `captures/`); `K` and the derivation are vendor constants and are in the code.
