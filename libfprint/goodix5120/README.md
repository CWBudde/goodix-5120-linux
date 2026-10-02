# goodix5120: libfprint driver for the Goodix `27c6:5120` behind an ITE EC

A libfprint driver in C for the fingerprint reader in the Huawei MateBook `HVY-WXX9`. It follows the command sequence
of the Go reference in `cmd/goodix-probe` byte for byte, runs the TLS-PSK session itself, and matches with SIGFM.

**Status (2026-10-02):** enroll, verify and identify work on this machine through fprintd and PAM (Runs 41–45 in
[`docs/protocol.md`](../../docs/protocol.md)). Genuine scores so far 36–258594, other fingers 0–9, threshold 24.
An open takes about 965 ms. Cancellation during open, suspend/resume and autosuspend are untested live. Install for
fprintd with [`docs/fprintd.md`](../../docs/fprintd.md).

## Read this first: the hardware can be wedged

The sensor sits behind the ITE embedded controller that also drives the internal keyboard. A wrong frame has wedged
that EC and killed the keyboard until a cold power cycle, several times (`docs/protocol.md`, Runs 1–4 and 12). The
driver is built around that:

- **One way to build a command frame.** `g5120_command_frame()` refuses any opcode that is not in the send table and
  any payload whose length differs from the vendor's. An argument-less `0xe4` wedged the EC three times, and
  `/goodix5120/gate/refuses-empty-e4` pins that it cannot be built.
- **No destructive opcodes.** `0xe0` (`preset_psk_write`) and `0xf0` (`write_firmware`) are not in the send table and
  not in the source. `/goodix5120/gate/no-destructive-opcodes` checks this.
- **Health check first.** Open sends `0xa8` and requires an answer before anything else goes out, as
  `checkECResponsive` does in the Go probe. An EC left inside an unfinished TLS handshake answers nothing but
  `0xae`, and sending the init into that state cost the keyboard in Run 12.
- **Only the tested firmware.** If the firmware string is not `GF_ITE_EC_20063`, open stops before the init.
- **Everything that can fail offline fails before the first byte.** A missing or malformed PSK file, or an OpenSSL
  whose effective policy forbids suite `0x00ae`, fails open before the USB interface is claimed. Policy is
  tested on a disposable TLS server with a synthetic ClientHello; no automatic security-level downgrade occurs. An unfinished handshake leaves the EC
  stuck, so a handshake that cannot succeed must never start.
- **Fail closed.** A missing ACK or data reply, data that arrives before its ACK, an ACK status other than `0x01`,
  a handshake without progress for 5 s: each of these stops the sequence. Nothing is retried.
- **Half duplex.** Only one state machine talks to the device at a time, and nothing is written while a reply is
  awaited.
- **Completed 64-byte writes.** Each padded frame is sent one packet at a time, with the next packet submitted
  after completion. Short/zero completions stop the frame; all packets share its original write budget.
- **TLS pacing.** Between every pair of host TLS records (ServerHello/ServerHelloDone and
  ChangeCipherSpec/Finished), a 60 ms interval permits alert reads. Stale input preserves the deadline;
  fragmented TLS input is completed before more output. A 10 ms settle read precedes `0xd4`; a record
  arriving after the local handshake completed fails open. The total handshake budget bounds all states
  and transfers. Every failing run had one pair of host writes within ~1 ms (Runs 24/25 the first flight,
  26/27 Finished/`0xd4`, 28–30 ChangeCipherSpec/Finished); Go's working Run 31 never went below ~2.5 ms.
- **Listen after `0xd4`.** After the `0xd4` ACK the driver reads IN for 50 ms and sends nothing, so no two
  host writes are closer than 10 ms. A stale event does not end the window; a TLS record in it fails open.
  It was 5 s (after Go's `collect` in Run 18) until Run 43. Run 30 ruled that hypothesis out, Runs 32/33
  pinned the cause on sub-millisecond write pairs, and the EC was silent in every 5 s window.
- **Open time.** Only the attach drain waits 200 ms for silence; the drains between open steps wait 20 ms,
  since each exchange has read its replies in full. Open logs `open: N ms` (961–968 ms in Run 44; 8 s before).
- **Immediate MCU state.** After authenticated TLS, completed host records and a positive `0xd4` ACK,
  the final reply must be 20 bytes and have the TLS bit set or exactly status `0x00` (Run 26).
  This exception does not reinterpret the clear bit. Other bit-clear states, including stuck `0x08`, stop open.
- **No USB reset.** `goodixmoc` resets its device on open; this driver does not, because what a reset does to the EC
  is unknown.
- **Driver-level redaction:** the driver withholds the PSK, `0xe4`/`0xa6` reply bodies, TLS bodies, and image data.
  TLS records are logged by type and length only. This does not cover libfprint USB transfer tracing: when
  `FP_DEBUG_TRANSFER` and debug logging are enabled, the USB helper can dump raw sensitive replies.
  Leave `FP_DEBUG_TRANSFER` unset, including inherited service environments; never publish raw transfer traces.
- **Two log levels.** Debug output (`G_MESSAGES_DEBUG=libfprint-goodix5120`) carries milestones only: firmware,
  TLS up, finger down/up, image contrast, keypoints, scores, warnings. Every ACK, reply, send, TLS record and
  finger-detect reading is logged only when `GOODIX5120_TRACE` is set (not `0`); the redaction above holds at both
  levels. The offline suite runs the driver tests a second time with tracing on.

## Files

| File                                                                              | What it is                                                                                                                                     |
| --------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `goodix5120.c`, `goodix5120.h`                                                    | The libfprint driver: an `FpDevice` with its own enroll/verify/identify/capture loop, `FpiSsm` state machines, USB                             |
| `goodix5120_match.c/.h`                                                           | The stored template (a GVariant of SIGFM views), validated in full before use. GLib only                                                       |
| `goodix5120_sigfm.cpp`                                                            | The SIGFM view backend: extraction, scoring, conversion to and from the template. Keeps C++ exceptions out of the driver                       |
| `sigfm/`                                                                          | SIGFM from the `goodixtls` fork, vendored unmodified, LGPL-2.1+ ([its README](sigfm/README.md))                                                |
| `goodix5120_proto.c/.h`                                                           | Pure framing, the send gate, the vendor sequence, TLS record splitting, FDT arm/event codec and threshold rules, 12-bit unpacking. GLib only   |
| `goodix5120_tls.c/.h`                                                             | TLS 1.2 PSK server on OpenSSL memory BIOs: no socket, no thread, no subprocess. GLib and OpenSSL only                                          |
| `tests/test-goodix5120-proto.c`                                                   | Unit tests. The vectors come from the Go tests or from bytes observed on the wire                                                              |
| `tests/test-goodix5120-tls.c`                                                     | Offline rehearsal. An in-process OpenSSL PSK client stands in for the EC                                                                       |
| `tests/test-goodix5120-driver.c`, `tests/fake-libfprint/`, `tests/fake-matcher.c` | Actual driver compiled against a test-only libfprint/USB adapter and a fake SIGFM backend; synthetic lifecycle, matching and failure scenarios |
| `tests/test-goodix5120-match.c`                                                   | The template format: round trip and every refused shape                                                                                        |
| `tests/test-goodix5120-sigfm.cpp`                                                 | Real SIGFM on synthetic patterns: extraction, and that storing a view changes no score (built only with OpenCV)                                |
| `meson.build`                                                                     | Standalone helper and driver tests, without linking libfprint or USB                                                                           |
| `libfprint-register.patch`                                                        | Registers the driver in a libfprint tree                                                                                                       |
| `fprintd/goodix5120-fprintd.sh`                                                   | Points the system fprintd at this build, reversibly ([`docs/fprintd.md`](../../docs/fprintd.md))                                               |

## Building

`just bundle` (repository root) does all of the below in docker and produces the release bundle; see
`build/build-bundle.sh`. By hand:

```sh
cd libfprint                                  # a libfprint source checkout
mkdir -p libfprint/drivers/goodix5120
cp /path/to/this/dir/goodix5120*.[ch] /path/to/this/dir/goodix5120_sigfm.cpp libfprint/drivers/goodix5120/
cp -r /path/to/this/dir/sigfm libfprint/drivers/goodix5120/
patch -p1 < /path/to/this/dir/libfprint-register.patch
meson setup build -Ddrivers=goodix5120 -Dintrospection=false -Ddoc=false
ninja -C build
```

`build/libfprint/fprint-list-supported-devices` should then list `27c6:5120 | Goodix 27c6:5120 behind an ITE EC
(TLS-PSK)`. That tool reads the drivers' id tables and does not open a device.

The driver is registered as **optional**, so only `-Ddrivers=...,goodix5120` builds it. Neither `default` nor
`all` includes it. It uses two existing libfprint helpers and adds one:

- `openssl` (≥ 3.0) is already required by `uru4000`. It is used here for the TLS-PSK server.
- `pixman` is already required by the `aes3k` family. It is used here to enlarge the image (see below).
- `opencv` (≥ 4.4, `opencv4.pc`) is **new**: SIGFM uses OpenCV's SIFT and brute-force matcher. It also adds C++
  sources to libfprint, whose meson project already declares C++. Upstream libfprint has no such dependency, so this
  build stays local until upstreaming is decided.

`27c6:5120` is still in libfprint's generated "known unsupported" list. The patch leaves it there while the driver
is optional, and the hwdb tool warns about the overlap.

Tested against libfprint master `6f9479c`. The patch applies to a clean checkout, and the whole library builds with
`-Ddrivers=goodix5120` in `goodix-offline-build-opencv:26.04` (OpenCV 4.10) with no warnings from this driver under
libfprint's warning flags.

## The PSK

The EC and the host share a 32-byte TLS pre-shared key. The driver reads it as a **raw 32-byte file, not hex**, the
form `goodix-dpapi -out` writes ([`docs/protocol.md`](../../docs/protocol.md), "Unsealing the PSK offline"):

1. from the path in `GOODIX5120_PSK_FILE`, if set;
2. otherwise from `/var/lib/fprint/goodix5120/psk.bin`.

If the file is missing or is not exactly 32 bytes (a 64-character hex file is refused, not truncated), open fails
with a message naming both locations, and no USB traffic happens. A file readable by group or others draws a
warning. It should be `0600 root:root`. The fprintd installer copies it to `/etc/goodix5120/psk.bin` and sets
`GOODIX5120_PSK_FILE` in its drop-in.

### PSK provisioning (open decision)

**TODO(provisioning):** the driver does not provision a PSK and cannot. The only known way to write one is `0xe0`
(`preset_psk_write`). That opcode is destructive: it overwrites the key Windows provisioned and breaks Windows Hello
until Windows provisions again. It is absent from this driver on purpose. Until the decision in PLAN.md Phase 6 is
made with upstream:

- **dual-boot machines:** unseal the key from Windows with `goodix-dpapi`;
- **Linux-only machines:** unsupported. Provisioning would need `0xe0`, and it would first have to be shown that the
  device recovers afterwards.

## What goes on the wire

Open. This is the vendor's `vendorInit` from `cmd/goodix-probe/vendor.go`, in the order Runs 18 and 20
ran it live:

```
drain
a8 00 00                      health check: ACK + "GF_ITE_EC_20063", else stop
drain
96 01 02                      no reply
a8 00 00                      ACK + version
ae 55 a2 52 00 00             data only (20 bytes), no ACK
e4 03 00 02 bb 00 00 00 00    ACK + 41 bytes (PSK hash; never logged)
a2 01 14                      ACK + 01 00 08
82 00 00 00 04 00             ACK + a2 04 25 00 (chip ID 0x2504)
a6 00 00                      ACK + 64 bytes OTP (never logged)
a2 01 14                      ACK + 01 00 08
70 14 00                      ACK only
98 c8 0b be 00 bc 00 bc 00    ACK + 01 01
90 <224-byte config>          ACK + 01 01
d0 00 00                      no ACK: the EC opens a TLS handshake
  <- ClientHello              (EC is the TLS client, host the server)
  -> ServerHello, ServerHelloDone      one 0xb0 pack each
  <- ClientKeyExchange, ChangeCipherSpec, Finished   three transfers, all read
  -> ChangeCipherSpec, Finished        one 0xb0 pack each
d4 00 00                      ACK only
ae 55 a2 52 00 00             data only; TLS bit set or immediate status 00 after authenticated TLS + d4 ACK
drain
```

There is a short drain (20 ms of quiet; 200 ms after attach) after each init step, never after `0xd0`. TLS is 1.2 with suite `0x00ae`
`TLS_PSK_WITH_AES_128_CBC_SHA256` and identity `Client_identity`. There is no identity hint, so no
ServerKeyExchange, and the vendor's flight has none either. Records are forwarded verbatim. An alert the host side
generates is **not** sent to the EC; the Go bridge does the same.

Touch. Every action is one touch (enroll: one per stage), and a touch is the same three steps the image-device
class drove in the earlier image-device build:

```
finger down       32 0c 01 (80 t)x6 <u16 ms>   ACK, then wait (no timeout) for the 0x32 event
                  0x32 80 00 00 00 "base invalid" -> re-arm 0x32 from its readings >> 1
                  0x32 02 00 <flags> 00 finger down -> up thresholds from its readings
capture           20 01 00                      ACK, then one 0xb0 pack: one TLS application-data record
finger up         34 0e 01 (80 t)x6             ACK, then wait for 0x34 00 02 00 00 finger up
                                                -> next down thresholds = its readings >> 1
```

Every touch, the last enroll stage included, waits for the finger-up event before the action reports, so an action
always ends with nothing outstanding. (The image-device class ended an enrollment during the last lift: in Run 35
it cancelled the up wait and left the EC armed with `0x34`.) Cancellation finishes a command in flight and cancels a
wait for the finger; the session stays usable. Close sends nothing.

Threshold rules (Phase 5d, from `dump.pcapng` and the vendor debug log):

- **down:** no-finger reading `>> 1`. The first arm after load uses this unit's observed baseline
  `b8 c5 ab b9 aa b9`.
- **up:** for zone `i` with bit `i` of the down event's touch flags set, `(reading >> 1) + fdt_delta`; otherwise
  `0x19`. `fdt_delta` = 27 on this unit ("OTP tcode 272, fdt delta 27"); the vendor's default is 21.
- Every threshold is clamped to one byte.

Image: 7693 bytes of plaintext = an 8-byte header, 7680 bytes of samples and a 5-byte trailer (Run 20). A bare
7680-byte frame is also accepted, as `image.TrimFrame` accepts it; any other length is refused rather than guessed.
The samples are 12-bit, packed four to six bytes, **64 columns × 80 rows**, stretched to 8 bits per frame: the samples at
the 1st and 99th percentile become 0 and 255, values between map linearly and outliers clamp
(`g5120_samples_to_gray8_stretched`; a flat frame falls back to the Go reference's `>> 4`). The debug log reports
the two bounds, never pixels. The frame is then enlarged ×3 to 192 × 240 with pixman, as `aes4000` does for its small press sensor.

## Matching (SIGFM)

NBIS finds at most 5 minutiae per frame on this sensor (Run 37) and Bozorth3 needs 10, so the driver does not use
libfprint's image-device class, which always matches with NBIS. It is a plain `FpDevice` and runs SIGFM, the
SIFT-based matcher of the `goodixtls` fork ([`sigfm/`](sigfm/README.md)), on the driver's 192 × 240 image:

- **Enroll:** 15 touches (`G5120_ENROLL_STAGES`), each one view. Run 39 rejected 3 of 6 genuine attempts against 5
  views; Run 40 accepted 14 of 15 against 14. A touch with fewer than 25 SIFT keypoints is a retry stage
  ("press the finger flat"), as in the fork.
- **Verify / identify:** one touch, scored against every stored view; the best score must reach 24, the fork's
  threshold. In Run 40 genuine attempts scored at least 3 526 (64 × 80) and 6 643 (192 × 240), other fingers at
  most 9 and 2. The log shows the best score per print (`best SIGFM score N, threshold 24`), a number, not
  biometric data.
- **Capture** still returns the image and runs no matcher.

The print is a libfprint raw print (`FPI_PRINT_RAW`), so fprintd and the examples store it like any other.
Its data is `(yqqa(a(qq)ay))`: format version 1, the image size the views came from, and per view the keypoint
positions (rounded to pixels) and the 128-byte SIFT descriptors. SIGFM uses positions only as integer points and
OpenCV's SIFT descriptors are whole numbers 0..255, so this changes no score (`/goodix5120/sigfm/round-trip-scores`).
A 15-view template is roughly 200 KB. It is biometric data: SIFT features describe the ridge pattern. Stored data
is checked in full (type, normal form, version, image size, view and keypoint counts, descriptor lengths,
positions inside the image) before SIGFM sees it; anything else fails the action with `DATA_INVALID` before a byte
goes to the device. SIGFM's own binary deserialiser does not bound its reads and is not used.

libfprint's heat model is switched off (`temp_hot_seconds = -1`, as the match-on-chip drivers do): by default it fails
an action after about 4 minutes of use, which a slow 15-touch enroll can reach, and this sensor images only on a
touch.

Validated so far: one owner, two sessions per template, stored templates read back across sessions and through
fprintd (Runs 41–45). A template whose views overlap poorly scores low (36 in Run 44); re-enrolling with varied
placements fixed it. Not validated: dry or wet skin, other people. The fork also subtracts a no-finger background
frame; this driver does not (that needs a new live step).

## Tests (offline, no device)

```sh
meson setup build-c libfprint/goodix5120
meson test -C build-c -v
# the same under sanitizers:
meson setup build-c-asan libfprint/goodix5120 -Db_sanitize=address,undefined && meson test -C build-c-asan
```

Needs GLib/GObject/GIO and OpenSSL development headers; with OpenCV 4 the real SIGFM test is built too. These
tests cover:

- **framing:** the golden frames from `internal/proto/packet_test.go`, the checksum wrap cases, round trips with USB
  padding, and four replies **observed from this device** whose checksums must verify (the `0xa8` version reply, two
  ACKs, the unsolicited `0x32` event);
- **gate:** no `0xe0`, `0xf0`, `0xb0` or `nop`; empty `0xe4` refused; the vendor init order and payloads; the
  `0x90` config's `sum & 0xff == 0xaa`; a TLS pack holds exactly one whole record;
- **FDT:** the shared arm vectors in `internal/testfixtures/testdata/protocol.ini`, every event header counted in `dump.pcapng`, zone
  decoding, and the down/up threshold rules including clamping. `run22-session` replays Run 22's three touches:
  from the baseline arm and each logged event it must derive every up arm the probe sent (`ba198e9884ac`,
  `bf19839a969c`, `9ea8a0a491a0`, a zone without its touch flag getting `0x19`) and each next down arm
  (`b9c6acbaabba`, `b8c5abb9aab9`), all of which the EC accepted;
- **image:** the 12-bit vectors from `internal/image/image_test.go`, a 64 × 80 round trip, and the frame-layout rules
  from `frame_test.go`;
- **TLS:** a full handshake against an OpenSSL PSK client configured like the EC (no EMS, no ETM, no tickets). The
  record lengths must be **the vendor's own**: ServerHello 86 bytes, ServerHelloDone 9, ChangeCipherSpec 6, Finished
  85 (the driver log's "SENT DATA LEN"), with the EC side sending four records. A 7693-byte frame must encrypt to the
  7744-byte record body and 7753-byte pack seen in the vendor capture, and decrypt intact when fed in two pieces.
  Also covered: a wrong PSK is reported as a key mismatch with no alert left queued for the EC, an alert from the EC
  is reported, and the PSK file rules.
- **shared reference:** Go and C independently check all 14 init payloads, every config byte, reply expectations,
  FDT vectors and complete synthetic images against [one committed corpus](../../internal/testfixtures/testdata/README.md).
  The actual driver's additional health check and all init writes are checked during a real synthetic TLS session.
- **matching:** the template round trip through serialised bytes, refusal of every malformed shape, and with
  OpenCV the real SIGFM backend: extraction and identical scores before and after storing a view.
- **actual driver:** open, 15 synthetic enrollment stages in one TLS session with retry stages, verify and identify
  (match, no match, retry), malformed stored templates refused before any I/O, capture, cancellation in every
  FDT/capture state, at every USB yield and between enroll stages, unplug at every open transfer, read/write
  failures, short writes, timeouts, wrong ACKs, stale/unexpected messages, base-invalid rearming/exhaustion,
  close/reopen, and strict init reply lengths/status/chip ID/final TLS state. Rejected replies
  must stop further writes; positive cases keep secret and undocumented fields opaque. The adapter preserves
  synchronous state-machine callbacks and asynchronous
  USB completion; no device discovery or USB library is linked. See [the harness guide](tests/README.md) for its
  boundaries. These tests do not establish timing on hardware, matching accuracy, or real libfprint/GUsb integration.

## What is not done, or stubbed

- `0x98` (set DAC) sends **this unit's** OTP-derived values, and `fdt_delta` is **this unit's**. Both have to be
  derived from the `0xa6` OTP reply before the driver can serve a second machine, and the derivation is not known.
  PLAN.md also lists the OTP-derived DAC values as something never to publish. That makes them a blocker for
  upstreaming as well as a correctness issue.
- **The vendor's post-init calibration is not sent:** step 15 of its init (`36`, `50`, `36`, `82 …`, `20`, `36`).
  Neither is the `0x50` "nav mode" it sends after each finger-up, which appears only in the driver log.
- No suspend/resume handling, and no command that ends a session on close. The EC keeps its TLS session and last FDT
  arm, as Windows leaves it. Each open repeats the full init and handshake; fprintd opens per operation, and many
  opens in a row have worked (Runs 43–45).
- PSK provisioning (see above).
- No umockdev recording under `tests/` in libfprint style, because making one needs the device. Captures also must
  not enter this repository.

## Open questions

1. **Cancellation during open.** A command in flight finishes, then the action ends; a cancel during the finger wait
   leaves the session usable. A cancel in the middle of the TLS handshake has not been tried live. An unfinished
   handshake is the one state known to leave the EC stuck (`docs/protocol.md`, "Recovering the EC").
2. **What the EC is left in after a failure.** A handshake failure (wrong PSK, timeout) probably leaves the EC stuck.
   The driver says so and sends nothing more; the next open's health check then refuses. Sending a TLS fatal alert
   to unstick it is untested ("Recovering the EC", item 4) and deliberately not done. After an image, TLS or
   transport failure during an operation, the driver discards its TLS session and refuses every action until
   close/reopen, sending nothing. Reopening after a failed operation has only been tested with a synthetic EC.
3. **Suspend and autosuspend.** The hwdb gives this device `ID_AUTOSUSPEND=1`. Whether a suspend or USB autosuspend
   between sessions upsets the EC is unknown.
4. **ACK status.** Only `0x01` has ever been seen, and anything else stops the driver. That may be too strict.
5. **Base invalid.** Run 35 saw one base-invalid event and the driver re-armed from its readings. If an event ever
   carries zeroes instead, the driver keeps its previous thresholds and gives up after 8 in a row per action.
6. **Kernel driver.** `cdc_acm` is not bound on this machine. If it binds elsewhere, the claim detaches it
   (`G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER`), and close requests reattachment. Real restoration is
   unverified; [GUsb](https://github.com/hughsie/libgusb/blob/0.4.9/gusb/gusb-device.c#L1602) has no rollback if the
   claim itself fails.
