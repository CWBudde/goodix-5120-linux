/*
 * Goodix 27c6:5120 (behind an ITE EC) — wire protocol helpers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 *
 * Pure functions only: no I/O, no libfprint types, GLib only. This is the C
 * mirror of the Go reference in internal/proto and internal/image of the
 * goodix-5120-linux repository, and its unit tests reuse that code's vectors.
 */

#pragma once

#include <glib.h>

G_BEGIN_DECLS

/* ---- Framing ------------------------------------------------------------
 *
 * Two nested layers (docs/protocol.md, "Framing"):
 *
 *   pack:    [flags:1][len:2 LE = N][checksum:1][payload:N]
 *            checksum = (flags + len_lo + len_hi) & 0xff
 *   message: [cmd:1][len:2 LE = N+1][payload:N][checksum:1]
 *            checksum = (0xaa - sum(all preceding bytes)) & 0xff,
 *            or the literal 0x88 in no-checksum mode (accepted on decode)
 */

#define G5120_FLAG_MESSAGE   0xa0
#define G5120_FLAG_TLS       0xb0
#define G5120_FLAG_TLS_ALT   0xb2

#define G5120_PACK_HEADER_LEN     4
#define G5120_MESSAGE_HEADER_LEN  3
#define G5120_NO_CHECKSUM_MARKER  0x88

/* Outbound frames are zero-padded to a multiple of the bulk packet size. */
#define G5120_USB_PACKET_SIZE 0x40

/* An acknowledgement is a message with cmd 0xb0 and payload [cmd][status].
 * Receive-only: it is deliberately absent from the send table below. Not to be
 * confused with G5120_FLAG_TLS, which has the same value at the pack layer. */
#define G5120_CMD_ACK 0xb0

#define G5120_PROTO_ERROR (g5120_proto_error_quark ())
typedef enum {
  G5120_PROTO_ERROR_SHORT,     /* buffer too short for a header */
  G5120_PROTO_ERROR_LENGTH,    /* declared length inconsistent with the buffer */
  G5120_PROTO_ERROR_CHECKSUM,  /* checksum did not verify */
  G5120_PROTO_ERROR_REFUSED,   /* the send gate refused the frame */
  G5120_PROTO_ERROR_FDT,       /* not a well-formed finger-detect frame */
  G5120_PROTO_ERROR_IMAGE,     /* image plaintext matches no known layout */
} G5120ProtoError;

GQuark g5120_proto_error_quark (void);

guint8 g5120_pack_checksum (const guint8 *header3);
guint8 g5120_message_checksum (const guint8 *data,
                               gsize         len);

/* Builds [cmd][len][payload][checksum]. */
GByteArray *g5120_message_encode (guint8        cmd,
                                  const guint8 *payload,
                                  gsize         payload_len,
                                  gboolean      no_checksum);

/* Builds [flags][len][checksum][payload]. */
GByteArray *g5120_pack_encode (guint8        flags,
                               const guint8 *payload,
                               gsize         payload_len);

/* Zero-pads to a multiple of G5120_USB_PACKET_SIZE, in place. */
void g5120_pad_to_packet (GByteArray *frame);

/* The common case: a checksummed message in an 0xa0 pack, padded, ready for
 * the OUT endpoint. It runs g5120_check_send() first and returns NULL with
 * @error set if the gate refuses. There is no other way to build a command
 * frame in this driver. */
GByteArray *g5120_command_frame (guint8        cmd,
                                 const guint8 *payload,
                                 gsize         payload_len,
                                 GError      **error);

/* A TLS-data pack (0xb0) around exactly one whole TLS record, padded. Refuses
 * anything that is not a single whole record. */
GByteArray *g5120_tls_frame (const guint8 *record,
                             gsize         record_len,
                             GError      **error);

/* Parses the pack layer. Bytes past the declared length (USB padding) are
 * ignored. @payload points into @buf. */
gboolean g5120_pack_decode (const guint8  *buf,
                            gsize          len,
                            guint8        *flags,
                            const guint8 **payload,
                            gsize         *payload_len,
                            GError       **error);

/* Parses exactly one message; trailing bytes are an error. @payload points
 * into @buf. */
gboolean g5120_message_decode (const guint8  *buf,
                               gsize          len,
                               guint8        *cmd,
                               const guint8 **payload,
                               gsize         *payload_len,
                               GError       **error);

/* TRUE if the message is an ACK; fills in the acknowledged command and the
 * status byte (0x01 is the only value ever observed). */
gboolean g5120_ack_decode (guint8        cmd,
                           const guint8 *payload,
                           gsize         payload_len,
                           guint8       *acked,
                           guint8       *status);

/* ---- The send gate -------------------------------------------------------
 *
 * Every opcode this driver may put on the wire, with the exact payload length
 * the vendor driver sends. An opcode not in the table cannot be sent at all.
 * The destructive opcodes (0xe0 preset_psk_write, 0xf0 write_firmware) are
 * not in it and must never be added: a wrong frame has wedged this EC and
 * killed the laptop's keyboard. An argument-less 0xe4 did exactly that, which
 * is why every entry carries a payload length and the gate checks it.
 */

typedef struct
{
  guint8      cmd;
  const char *name;
  gsize       payload_len;
} G5120Opcode;

const G5120Opcode *g5120_opcode_lookup (guint8 cmd);
const G5120Opcode *g5120_opcode_table (gsize *n_entries);

gboolean g5120_check_send (guint8   cmd,
                           gsize    payload_len,
                           GError **error);

/* ---- Vendor sequence -----------------------------------------------------
 *
 * The Windows driver's init, byte for byte (cmd/goodix-probe/vendor.go,
 * `vendorInit`). Replies: see G5120Reply.
 */

typedef enum {
  G5120_REPLY_NONE = 0,       /* nothing comes back (0x96) */
  G5120_REPLY_ACK  = 1 << 0,  /* a 0xb0 ACK message */
  G5120_REPLY_DATA = 1 << 1,  /* a data message with the same cmd */
  G5120_REPLY_TLS  = 1 << 2,  /* the EC opens a TLS handshake (0xd0) */
} G5120Reply;

typedef struct
{
  guint8        cmd;
  const guint8 *payload;
  gsize         payload_len;
  G5120Reply    reply;
  gboolean      secret_reply;   /* never log the data reply (0xe4, 0xa6) */
  const char   *purpose;
} G5120Step;

/* Steps 1..11 of the vendor init: everything before 0xd0. */
const G5120Step *g5120_vendor_init_pre_tls (gsize *n_steps);
/* 0xa8 as the health check the Go probe sends before anything else. */
const G5120Step *g5120_step_health_check (void);
const G5120Step *g5120_step_request_tls (void);      /* 0xd0 */
const G5120Step *g5120_step_tls_established (void);  /* 0xd4 */
const G5120Step *g5120_step_mcu_state (void);        /* 0xae */
const G5120Step *g5120_step_get_image (void);        /* 0x20 01 00 */

/* The firmware string this driver has been brought up against. */
#define G5120_FIRMWARE_TESTED "GF_ITE_EC_20063"

/* ---- TLS records ---------------------------------------------------------- */

#define G5120_TLS_RECORD_HEADER_LEN 5
/* TLS 1.2 plaintext ceiling plus maximum cipher expansion (RFC 5246 6.2.3). */
#define G5120_TLS_MAX_BODY_LEN ((1 << 14) + 2048)
#define G5120_TLS_CHANGE_CIPHER_SPEC 0x14
#define G5120_TLS_ALERT              0x15
#define G5120_TLS_HANDSHAKE          0x16
#define G5120_TLS_APPLICATION_DATA   0x17

/* Returns the length of the whole record at the start of @buf, or 0 if @buf
 * does not yet hold a complete record. */
gsize g5120_tls_record_len (const guint8 *buf,
                            gsize         len);

const char *g5120_tls_type_name (guint8 type);

/* ---- Finger detection (FDT) ----------------------------------------------
 *
 * Arm payloads (observed, dump.pcapng + vendor debug log):
 *   0x32 down:   0c 01 + 6 x (80 thr) + uint16 LE timestamp  (16 bytes)
 *   0x34 up:     0e 01 + 6 x (80 thr)                        (14 bytes)
 *   0x36 manual: 0d 01 + 6 x (80 thr)                        (14 bytes)
 * Events: 4-byte header + 6 x uint16 LE zone readings (16 bytes).
 *   0x32 02 00 <touchflags> 00  finger down
 *   0x32 80 00 00 00            base invalid: zones carry the current
 *                               no-finger readings; re-arm 0x32 from them
 *   0x34 00 02 00 00            finger up
 *   0x36 00 01 <flags> 00       manual
 */

#define G5120_FDT_ZONES 6
#define G5120_FDT_EVENT_LEN 16
#define G5120_FDT_DOWN_ARM_LEN 16
#define G5120_FDT_UP_ARM_LEN 14

#define G5120_CMD_FDT_DOWN   0x32
#define G5120_CMD_FDT_UP     0x34
#define G5120_CMD_FDT_MANUAL 0x36

/* Zones whose touch bit is clear get this up-threshold. */
#define G5120_FDT_UP_UNTOUCHED 0x19
/* fdt_delta: "OTP tcode 272, fdt delta 27" in this device's vendor log; the
 * vendor's default when the OTP gives none is 21. */
#define G5120_FDT_DELTA_THIS_DEVICE 27
#define G5120_FDT_DELTA_DEFAULT     21

typedef enum {
  G5120_FDT_EVENT_UNKNOWN = 0,
  G5120_FDT_EVENT_DOWN,
  G5120_FDT_EVENT_UP,
  G5120_FDT_EVENT_MANUAL,
  G5120_FDT_EVENT_BASE_INVALID,
} G5120FdtEventKind;

typedef struct
{
  G5120FdtEventKind kind;
  guint8            header[4];
  guint8            touchflags;          /* header[2] */
  guint16           zones[G5120_FDT_ZONES];
} G5120FdtEvent;

/* TRUE for the three FDT opcodes. */
gboolean g5120_is_fdt_cmd (guint8 cmd);

gboolean g5120_fdt_decode_event (guint8         cmd,
                                 const guint8  *payload,
                                 gsize          len,
                                 G5120FdtEvent *event,
                                 GError       **error);

const char *g5120_fdt_event_kind_name (G5120FdtEventKind kind);

/* Writes the arm payload for @cmd into @out (at least 16 bytes) and returns
 * its length, or 0 if @cmd is not an FDT opcode. @timestamp is only used by
 * 0x32. */
gsize g5120_fdt_encode_arm (guint8       cmd,
                            const guint8 thresholds[G5120_FDT_ZONES],
                            guint16      timestamp,
                            guint8      *out);

/* Down thresholds from no-finger readings: reading >> 1 (clamped to 0xff). */
void g5120_fdt_down_thresholds (const guint16 zones[G5120_FDT_ZONES],
                                guint8        thresholds[G5120_FDT_ZONES]);

/* Up thresholds from finger-down readings: zone i with bit i of @touchflags
 * set gets (reading >> 1) + @delta (clamped); a zone with the bit clear gets
 * G5120_FDT_UP_UNTOUCHED. */
void g5120_fdt_up_thresholds (const guint16 zones[G5120_FDT_ZONES],
                              guint8        touchflags,
                              guint8        delta,
                              guint8        thresholds[G5120_FDT_ZONES]);

/* This device's observed no-finger arm, used for the very first 0x32 before
 * any reading is known. Device specific. */
extern const guint8 g5120_fdt_initial_down_thresholds[G5120_FDT_ZONES];

/* ---- Image --------------------------------------------------------------
 *
 * 64 columns x 80 rows (Run 20), 12-bit samples packed four per six bytes:
 *   s0 = (b0 & 0x0f) << 8 | b1     s1 = b3 << 4 | b0 >> 4
 *   s2 = (b5 & 0x0f) << 8 | b2     s3 = b4 << 4 | b5 >> 4
 * The decrypted frame is 8 header bytes + 7680 sample bytes + 5 trailer
 * bytes = 7693 (Run 20). A bare 7680-byte frame is also accepted, as the Go
 * reference does; any other length is refused rather than guessed.
 */

#define G5120_IMG_WIDTH  64
#define G5120_IMG_HEIGHT 80
#define G5120_IMG_SAMPLES (G5120_IMG_WIDTH * G5120_IMG_HEIGHT)
#define G5120_IMG_PACKED_LEN (G5120_IMG_SAMPLES / 4 * 6)               /* 7680 */
#define G5120_IMG_HEADER_LEN  8
#define G5120_IMG_TRAILER_LEN 5
#define G5120_IMG_WRAPPED_LEN (G5120_IMG_PACKED_LEN + G5120_IMG_HEADER_LEN + G5120_IMG_TRAILER_LEN) /* 7693 */

/* Unpacks @n_samples 12-bit samples (a multiple of 4) from @raw. */
gboolean g5120_decode_12bit (const guint8 *raw,
                             gsize         raw_len,
                             guint16      *out,
                             gsize         n_samples,
                             GError      **error);

/* Returns a pointer to the 7680 packed sample bytes inside a decrypted frame,
 * or NULL with @error set if its length matches neither layout. */
const guint8 *g5120_frame_samples (const guint8 *plain,
                                   gsize         len,
                                   gboolean     *wrapped,
                                   GError      **error);

/* Reduces 12-bit samples to 8 bits by taking the high byte (value >> 4), as
 * the Go reference does. */
void g5120_samples_to_gray8 (const guint16 *samples,
                             gsize          n,
                             guint8        *out);

#define G5120_SAMPLE_LEVELS     4096
#define G5120_STRETCH_CLIP_DIV  100

/* Stretches the frame's own sample range to 0..255: the samples at the 1st
 * and 99th percentile (rank n/100 from either end) become 0 and 255, values
 * between map linearly with rounding, values outside clamp. Run 32's >> 4
 * frame found no minutiae; the sensor's raw range is unknown, so this is a
 * per-frame normalisation, not a calibration. A frame whose two percentiles
 * coincide falls back to g5120_samples_to_gray8. The chosen bounds go to
 * @lo_out / @hi_out when non-NULL. */
void g5120_samples_to_gray8_stretched (const guint16 *samples,
                                       gsize          n,
                                       guint8        *out,
                                       guint16       *lo_out,
                                       guint16       *hi_out);

/* Wire-level logging (every ACK, reply, send, TLS record, finger-detect
 * reading) is off unless GOODIX5120_TRACE is set to a value other than
 * "" or "0"; milestones log either way. Read once per process. */
gboolean g5120_trace_enabled (void);

G_END_DECLS
