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
 */

#include <string.h>

#include "goodix5120_proto.h"

G_DEFINE_QUARK (g5120 - proto - error - quark, g5120_proto_error)

/* ---- Framing ------------------------------------------------------------ */

guint8
g5120_pack_checksum (const guint8 *header3)
{
  return (guint8) (header3[0] + header3[1] + header3[2]);
}

guint8
g5120_message_checksum (const guint8 *data, gsize len)
{
  guint8 sum = 0;

  for (gsize i = 0; i < len; i++)
    sum += data[i];

  return (guint8) (0xaa - sum);
}

GByteArray *
g5120_message_encode (guint8        cmd,
                      const guint8 *payload,
                      gsize         payload_len,
                      gboolean      no_checksum)
{
  GByteArray *out;
  guint8 header[G5120_MESSAGE_HEADER_LEN];
  guint8 checksum;

  g_return_val_if_fail (payload_len < G_MAXUINT16, NULL);

  header[0] = cmd;
  header[1] = (payload_len + 1) & 0xff;
  header[2] = ((payload_len + 1) >> 8) & 0xff;

  out = g_byte_array_sized_new (G5120_MESSAGE_HEADER_LEN + payload_len + 1);
  g_byte_array_append (out, header, sizeof (header));
  if (payload_len > 0)
    g_byte_array_append (out, payload, payload_len);

  if (no_checksum)
    checksum = G5120_NO_CHECKSUM_MARKER;
  else
    checksum = g5120_message_checksum (out->data, out->len);
  g_byte_array_append (out, &checksum, 1);

  return out;
}

GByteArray *
g5120_pack_encode (guint8 flags, const guint8 *payload, gsize payload_len)
{
  GByteArray *out;
  guint8 header[G5120_PACK_HEADER_LEN];

  g_return_val_if_fail (payload_len <= G_MAXUINT16, NULL);

  header[0] = flags;
  header[1] = payload_len & 0xff;
  header[2] = (payload_len >> 8) & 0xff;
  header[3] = g5120_pack_checksum (header);

  out = g_byte_array_sized_new (G5120_PACK_HEADER_LEN + payload_len);
  g_byte_array_append (out, header, sizeof (header));
  if (payload_len > 0)
    g_byte_array_append (out, payload, payload_len);

  return out;
}

void
g5120_pad_to_packet (GByteArray *frame)
{
  gsize rem = frame->len % G5120_USB_PACKET_SIZE;

  if (rem != 0)
    {
      gsize old = frame->len;

      g_byte_array_set_size (frame, old + (G5120_USB_PACKET_SIZE - rem));
      memset (frame->data + old, 0, frame->len - old);
    }
}

GByteArray *
g5120_command_frame (guint8        cmd,
                     const guint8 *payload,
                     gsize         payload_len,
                     GError      **error)
{
  g_autoptr(GByteArray) msg = NULL;
  GByteArray *pack;

  if (!g5120_check_send (cmd, payload_len, error))
    return NULL;

  msg = g5120_message_encode (cmd, payload, payload_len, FALSE);
  pack = g5120_pack_encode (G5120_FLAG_MESSAGE, msg->data, msg->len);
  g5120_pad_to_packet (pack);

  return pack;
}

GByteArray *
g5120_tls_frame (const guint8 *record, gsize record_len, GError **error)
{
  GByteArray *pack;

  if (record_len < G5120_TLS_RECORD_HEADER_LEN || record_len > G_MAXUINT16 ||
      record[0] < G5120_TLS_CHANGE_CIPHER_SPEC || record[0] > G5120_TLS_APPLICATION_DATA ||
      record[1] != 3 || record[2] < 1 || record[2] > 3 ||
      ((record[3] << 8) | record[4]) == 0 ||
      ((record[3] << 8) | record[4]) > G5120_TLS_MAX_BODY_LEN ||
      g5120_tls_record_len (record, record_len) != record_len)
    {
      g_set_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_REFUSED,
                   "refusing a TLS-data pack of %" G_GSIZE_FORMAT " bytes: "
                   "it is not exactly one whole TLS record", record_len);
      return NULL;
    }

  pack = g5120_pack_encode (G5120_FLAG_TLS, record, record_len);
  if (pack == NULL)
    {
      g_set_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_REFUSED,
                   "cannot encode the TLS-data pack");
      return NULL;
    }
  g5120_pad_to_packet (pack);

  return pack;
}

gboolean
g5120_pack_decode (const guint8  *buf,
                   gsize          len,
                   guint8        *flags,
                   const guint8 **payload,
                   gsize         *payload_len,
                   GError       **error)
{
  gsize n;

  if (len < G5120_PACK_HEADER_LEN)
    {
      g_set_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_SHORT,
                   "pack needs %d bytes, got %" G_GSIZE_FORMAT,
                   G5120_PACK_HEADER_LEN, len);
      return FALSE;
    }

  if (buf[3] != g5120_pack_checksum (buf))
    {
      g_set_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_CHECKSUM,
                   "pack checksum 0x%02x, want 0x%02x",
                   buf[3], g5120_pack_checksum (buf));
      return FALSE;
    }

  n = buf[1] | (buf[2] << 8);
  if (len < G5120_PACK_HEADER_LEN + n)
    {
      g_set_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_LENGTH,
                   "pack declares %" G_GSIZE_FORMAT " payload bytes, buffer holds %" G_GSIZE_FORMAT,
                   n, len - G5120_PACK_HEADER_LEN);
      return FALSE;
    }

  *flags = buf[0];
  *payload = buf + G5120_PACK_HEADER_LEN;
  *payload_len = n;
  return TRUE;
}

gboolean
g5120_message_decode (const guint8  *buf,
                      gsize          len,
                      guint8        *cmd,
                      const guint8 **payload,
                      gsize         *payload_len,
                      GError       **error)
{
  gsize length, total;
  guint8 got;

  if (len < G5120_MESSAGE_HEADER_LEN + 1)
    {
      g_set_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_SHORT,
                   "message needs %d bytes, got %" G_GSIZE_FORMAT,
                   G5120_MESSAGE_HEADER_LEN + 1, len);
      return FALSE;
    }

  length = buf[1] | (buf[2] << 8);
  if (length < 1)
    {
      g_set_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_LENGTH,
                   "message length field is 0, want at least 1");
      return FALSE;
    }

  total = G5120_MESSAGE_HEADER_LEN + length;
  if (len != total)
    {
      g_set_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_LENGTH,
                   "message declares %" G_GSIZE_FORMAT " bytes, buffer holds %" G_GSIZE_FORMAT,
                   total, len);
      return FALSE;
    }

  got = buf[total - 1];
  if (got != G5120_NO_CHECKSUM_MARKER &&
      got != g5120_message_checksum (buf, total - 1))
    {
      g_set_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_CHECKSUM,
                   "message checksum 0x%02x, want 0x%02x",
                   got, g5120_message_checksum (buf, total - 1));
      return FALSE;
    }

  *cmd = buf[0];
  *payload = buf + G5120_MESSAGE_HEADER_LEN;
  *payload_len = length - 1;
  return TRUE;
}

gboolean
g5120_ack_decode (guint8        cmd,
                  const guint8 *payload,
                  gsize         payload_len,
                  guint8       *acked,
                  guint8       *status)
{
  if (cmd != G5120_CMD_ACK || payload_len != 2)
    return FALSE;

  *acked = payload[0];
  *status = payload[1];
  return TRUE;
}

/* ---- The send gate ------------------------------------------------------ */

/* Mirrors internal/proto/opcode.go minus the opcodes this driver never sends
 * (nop, nav_mode, check_firmware). Every length is what the vendor driver was
 * observed to send. 0xe0 and 0xf0 are absent on purpose and forever. */
static const G5120Opcode opcode_table[] = {
  { 0xa8, "firmware_version",             2 },
  { 0xa6, "read_otp",                     2 },
  { 0xae, "get_mcu_state",                5 },
  { 0x82, "read_register",                5 },
  { 0xe4, "preset_psk_read",              8 },  /* empty payload wedged the EC */
  { 0x96, "enable_chip",                  2 },
  { 0xa2, "reset",                        2 },
  { 0x70, "mcu_switch_to_idle_mode",      2 },
  { 0x98, "set_dac",                      8 },
  { 0x90, "upload_config_mcu",            224 },
  { 0xd0, "request_tls_connection",       2 },
  { 0xd4, "tls_successfully_established", 2 },
  { 0x20, "mcu_get_image",                2 },
  { 0x32, "fdt_down",                     16 },
  { 0x34, "fdt_up",                       14 },
  { 0x36, "fdt_manual",                   14 },
};

const G5120Opcode *
g5120_opcode_table (gsize *n_entries)
{
  *n_entries = G_N_ELEMENTS (opcode_table);
  return opcode_table;
}

const G5120Opcode *
g5120_opcode_lookup (guint8 cmd)
{
  for (gsize i = 0; i < G_N_ELEMENTS (opcode_table); i++)
    if (opcode_table[i].cmd == cmd)
      return &opcode_table[i];

  return NULL;
}

gboolean
g5120_check_send (guint8 cmd, gsize payload_len, GError **error)
{
  const G5120Opcode *op = g5120_opcode_lookup (cmd);

  if (op == NULL)
    {
      g_set_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_REFUSED,
                   "refusing opcode 0x%02x: it is not in this driver's send table, "
                   "so its arguments are unknown", cmd);
      return FALSE;
    }

  if (payload_len != op->payload_len)
    {
      g_set_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_REFUSED,
                   "refusing %s (0x%02x) with a %" G_GSIZE_FORMAT "-byte payload: "
                   "the vendor driver sends exactly %" G_GSIZE_FORMAT,
                   op->name, cmd, payload_len, op->payload_len);
      return FALSE;
    }

  return TRUE;
}

/* ---- Vendor sequence ---------------------------------------------------- */

static const guint8 p_enable_chip[] = { 0x01, 0x02 };
static const guint8 p_zero2[] = { 0x00, 0x00 };
/* 0x55 then a uint32 LE host timestamp. The vendor sends a live counter; the
 * EC has never been seen to react to it, so the Go reference's fixed value is
 * used and frames stay reproducible. */
static const guint8 p_mcu_state[] = { 0x55, 0xa2, 0x52, 0x00, 0x00 };
/* data_type 0xbb020003 LE, then a uint32 length of 0. NEVER send 0xe4 without
 * this argument: the empty form wedged the EC in Runs 1, 2 and 4. */
static const guint8 p_psk_read[] = { 0x03, 0x00, 0x02, 0xbb, 0x00, 0x00, 0x00, 0x00 };
static const guint8 p_reset[] = { 0x01, 0x14 };
static const guint8 p_read_chip_id[] = { 0x00, 0x00, 0x00, 0x04, 0x00 };
static const guint8 p_idle[] = { 0x14, 0x00 };
/* TODO(upstream): these DAC values are derived from THIS device's OTP by the
 * vendor driver. They are correct for the one machine this was brought up on
 * and nothing else; a driver for more than one unit must derive them from
 * the 0xa6 reply, and the derivation is not known yet. */
static const guint8 p_set_dac[] = { 0xc8, 0x0b, 0xbe, 0x00, 0xbc, 0x00, 0xbc, 0x00 };
/* The 224-byte register script the vendor writes on every init, recovered from
 * gfusb.dll (docs/protocol.md). sum & 0xff == 0xaa pins the window. Generated
 * mechanically from cmd/goodix-probe/vendor.go `uploadConfigPayload`. */
static const guint8 p_upload_config[224] = {
  0x70, 0x11, 0x60, 0x71, 0x00, 0x71, 0x2c, 0x9d,
  0x1c, 0xb9, 0x18, 0xd1, 0x00, 0xd1, 0x00, 0xd1,
  0x00, 0xba, 0x00, 0x01, 0x80, 0xca, 0x00, 0x04,
  0x00, 0x84, 0x00, 0x15, 0xb3, 0x86, 0x00, 0x00,
  0xc4, 0x88, 0x00, 0x00, 0xba, 0x8a, 0x00, 0x00,
  0xb2, 0x8c, 0x00, 0x00, 0xaa, 0x8e, 0x00, 0x00,
  0xc1, 0x90, 0x00, 0xbb, 0xbb, 0x92, 0x00, 0xb1,
  0xb1, 0x94, 0x00, 0x00, 0xa8, 0x96, 0x00, 0x00,
  0xb6, 0x98, 0x00, 0x00, 0x00, 0x9a, 0x00, 0x00,
  0x00, 0xd2, 0x00, 0x00, 0x00, 0xd4, 0x00, 0x00,
  0x00, 0xd6, 0x00, 0x00, 0x00, 0xd8, 0x00, 0x00,
  0x00, 0x50, 0x00, 0x01, 0x05, 0xd0, 0x00, 0x00,
  0x00, 0x70, 0x00, 0x00, 0x00, 0x72, 0x00, 0x78,
  0x56, 0x74, 0x00, 0x34, 0x12, 0x20, 0x00, 0x10,
  0x40, 0x2a, 0x01, 0x82, 0x03, 0x22, 0x00, 0x01,
  0x20, 0x24, 0x00, 0x14, 0x00, 0x80, 0x00, 0x01,
  0x00, 0x5c, 0x00, 0x00, 0x01, 0x56, 0x00, 0x04,
  0x20, 0x58, 0x00, 0x03, 0x02, 0x32, 0x00, 0x0c,
  0x02, 0x66, 0x00, 0x03, 0x00, 0x7c, 0x00, 0x00,
  0x58, 0x82, 0x00, 0x80, 0x15, 0x2a, 0x01, 0x08,
  0x00, 0x5c, 0x00, 0x80, 0x00, 0x54, 0x00, 0x10,
  0x01, 0x62, 0x00, 0x04, 0x03, 0x64, 0x00, 0x19,
  0x00, 0x66, 0x00, 0x03, 0x00, 0x7c, 0x00, 0x00,
  0x58, 0x2a, 0x01, 0x08, 0x00, 0x5c, 0x00, 0x00,
  0x01, 0x52, 0x00, 0x08, 0x00, 0x54, 0x00, 0x00,
  0x01, 0x66, 0x00, 0x03, 0x00, 0x7c, 0x00, 0x00,
  0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x78, 0x15,
};
static const guint8 p_get_image[] = { 0x01, 0x00 };

#define STEP(c, p, r, s, why) { c, p, sizeof (p), r, s, why }

static const G5120Step vendor_init_pre_tls[] = {
  STEP (0x96, p_enable_chip, G5120_REPLY_NONE, FALSE, "enable chip"),
  STEP (0xa8, p_zero2, G5120_REPLY_ACK | G5120_REPLY_DATA, FALSE, "firmware version"),
  STEP (0xae, p_mcu_state, G5120_REPLY_DATA, FALSE, "get MCU state (no ACK)"),
  STEP (0xe4, p_psk_read, G5120_REPLY_ACK | G5120_REPLY_DATA, TRUE, "read production data (PSK hash)"),
  STEP (0xa2, p_reset, G5120_REPLY_ACK | G5120_REPLY_DATA, FALSE, "reset"),
  STEP (0x82, p_read_chip_id, G5120_REPLY_ACK | G5120_REPLY_DATA, FALSE, "read register: chip ID"),
  STEP (0xa6, p_zero2, G5120_REPLY_ACK | G5120_REPLY_DATA, TRUE, "read OTP"),
  STEP (0xa2, p_reset, G5120_REPLY_ACK | G5120_REPLY_DATA, FALSE, "reset, again"),
  STEP (0x70, p_idle, G5120_REPLY_ACK, FALSE, "switch MCU to idle mode (ACK only)"),
  STEP (0x98, p_set_dac, G5120_REPLY_ACK | G5120_REPLY_DATA, FALSE, "set DAC"),
  STEP (0x90, p_upload_config, G5120_REPLY_ACK | G5120_REPLY_DATA, FALSE, "upload config"),
};

static const G5120Step step_health =
  STEP (0xa8, p_zero2, G5120_REPLY_ACK | G5120_REPLY_DATA, FALSE, "health check: firmware version");
static const G5120Step step_request_tls =
  STEP (0xd0, p_zero2, G5120_REPLY_TLS, FALSE, "request TLS connection (no ACK)");
static const G5120Step step_tls_established =
  STEP (0xd4, p_zero2, G5120_REPLY_ACK, FALSE, "TLS established (ACK only)");
static const G5120Step step_mcu_state =
  STEP (0xae, p_mcu_state, G5120_REPLY_DATA, FALSE, "get MCU state (no ACK)");
static const G5120Step step_get_image =
  STEP (0x20, p_get_image, G5120_REPLY_ACK | G5120_REPLY_TLS, FALSE, "get one image");

#undef STEP

const G5120Step *
g5120_vendor_init_pre_tls (gsize *n_steps)
{
  *n_steps = G_N_ELEMENTS (vendor_init_pre_tls);
  return vendor_init_pre_tls;
}

const G5120Step *
g5120_step_health_check (void)
{
  return &step_health;
}

const G5120Step *
g5120_step_request_tls (void)
{
  return &step_request_tls;
}

const G5120Step *
g5120_step_tls_established (void)
{
  return &step_tls_established;
}

const G5120Step *
g5120_step_mcu_state (void)
{
  return &step_mcu_state;
}

const G5120Step *
g5120_step_get_image (void)
{
  return &step_get_image;
}

/* ---- TLS records -------------------------------------------------------- */

gsize
g5120_tls_record_len (const guint8 *buf, gsize len)
{
  gsize body;

  if (len < G5120_TLS_RECORD_HEADER_LEN)
    return 0;

  body = (buf[3] << 8) | buf[4];
  if (len < G5120_TLS_RECORD_HEADER_LEN + body)
    return 0;

  return G5120_TLS_RECORD_HEADER_LEN + body;
}

const char *
g5120_tls_type_name (guint8 type)
{
  switch (type)
    {
    case G5120_TLS_CHANGE_CIPHER_SPEC:
      return "change_cipher_spec";

    case G5120_TLS_ALERT:
      return "alert";

    case G5120_TLS_HANDSHAKE:
      return "handshake";

    case G5120_TLS_APPLICATION_DATA:
      return "application_data";

    default:
      return "unknown";
    }
}

/* ---- Finger detection --------------------------------------------------- */

#define FDT_ARM_MARKER   0x80
#define FDT_ARM_CONSTANT 0x01
#define FDT_MODE_DOWN    0x0c
#define FDT_MODE_UP      0x0e
#define FDT_MODE_MANUAL  0x0d

/* This machine's no-finger arm, observed in dump.pcapng. */
const guint8 g5120_fdt_initial_down_thresholds[G5120_FDT_ZONES] = {
  0xb8, 0xc5, 0xab, 0xb9, 0xaa, 0xb9,
};

gboolean
g5120_is_fdt_cmd (guint8 cmd)
{
  return cmd == G5120_CMD_FDT_DOWN || cmd == G5120_CMD_FDT_UP ||
         cmd == G5120_CMD_FDT_MANUAL;
}

gboolean
g5120_fdt_decode_event (guint8         cmd,
                        const guint8  *payload,
                        gsize          len,
                        G5120FdtEvent *event,
                        GError       **error)
{
  if (len != G5120_FDT_EVENT_LEN)
    {
      g_set_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_FDT,
                   "finger-detect event is %" G_GSIZE_FORMAT " bytes, want %d",
                   len, G5120_FDT_EVENT_LEN);
      return FALSE;
    }

  memset (event, 0, sizeof (*event));
  memcpy (event->header, payload, 4);
  event->touchflags = payload[2];
  for (guint i = 0; i < G5120_FDT_ZONES; i++)
    event->zones[i] = payload[4 + 2 * i] | (payload[5 + 2 * i] << 8);

  if (cmd == G5120_CMD_FDT_DOWN && payload[0] == 0x80)
    event->kind = G5120_FDT_EVENT_BASE_INVALID;
  else if (cmd == G5120_CMD_FDT_DOWN && payload[0] == 0x02 && payload[1] == 0x00)
    event->kind = G5120_FDT_EVENT_DOWN;
  else if (cmd == G5120_CMD_FDT_UP && payload[0] == 0x00 && payload[1] == 0x02)
    event->kind = G5120_FDT_EVENT_UP;
  else if (cmd == G5120_CMD_FDT_MANUAL && payload[0] == 0x00 && payload[1] == 0x01)
    event->kind = G5120_FDT_EVENT_MANUAL;
  else
    event->kind = G5120_FDT_EVENT_UNKNOWN;  /* not an error: keep it for the log */

  return TRUE;
}

const char *
g5120_fdt_event_kind_name (G5120FdtEventKind kind)
{
  switch (kind)
    {
    case G5120_FDT_EVENT_DOWN:
      return "finger down";

    case G5120_FDT_EVENT_UP:
      return "finger up";

    case G5120_FDT_EVENT_MANUAL:
      return "manual";

    case G5120_FDT_EVENT_BASE_INVALID:
      return "base invalid";

    case G5120_FDT_EVENT_UNKNOWN:
    default:
      return "unknown";
    }
}

gsize
g5120_fdt_encode_arm (guint8       cmd,
                      const guint8 thresholds[G5120_FDT_ZONES],
                      guint16      timestamp,
                      guint8      *out)
{
  gsize len;

  switch (cmd)
    {
    case G5120_CMD_FDT_DOWN:
      out[0] = FDT_MODE_DOWN;
      len = G5120_FDT_DOWN_ARM_LEN;
      break;

    case G5120_CMD_FDT_UP:
      out[0] = FDT_MODE_UP;
      len = G5120_FDT_UP_ARM_LEN;
      break;

    case G5120_CMD_FDT_MANUAL:
      out[0] = FDT_MODE_MANUAL;
      len = G5120_FDT_UP_ARM_LEN;
      break;

    default:
      return 0;
    }

  out[1] = FDT_ARM_CONSTANT;
  for (guint i = 0; i < G5120_FDT_ZONES; i++)
    {
      out[2 + 2 * i] = FDT_ARM_MARKER;
      out[3 + 2 * i] = thresholds[i];
    }

  if (cmd == G5120_CMD_FDT_DOWN)
    {
      out[14] = timestamp & 0xff;
      out[15] = (timestamp >> 8) & 0xff;
    }

  return len;
}

static guint8
clamp_u8 (guint v)
{
  return v > 0xff ? 0xff : (guint8) v;
}

void
g5120_fdt_down_thresholds (const guint16 zones[G5120_FDT_ZONES],
                           guint8        thresholds[G5120_FDT_ZONES])
{
  for (guint i = 0; i < G5120_FDT_ZONES; i++)
    thresholds[i] = clamp_u8 (zones[i] >> 1);
}

void
g5120_fdt_up_thresholds (const guint16 zones[G5120_FDT_ZONES],
                         guint8        touchflags,
                         guint8        delta,
                         guint8        thresholds[G5120_FDT_ZONES])
{
  for (guint i = 0; i < G5120_FDT_ZONES; i++)
    {
      if (touchflags & (1u << i))
        thresholds[i] = clamp_u8 ((zones[i] >> 1) + delta);
      else
        thresholds[i] = G5120_FDT_UP_UNTOUCHED;
    }
}

/* ---- Image -------------------------------------------------------------- */

gboolean
g5120_decode_12bit (const guint8 *raw,
                    gsize         raw_len,
                    guint16      *out,
                    gsize         n_samples,
                    GError      **error)
{
  gsize need;

  if (n_samples == 0 || n_samples % 4 != 0)
    {
      g_set_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_IMAGE,
                   "%" G_GSIZE_FORMAT " samples is not a positive multiple of 4", n_samples);
      return FALSE;
    }

  need = n_samples / 4 * 6;
  if (raw_len < need)
    {
      g_set_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_IMAGE,
                   "have %" G_GSIZE_FORMAT " bytes, need %" G_GSIZE_FORMAT, raw_len, need);
      return FALSE;
    }

  for (gsize i = 0, o = 0; i < need; i += 6, o += 4)
    {
      const guint8 *c = raw + i;

      out[o + 0] = ((c[0] & 0x0f) << 8) | c[1];
      out[o + 1] = (c[3] << 4) | (c[0] >> 4);
      out[o + 2] = ((c[5] & 0x0f) << 8) | c[2];
      out[o + 3] = (c[4] << 4) | (c[5] >> 4);
    }

  return TRUE;
}

const guint8 *
g5120_frame_samples (const guint8 *plain,
                     gsize         len,
                     gboolean     *wrapped,
                     GError      **error)
{
  if (len == G5120_IMG_WRAPPED_LEN)
    {
      *wrapped = TRUE;
      return plain + G5120_IMG_HEADER_LEN;
    }

  if (len == G5120_IMG_PACKED_LEN)
    {
      *wrapped = FALSE;
      return plain;
    }

  /* Refusing beats picking an offset: a frame decoded from the wrong offset
   * still looks like a fingerprint, so the mistake would be invisible. */
  g_set_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_IMAGE,
               "%" G_GSIZE_FORMAT " plaintext bytes match neither known layout "
               "(%d wrapped, %d bare)", len, G5120_IMG_WRAPPED_LEN, G5120_IMG_PACKED_LEN);
  return NULL;
}

void
g5120_samples_to_gray8 (const guint16 *samples, gsize n, guint8 *out)
{
  for (gsize i = 0; i < n; i++)
    out[i] = (guint8) (samples[i] >> 4);
}

void
g5120_samples_to_gray8_stretched (const guint16 *samples, gsize n, guint8 *out,
                                  guint16 *lo_out, guint16 *hi_out)
{
  g_autofree guint32 *hist = g_new0 (guint32, G5120_SAMPLE_LEVELS);
  gsize clip = n / G5120_STRETCH_CLIP_DIV;
  gsize seen = 0;
  guint lo = 0, hi = G5120_SAMPLE_LEVELS - 1;

  for (gsize i = 0; i < n; i++)
    hist[samples[i] & (G5120_SAMPLE_LEVELS - 1)]++;

  /* lo is the sample at rank clip, hi the one at rank n - 1 - clip. */
  for (lo = 0; lo < G5120_SAMPLE_LEVELS - 1; lo++)
    if ((seen += hist[lo]) > clip)
      break;
  seen = 0;
  for (hi = G5120_SAMPLE_LEVELS - 1; hi > 0; hi--)
    if ((seen += hist[hi]) > clip)
      break;

  if (lo_out)
    *lo_out = (guint16) lo;
  if (hi_out)
    *hi_out = (guint16) hi;

  /* A flat frame has nothing to stretch; keep the plain mapping. */
  if (hi <= lo)
    {
      g5120_samples_to_gray8 (samples, n, out);
      return;
    }

  for (gsize i = 0; i < n; i++)
    {
      guint v = samples[i] & (G5120_SAMPLE_LEVELS - 1);
      guint range = hi - lo;

      if (v <= lo)
        out[i] = 0;
      else if (v >= hi)
        out[i] = 255;
      else
        out[i] = (guint8) (((v - lo) * 255 + range / 2) / range);
    }
}
