/*
 * Goodix 27c6:5120 (behind an ITE embedded controller) driver for libfprint
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

/*
 * READ THIS BEFORE CHANGING ANYTHING THAT GOES ON THE WIRE
 *
 * The sensor sits behind an ITE embedded controller (firmware
 * GF_ITE_EC_20063) that also drives the laptop's internal keyboard. A wrong
 * frame has wedged that EC and killed the keyboard until a cold power cycle,
 * several times. So:
 *
 *  - Every command frame is built by g5120_command_frame(), which refuses
 *    any opcode not in the send table and any payload of the wrong length.
 *    There is no other way to build one here. The destructive opcodes (0xe0
 *    preset_psk_write, 0xf0 write_firmware) are not in the table at all.
 *  - The sequence is the vendor driver's, byte for byte, as recorded in the
 *    goodix-5120-linux reference (cmd/goodix-probe/vendor.go, Runs 18 and 20
 *    in docs/protocol.md). Do not reorder it or "simplify" it.
 *  - Open starts with the same health check the Go probe uses: 0xa8 must be
 *    answered before anything else is sent. An EC left inside an unfinished
 *    TLS handshake answers nothing but 0xae, and sending the init into that
 *    state cost the keyboard in Run 12.
 *  - Half duplex: exactly one state machine talks to the device at a time,
 *    and nothing is written while a read for a reply is outstanding.
 *  - Anything unexpected stops the sequence rather than pressing on.
 *
 * Wire summary (docs/protocol.md):
 *   open:  drain, 0xa8 (health), 96 a8 ae e4 a2 82 a6 a2 70 98 90,
 *          0xd0 -> TLS-PSK handshake (EC = client, host = server),
 *          0xd4, 0xae
 *   loop:  0x32 arm -> finger-down event -> 0x20 -> image (one TLS
 *          application-data record in a 0xb0 pack) -> 0x34 arm ->
 *          finger-up event -> re-arm 0x32 from the up readings
 *
 * Never logged: the PSK, the 0xe4 reply (a hash of the PSK), the 0xa6 reply
 * (OTP), TLS record bodies, and image data.
 */

#define FP_COMPONENT "goodix5120"

#include <string.h>

#include "drivers_api.h"
#include "goodix5120.h"
#include "goodix5120_proto.h"
#include "goodix5120_tls.h"

typedef enum {
  RX_EMPTY,
  RX_OTHER,
  RX_ACK,
  RX_DATA,
  RX_TLS,
  RX_FDT,
} G5120RxKind;

typedef enum {
  RESULT_NONE,
  RESULT_FINGER_DOWN,
  RESULT_FINGER_UP,
  RESULT_IMAGE,
} G5120Result;

struct _FpiDeviceGoodix5120
{
  FpImageDevice parent;

  G5120Tls     *tls;
  gboolean      session_valid; /* only a successful open permits operations */

  /* The exchange in progress. One at a time: the driver is half duplex. */
  guint8        x_cmd;
  guint8        x_payload[224];
  gsize         x_payload_len;
  G5120Reply    x_reply;
  gboolean      x_secret;       /* never log the data reply */
  gboolean      x_send;         /* FALSE: just drain the IN endpoint */
  gboolean      x_health;       /* the health check */
  const char   *x_purpose;
  gboolean      x_got_ack;
  gboolean      x_got_tls;
  guint         x_reads;
  GByteArray   *x_data;         /* payload of the data reply */

  /* The last transfer, classified. */
  guint8        rx_ack_status;
  guint8        rx_fdt_cmd;
  G5120FdtEvent rx_fdt;
  GByteArray   *rx_tls;

  /* Open. */
  gboolean      interface_claimed;
  gboolean      interface_cleanup_failed; /* release failure has ambiguous ownership */
  guint         init_idx;
  gint64        hs_deadline;
  gint64        hs_pace_deadline;
  gboolean      hs_done;

  /* Capture. */
  GByteArray   *plain;
  guint         cap_reads;
  FpImage      *captured;

  /* Finger detection. */
  guint8        fdt_mode;       /* G5120_CMD_FDT_DOWN or G5120_CMD_FDT_UP */
  guint8        down_thr[G5120_FDT_ZONES];
  guint8        up_thr[G5120_FDT_ZONES];
  guint8        fdt_delta;
  guint         base_invalid;

  /* Activation. */
  FpiSsm       *ssm;            /* the one running session machine, if any */
  G5120Result   result;
  GCancellable *fdt_cancel;
  gboolean      deactivating;
};

G_DEFINE_TYPE (FpiDeviceGoodix5120, fpi_device_goodix5120, FP_TYPE_IMAGE_DEVICE)

/* ---- Helpers ------------------------------------------------------------- */

static gchar *
hexstr (const guint8 *data, gsize len)
{
  GString *s = g_string_sized_new (len * 3);

  for (gsize i = 0; i < len; i++)
    g_string_append_printf (s, i ? " %02x" : "%02x", data[i]);
  return g_string_free (s, FALSE);
}

static const char *
opcode_name (guint8 cmd)
{
  const G5120Opcode *op = g5120_opcode_lookup (cmd);

  return op ? op->name : "unregistered";
}

static GError *
proto_error (GError *cause, const char *context)
{
  GError *e = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO, "%s: %s",
                                        context, cause->message);

  g_error_free (cause);
  return e;
}

static gboolean
is_timeout (GError *error)
{
  return g_error_matches (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT);
}

static void
submit_read (FpiSsm *ssm, FpDevice *dev, guint timeout, GCancellable *cancel,
             FpiUsbTransferCallback cb)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);

  transfer->ssm = ssm;
  fpi_usb_transfer_fill_bulk (transfer, G5120_EP_IN, G5120_IN_BUF_SIZE);
  fpi_usb_transfer_submit (transfer, timeout, cancel, cb, NULL);
}

typedef struct {
  FpiSsm *ssm;
  GByteArray *frame;
  gsize offset;
  gint64 deadline;
  FpiUsbTransferCallback callback;
} PacketWrite;

static void packet_write_next (PacketWrite *write, FpDevice *dev);

static void
packet_write_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  PacketWrite *write = user_data;
  FpiUsbTransferCallback callback = write->callback;

  /* Pinned libfprint's short_is_error check excludes zero-byte completions.
   * Do not advance the stream unless the complete packet was written. */
  if (!error && transfer->actual_length != G5120_USB_PACKET_SIZE)
    error = g_error_new_literal (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_FAILED,
                                 "OUT packet did not write exactly 64 bytes");
  if (!error)
    {
      write->offset += G5120_USB_PACKET_SIZE;
      if (write->offset < write->frame->len)
        {
          if (g_get_monotonic_time () < write->deadline)
            {
              packet_write_next (write, dev);
              return;
            }
          error = g_error_new_literal (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT,
                                       "OUT frame exceeded its write budget");
        }
    }

  /* Complete the caller's exchange only once, after the whole frame or the
   * first failed packet. Release ownership before its reentrant callback. */
  g_byte_array_unref (write->frame);
  g_free (write);
  callback (transfer, dev, NULL, error);
}

static void
packet_write_next (PacketWrite *write, FpDevice *dev)
{
  FpiUsbTransfer *transfer = fpi_usb_transfer_new (dev);
  guint8 *data = g_memdup2 (write->frame->data + write->offset, G5120_USB_PACKET_SIZE);
  gint64 remaining = write->deadline - g_get_monotonic_time ();
  guint timeout;

  transfer->ssm = write->ssm;
  transfer->short_is_error = TRUE;
  fpi_usb_transfer_fill_bulk_full (transfer, G5120_EP_OUT, data, G5120_USB_PACKET_SIZE, g_free);
  if (remaining <= 0)
    {
      packet_write_cb (transfer, dev, write,
                        g_error_new_literal (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT,
                                             "OUT frame exceeded its write budget before submission"));
      fpi_usb_transfer_unref (transfer);
      return;
    }
  timeout = (guint) MIN ((remaining + 999) / 1000, G5120_TIMEOUT_OUT);
  fpi_usb_transfer_submit (transfer, timeout, NULL, packet_write_cb, write);
}

/* Consume a padded frame and submit one completed 64-byte OUT at a time,
 * matching the Go reference. Keep the original budget for the whole frame. */
static void
submit_write_until (FpiSsm *ssm, FpDevice *dev, GByteArray *frame,
                    FpiUsbTransferCallback cb, gint64 deadline)
{
  PacketWrite *write = g_new0 (PacketWrite, 1);

  g_assert (frame->len > 0 && frame->len % G5120_USB_PACKET_SIZE == 0);
  write->ssm = ssm;
  write->frame = frame;
  write->deadline = MIN (deadline, g_get_monotonic_time () + (gint64) G5120_TIMEOUT_OUT * 1000);
  write->callback = cb;
  packet_write_next (write, dev);
}

static void
submit_write (FpiSsm *ssm, FpDevice *dev, GByteArray *frame, FpiUsbTransferCallback cb)
{
  submit_write_until (ssm, dev, frame, cb, G_MAXINT64);
}

/* Classifies one IN transfer relative to the command @expect. It records what
 * it found in self->rx_* / self->x_data, and logs within the secrecy rules. */
static G5120RxKind
rx_classify (FpiDeviceGoodix5120 *self,
             const guint8        *buf,
             gsize                len,
             guint8               expect,
             gboolean             secret)
{
  g_autoptr(GError) error = NULL;
  const guint8 *pl, *mp;
  gsize pl_len, mp_len;
  guint8 flags, cmd, acked, status;

  if (len == 0)
    {
      fp_dbg ("empty transfer");
      return RX_EMPTY;
    }

  if (!g5120_pack_decode (buf, len, &flags, &pl, &pl_len, &error))
    {
      fp_warn ("undecodable %" G_GSIZE_FORMAT "-byte transfer: %s", len, error->message);
      return RX_OTHER;
    }

  if (flags == G5120_FLAG_TLS || flags == G5120_FLAG_TLS_ALT)
    {
      /* Length only: a TLS body is key agreement or an image. */
      fp_dbg ("TLS pack (flags 0x%02x), %" G_GSIZE_FORMAT " bytes", flags, pl_len);
      g_byte_array_set_size (self->rx_tls, 0);
      g_byte_array_append (self->rx_tls, pl, pl_len);
      return RX_TLS;
    }

  if (flags != G5120_FLAG_MESSAGE)
    {
      fp_warn ("pack with unknown flags 0x%02x, %" G_GSIZE_FORMAT " bytes; ignored", flags, pl_len);
      return RX_OTHER;
    }

  if (!g5120_message_decode (pl, pl_len, &cmd, &mp, &mp_len, &error))
    {
      fp_warn ("undecodable message: %s", error->message);
      return RX_OTHER;
    }

  if (g5120_ack_decode (cmd, mp, mp_len, &acked, &status))
    {
      if (acked == expect)
        {
          fp_dbg ("ACK for %s (0x%02x), status 0x%02x", opcode_name (acked), acked, status);
          self->rx_ack_status = status;
          return RX_ACK;
        }
      fp_dbg ("ACK for 0x%02x while waiting on 0x%02x; ignored", acked, expect);
      return RX_OTHER;
    }

  /* Finger-detect events come unprompted, so they are recognised before a
   * data reply: an 0x32 event is not the reply to an 0x32 arm. */
  if (g5120_is_fdt_cmd (cmd) &&
      g5120_fdt_decode_event (cmd, mp, mp_len, &self->rx_fdt, NULL))
    {
      fp_dbg ("FDT event 0x%02x (%s): header %02x %02x %02x %02x, zones %u %u %u %u %u %u",
              cmd, g5120_fdt_event_kind_name (self->rx_fdt.kind),
              self->rx_fdt.header[0], self->rx_fdt.header[1],
              self->rx_fdt.header[2], self->rx_fdt.header[3],
              self->rx_fdt.zones[0], self->rx_fdt.zones[1], self->rx_fdt.zones[2],
              self->rx_fdt.zones[3], self->rx_fdt.zones[4], self->rx_fdt.zones[5]);
      self->rx_fdt_cmd = cmd;
      return RX_FDT;
    }

  if (cmd == expect)
    {
      if (secret)
        {
          fp_dbg ("reply to %s (0x%02x): %" G_GSIZE_FORMAT " bytes (contents not logged)",
                  opcode_name (cmd), cmd, mp_len);
        }
      else
        {
          g_autofree gchar *h = hexstr (mp, mp_len);

          fp_dbg ("reply to %s (0x%02x): %s", opcode_name (cmd), cmd, h);
        }
      g_byte_array_set_size (self->x_data, 0);
      g_byte_array_append (self->x_data, mp, mp_len);
      return RX_DATA;
    }

  fp_dbg ("unsolicited message 0x%02x, %" G_GSIZE_FORMAT " bytes; ignored", cmd, mp_len);
  return RX_OTHER;
}

/* ---- One command exchange -------------------------------------------------
 *
 * Send one frame, then read until the replies the vendor's EC gives to it
 * have arrived: ACK, then a data message (most commands); data with no ACK
 * (0xae); ACK only (0x70, 0xd4, the FDT arms); nothing (0x96); or a TLS
 * handshake (0xd0), which the handshake machine reads instead. A reply that
 * does not come stops everything.
 */

enum {
  XCHG_SEND,
  XCHG_RECV,
  XCHG_NUM_STATES,
};

static GError *
missing_reply_error (FpiDeviceGoodix5120 *self)
{
  if (self->x_health)
    return fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                     "the EC did not answer firmware_version (0xa8), so it is "
                                     "not in the state this driver assumes, and nothing else "
                                     "was sent. An EC left inside an unfinished TLS handshake "
                                     "answers nothing but 0xae. Recovery that worked (Run 16): "
                                     "shut down with the charger plugged in and hold the power "
                                     "button for 40 s. Do not retry until then.");

  return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                   "no %s to %s (0x%02x, %s) where the vendor's EC sends one; "
                                   "stopping before anything else is sent",
                                   self->x_got_ack ? "data reply" : "acknowledgement",
                                   opcode_name (self->x_cmd), self->x_cmd, self->x_purpose);
}

/* Init replies documented in docs/protocol.md, "Init sequence" and Run 8.
 * Only check known fields: the hash, OTP and MCU counters are opaque.
 * Errors deliberately describe the envelope, never sensitive contents. */
static GError *
validate_data_reply (FpiDeviceGoodix5120 *self)
{
  /* Run 8: nine-byte reply envelope + 32-byte hash. The reply type differs
   * from the request; do not infer it by echoing p_psk_read. */
  static const guint8 psk_header[] = { 0, 3, 0, 1, 0xbb, 0x20, 0, 0, 0 };
  static const guint8 reset_reply[] = { 1, 0, 8 };
  static const guint8 chip_reply[] = { 0xa2, 4, 0x25, 0 };
  static const guint8 success_reply[] = { 1, 1 };
  const guint8 *expected = NULL;
  gsize expected_len = 0, reply_len;
  const guint8 *data = self->x_data->data;
  gsize len = self->x_data->len;

  switch (self->x_cmd)
    {
    case 0xa8:
      {
        gsize fw_len = strlen (G5120_FIRMWARE_TESTED);

        /* The recorded reply ends in NUL; the reference also accepts an
         * unterminated name. A NUL must not conceal extra payload bytes. */
        if (!((len == fw_len || (len == fw_len + 1 && data[fw_len] == 0)) &&
              memcmp (data, G5120_FIRMWARE_TESTED, fw_len) == 0))
          return fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                           "firmware reply is not exactly %s with an optional "
                                           "trailing NUL; refusing to continue init",
                                           G5120_FIRMWARE_TESTED);
        return NULL;
      }

    case 0xae:
      reply_len = 20;
      break;

    case 0xe4:
      reply_len = 41;
      expected = psk_header;
      expected_len = sizeof (psk_header);
      break;

    case 0xa2:
      reply_len = expected_len = sizeof (reset_reply);
      expected = reset_reply;
      break;

    case 0x82:
      /* This init reads only the four-byte chip ID register reply; the
       * supported sensor is 0x2504, encoded as a2 04 25 00. */
      reply_len = expected_len = sizeof (chip_reply);
      expected = chip_reply;
      break;

    case 0xa6:
      reply_len = 64;
      break;

    case 0x98:
    case 0x90:
      reply_len = expected_len = sizeof (success_reply);
      expected = success_reply;
      break;

    default:
      return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                       "no known data reply shape for command 0x%02x; stopping",
                                       self->x_cmd);
    }

  if (len != reply_len)
    return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                     "%s (0x%02x) returned %" G_GSIZE_FORMAT " bytes, expected "
                                     "%" G_GSIZE_FORMAT "; stopping before another command",
                                     opcode_name (self->x_cmd), self->x_cmd, len, reply_len);
  if (expected && memcmp (data, expected, expected_len) != 0)
    return fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                     "%s (0x%02x) returned an unexpected status or header "
                                     "(contents not logged); stopping before another command",
                                     opcode_name (self->x_cmd), self->x_cmd);
  return NULL;
}

static void
xchg_recv_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);
  FpiSsm *ssm = transfer->ssm;
  guint max_reads;

  if (error)
    {
      if (is_timeout (error))
        {
          g_error_free (error);
          if (self->x_reply == G5120_REPLY_NONE)
            fpi_ssm_mark_completed (ssm);
          else
            fpi_ssm_mark_failed (ssm, missing_reply_error (self));
          return;
        }
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  switch (rx_classify (self, transfer->buffer, transfer->actual_length,
                       self->x_cmd, self->x_secret))
    {
    case RX_ACK:
      if (!self->x_send)
        break;
      if (self->rx_ack_status != 0x01)
        {
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                         "%s (0x%02x) acknowledged with status 0x%02x; "
                                                         "only 0x01 has ever been observed, so stopping",
                                                         opcode_name (self->x_cmd), self->x_cmd,
                                                         self->rx_ack_status));
          return;
        }
      self->x_got_ack = TRUE;
      if (!(self->x_reply & (G5120_REPLY_DATA | G5120_REPLY_TLS)) ||
          ((self->x_reply & G5120_REPLY_TLS) && self->x_got_tls))
        {
          fpi_ssm_mark_completed (ssm);
          return;
        }
      break;

    case RX_DATA:
      if (self->x_send && (self->x_reply & G5120_REPLY_DATA))
        {
          /* Every live run sent the ACK first. Data without it would mean
           * an EC in some other state, and the ACK status unchecked. */
          if ((self->x_reply & G5120_REPLY_ACK) && !self->x_got_ack)
            {
              fpi_ssm_mark_failed (ssm,
                                   fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                             "data reply to %s (0x%02x) before its "
                                                             "acknowledgement; the vendor's EC sends "
                                                             "the ACK first, so stopping",
                                                             opcode_name (self->x_cmd), self->x_cmd));
              return;
            }
          error = validate_data_reply (self);
          if (error)
            {
              fpi_ssm_mark_failed (ssm, error);
              return;
            }
          fpi_ssm_mark_completed (ssm);
          return;
        }
      break;

    case RX_TLS:
      if (self->x_send && (self->x_reply & G5120_REPLY_TLS) && self->tls)
        {
          GError *terr = NULL;

          if (!g5120_tls_feed (self->tls, self->rx_tls->data, self->rx_tls->len, &terr))
            {
              fpi_ssm_mark_failed (ssm, proto_error (terr, "TLS"));
              return;
            }
          self->x_got_tls = TRUE;
          if (self->x_got_ack)
            {
              fpi_ssm_mark_completed (ssm);
              return;
            }
          break;
        }
      fp_warn ("unexpected TLS pack of %u bytes while waiting on 0x%02x; dropped",
               self->rx_tls->len, self->x_cmd);
      break;

    case RX_FDT:
      /* Before the arm's own ACK, an event is stale: it answers an earlier
       * arm (the EC stays armed across sessions; Windows leaves it armed). */
      fp_dbg ("finger-detect event while waiting on 0x%02x; dropped as stale", self->x_cmd);
      break;

    case RX_EMPTY:
    case RX_OTHER:
      break;
    }

  max_reads = self->x_send ? G5120_MAX_READS_PER_STEP : G5120_MAX_DRAIN_READS;
  if (++self->x_reads >= max_reads)
    {
      if (self->x_reply == G5120_REPLY_NONE)
        {
          fp_warn ("the device was still sending after %u reads; moving on", self->x_reads);
          fpi_ssm_mark_completed (ssm);
        }
      else
        {
          fpi_ssm_mark_failed (ssm, missing_reply_error (self));
        }
      return;
    }

  fpi_ssm_jump_to_state (ssm, XCHG_RECV);
}

static void
xchg_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case XCHG_SEND:
      {
        GError *error = NULL;
        GByteArray *frame;

        if (!self->x_send)
          {
            fpi_ssm_next_state (ssm);
            return;
          }

        /* The gate: refuses unregistered opcodes and wrong payload lengths. */
        frame = g5120_command_frame (self->x_cmd, self->x_payload, self->x_payload_len, &error);
        if (frame == NULL)
          {
            fpi_ssm_mark_failed (ssm, proto_error (error, "refused to send"));
            return;
          }

        fp_dbg ("-> %s (0x%02x), %" G_GSIZE_FORMAT "-byte payload: %s",
                opcode_name (self->x_cmd), self->x_cmd, self->x_payload_len, self->x_purpose);
        submit_write (ssm, dev, frame, fpi_ssm_usb_transfer_cb);
      }
      break;

    case XCHG_RECV:
      if (self->x_reply == G5120_REPLY_TLS)
        {
          /* 0xd0: no ACK; the EC opens a handshake, read by the caller. */
          fpi_ssm_mark_completed (ssm);
          return;
        }
      submit_read (ssm, dev,
                   self->x_reply == G5120_REPLY_NONE ? G5120_TIMEOUT_QUIET : G5120_TIMEOUT_REPLY,
                   NULL, xchg_recv_cb);
      break;

    default:
      g_assert_not_reached ();
    }
}

/* Every field is set before the child machine starts, because its first
 * state runs synchronously inside fpi_ssm_start_subsm(). */
static void
begin_exchange (FpiSsm              *parent,
                FpiDeviceGoodix5120 *self,
                gboolean             send,
                gboolean             health,
                guint8               cmd,
                const guint8        *payload,
                gsize                payload_len,
                G5120Reply           reply,
                gboolean             secret,
                const char          *purpose)
{
  g_assert (payload_len <= sizeof (self->x_payload));

  self->x_cmd = cmd;
  if (payload_len > 0)
    memcpy (self->x_payload, payload, payload_len);
  self->x_payload_len = payload_len;
  self->x_reply = reply;
  self->x_secret = secret;
  self->x_send = send;
  self->x_health = health;
  self->x_purpose = purpose;
  self->x_got_ack = FALSE;
  self->x_got_tls = FALSE;
  self->x_reads = 0;
  g_byte_array_set_size (self->x_data, 0);

  fpi_ssm_start_subsm (parent, fpi_ssm_new (FP_DEVICE (self), xchg_run_state, XCHG_NUM_STATES));
}

static void
start_exchange (FpiSsm              *parent,
                FpiDeviceGoodix5120 *self,
                guint8               cmd,
                const guint8        *payload,
                gsize                payload_len,
                G5120Reply           reply,
                gboolean             secret,
                const char          *purpose)
{
  begin_exchange (parent, self, TRUE, FALSE, cmd, payload, payload_len, reply, secret, purpose);
}

static void
start_step (FpiSsm *parent, FpiDeviceGoodix5120 *self, const G5120Step *step)
{
  start_exchange (parent, self, step->cmd, step->payload, step->payload_len,
                  step->reply, step->secret_reply, step->purpose);
}

/* The health check: 0xa8, whose silence means "stuck", not "slow". */
static void
start_health_check (FpiSsm *parent, FpiDeviceGoodix5120 *self)
{
  const G5120Step *step = g5120_step_health_check ();

  begin_exchange (parent, self, TRUE, TRUE, step->cmd, step->payload, step->payload_len,
                  step->reply, step->secret_reply, step->purpose);
}

/* Reads until the device is quiet, so no reply is left queued in the EC.
 * Sends nothing. */
static void
start_drain (FpiSsm *parent, FpiDeviceGoodix5120 *self)
{
  begin_exchange (parent, self, FALSE, FALSE, 0x00, NULL, 0, G5120_REPLY_NONE, TRUE, "drain");
}

/* ---- TLS-PSK handshake ------------------------------------------------------
 *
 * Read one transfer from the EC, feed it to the server, send every record the
 * server produced in its own 0xb0 pack, and go straight back to reading.
 * Read through the EC's flight without waiting for new host output: its
 * ClientKeyExchange, ChangeCipherSpec and Finished are separate transfers,
 * 22 ms and 5 ms apart. Waiting on the host here stalled Runs 11 and 17.
 *
 * Between two records of the host's own flight there is a bounded read interval
 * (HS_PACE). The vendor's log has 61 ms between ServerHello and
 * ServerHelloDone and 66 ms between ChangeCipherSpec and Finished; the Go
 * probe, which completed Runs 18-22, left ~3 ms. Runs 24 and 25 sent both
 * records within a millisecond and drew decode_error both times. This is a
 * timing hypothesis, not a confirmed fix. Read any complete alert before
 * sending another record; record counts describe progress when it was seen.
 */

enum {
  HS_READ,
  HS_WRITE,
  HS_PACE,
  HS_NUM_STATES,
};

static GError *
handshake_error (FpiDeviceGoodix5120 *self, GError *cause)
{
  GError *e;
  guint from_ec, to_ec;

  g5120_tls_counts (self->tls, &from_ec, &to_ec);
  if (g_error_matches (cause, G5120_TLS_ERROR, G5120_TLS_ERROR_PSK_MISMATCH))
    e = fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                  "TLS-PSK handshake rejected (%s) after %u record(s) from the EC "
                                  "and %u to it. The PSK file does not hold "
                                  "this device's key. The EC is probably left inside the "
                                  "handshake now: power it down with the charger plugged in "
                                  "and hold the power button 40 s before trying again.",
                                  cause->message, from_ec, to_ec);
  else
    e = fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                  "TLS-PSK handshake failed (%s) after %u record(s) from the EC "
                                  "and %u to it. The EC is probably left inside "
                                  "the handshake now: power it down with the charger plugged in "
                                  "and hold the power button 40 s before trying again.",
                                  cause->message, from_ec, to_ec);
  g_error_free (cause);
  return e;
}

/* HS_PACE keeps its original deadline across stale/empty reads. Complete a
 * fragmented incoming record before output, even if the interval has expired;
 * the overall handshake budget bounds that additional wait. */
static void
hs_receive (FpiUsbTransfer *transfer, FpDevice *dev, GError *error, gboolean pacing)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);
  FpiSsm *ssm = transfer->ssm;
  GError *terr = NULL;
  gboolean done = FALSE;
  int next = pacing ? HS_PACE : HS_READ;

  if (error)
    {
      if (is_timeout (error))
        {
          g_error_free (error);
          fpi_ssm_jump_to_state (ssm, next);
          return;
        }
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  switch (rx_classify (self, transfer->buffer, transfer->actual_length, 0xd0, TRUE))
    {
    case RX_TLS:
      if (!g5120_tls_feed (self->tls, self->rx_tls->data, self->rx_tls->len, &terr) ||
          !g5120_tls_handshake (self->tls, &done, &terr))
        {
          fpi_ssm_mark_failed (ssm, handshake_error (self, terr));
          return;
        }
      self->hs_done = done;
      fpi_ssm_jump_to_state (ssm, pacing ? HS_PACE :
                             (g5120_tls_has_partial_input (self->tls) ? HS_READ : HS_WRITE));
      return;

    case RX_EMPTY:
      if (!pacing)
        fp_warn ("zero-length transfer inside the handshake: the stalled Runs 11 and 17 "
                 "showed exactly this where the EC's next record should have been");
      break;

    case RX_ACK:
    case RX_DATA:
    case RX_FDT:
    case RX_OTHER:
      /* Already logged; nothing of the handshake's. */
      break;
    }

  fpi_ssm_jump_to_state (ssm, next);
}

static void
hs_read_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  hs_receive (transfer, dev, error, FALSE);
}

static void
hs_pace_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  hs_receive (transfer, dev, error, TRUE);
}

static void
hs_write_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }
  if (g5120_tls_has_record (self->tls))
    {
      self->hs_pace_deadline = g_get_monotonic_time () + (gint64) G5120_TIMEOUT_HS_PACE * 1000;
      fpi_ssm_jump_to_state (transfer->ssm, HS_PACE);
    }
  else
    fpi_ssm_jump_to_state (transfer->ssm, HS_WRITE);
}

static void
hs_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);
  gint64 remaining = self->hs_deadline - g_get_monotonic_time ();
  guint read_budget;

  if (remaining <= 0)
    {
      fpi_ssm_mark_failed (ssm,
                           handshake_error (self, g_error_new (G5120_TLS_ERROR, G5120_TLS_ERROR_FAILED,
                                                               "handshake exceeded its %d ms budget",
                                                               G5120_HANDSHAKE_BUDGET)));
      return;
    }
  read_budget = (guint) MIN ((remaining + 999) / 1000, G5120_TIMEOUT_HS_READ);

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case HS_READ:
      submit_read (ssm, dev, read_budget, NULL, hs_read_cb);
      break;

    case HS_PACE:
      {
        gint64 gap = self->hs_pace_deadline - g_get_monotonic_time ();

        if (gap <= 0 && !g5120_tls_has_partial_input (self->tls))
          {
            fp_dbg ("TLS: inter-record interval completed (%d ms); sending the next record",
                    G5120_TIMEOUT_HS_PACE);
            fpi_ssm_jump_to_state (ssm, HS_WRITE);
            return;
          }
        if (gap > 0)
          read_budget = (guint) MIN ((gap + 999) / 1000, read_budget);
        submit_read (ssm, dev, read_budget, NULL, hs_pace_cb);
      }
      break;

    case HS_WRITE:
      {
        g_autoptr(GBytes) rec = g5120_tls_pop_record (self->tls);
        GError *error = NULL;
        GByteArray *frame;
        gsize len;
        const guint8 *data;

        if (rec == NULL)
          {
            if (self->hs_done)
              fpi_ssm_mark_completed (ssm);
            else
              fpi_ssm_jump_to_state (ssm, HS_READ);
            return;
          }

        /* One record per pack, as the vendor driver sends them. */
        data = g_bytes_get_data (rec, &len);
        frame = g5120_tls_frame (data, len, &error);
        if (frame == NULL)
          {
            fpi_ssm_mark_failed (ssm, proto_error (error, "refused to send"));
            return;
          }
        submit_write_until (ssm, dev, frame, hs_write_cb, self->hs_deadline);
      }
      break;

    default:
      g_assert_not_reached ();
    }
}

/* ---- Open: health check, vendor init, handshake -------------------------- */

enum {
  OPEN_PREPARE,
  OPEN_CLAIM,
  OPEN_DRAIN,
  OPEN_HEALTH,
  OPEN_CHECK_FIRMWARE,
  OPEN_DRAIN_AFTER_HEALTH,
  OPEN_INIT_STEP,
  OPEN_INIT_DRAIN,
  OPEN_INIT_NEXT,
  OPEN_REQUEST_TLS,
  OPEN_HANDSHAKE,
  OPEN_TLS_ESTABLISHED,
  OPEN_MCU_STATE,
  OPEN_LOG_MCU_STATE,
  OPEN_DRAIN_FINAL,
  OPEN_NUM_STATES,
};

static void
open_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case OPEN_PREPARE:
      {
        /* Everything that can fail without the device fails here, before a
         * single byte is sent: a missing PSK, or an OpenSSL without the
         * suite. A handshake that cannot succeed must not be started, since
         * an unfinished one leaves the EC stuck. */
        const char *path = g_getenv (G5120_PSK_ENV);
        guint8 psk[G5120_PSK_LEN];

        if (path == NULL || *path == '\0')
          path = G5120_PSK_DEFAULT_PATH;

        if (!g5120_psk_load (path, psk, &error))
          {
            fpi_ssm_mark_failed (ssm,
                                 fpi_device_error_new_msg (FP_DEVICE_ERROR_NOT_SUPPORTED,
                                                           "%s. This driver needs the device's "
                                                           "32-byte TLS PSK as a raw file; set %s or "
                                                           "install it at %s. It does not provision "
                                                           "one (see README.md, PSK provisioning).",
                                                           error->message, G5120_PSK_ENV,
                                                           G5120_PSK_DEFAULT_PATH));
            g_error_free (error);
            return;
          }
        fp_dbg ("loaded a %d-byte PSK from %s (contents not logged)", G5120_PSK_LEN, path);

        g_clear_pointer (&self->tls, g5120_tls_free);
        self->tls = g5120_tls_new (psk, &error);
        memset (psk, 0, sizeof (psk));
        if (self->tls == NULL)
          {
            fpi_ssm_mark_failed (ssm, proto_error (error, "TLS setup"));
            return;
          }
        fpi_ssm_next_state (ssm);
      }
      break;

    case OPEN_CLAIM:
      /* No g_usb_device_reset(): what a USB reset does to this EC is not
       * known, and it is not something the vendor driver does. */
      if (!g_usb_device_claim_interface (fpi_device_get_usb_device (dev), G5120_INTERFACE,
                                         G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER, &error))
        {
          fpi_ssm_mark_failed (ssm, error);
          return;
        }
      self->interface_claimed = TRUE;
      fpi_ssm_next_state (ssm);
      break;

    case OPEN_DRAIN:
    case OPEN_DRAIN_AFTER_HEALTH:
    case OPEN_INIT_DRAIN:
    case OPEN_DRAIN_FINAL:
      start_drain (ssm, self);
      break;

    case OPEN_HEALTH:
      start_health_check (ssm, self);
      break;

    case OPEN_CHECK_FIRMWARE:
      /* The exchange validated the complete payload before advancing. */
      fp_info ("firmware: %s", G5120_FIRMWARE_TESTED);
      self->init_idx = 0;
      fpi_ssm_next_state (ssm);
      break;

    case OPEN_INIT_STEP:
      {
        gsize n;
        const G5120Step *steps = g5120_vendor_init_pre_tls (&n);

        start_step (ssm, self, &steps[self->init_idx]);
      }
      break;

    case OPEN_INIT_NEXT:
      {
        gsize n;

        g5120_vendor_init_pre_tls (&n);
        if (++self->init_idx < n)
          fpi_ssm_jump_to_state (ssm, OPEN_INIT_STEP);
        else
          fpi_ssm_next_state (ssm);
      }
      break;

    case OPEN_REQUEST_TLS:
      /* No drain after this: the EC's ClientHello is the next thing to read. */
      self->hs_done = FALSE;
      self->hs_deadline = g_get_monotonic_time () + G5120_HANDSHAKE_BUDGET * 1000;
      start_step (ssm, self, g5120_step_request_tls ());
      break;

    case OPEN_HANDSHAKE:
      fpi_ssm_start_subsm (ssm, fpi_ssm_new (dev, hs_run_state, HS_NUM_STATES));
      break;

    case OPEN_TLS_ESTABLISHED:
      {
        guint from_ec, to_ec;

        g5120_tls_counts (self->tls, &from_ec, &to_ec);
        fp_info ("TLS-PSK handshake complete: the EC and this host share the PSK "
                 "(%u record(s) from the EC, %u to it)", from_ec, to_ec);
        start_step (ssm, self, g5120_step_tls_established ());
      }
      break;

    case OPEN_MCU_STATE:
      start_step (ssm, self, g5120_step_mcu_state ());
      break;

    case OPEN_LOG_MCU_STATE:
      /* Only isTlsConnected (byte 1, bit 1) is pinned down. A local TLS
       * handshake alone does not establish that the EC accepted the session. */
      if (self->x_data->len != 20 || !(self->x_data->data[1] & 0x02))
        {
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                         "MCU state does not report isTlsConnected "
                                                         "after the handshake; refusing to activate"));
          return;
        }
      fpi_ssm_next_state (ssm);
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
release_interface (FpiDeviceGoodix5120 *self, GError **error)
{
  if (!self->interface_claimed)
    return;

  /* GUsb releases, then attaches. FALSE does not tell us which failed,
   * so do not release twice or reclaim on this object after failure. */
  self->interface_claimed = FALSE;
  if (!g_usb_device_release_interface (fpi_device_get_usb_device (FP_DEVICE (self)),
                                       G5120_INTERFACE,
                                       G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER, error))
    self->interface_cleanup_failed = TRUE;
}

static void
open_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);

  self->session_valid = error == NULL;
  if (error)
    {
      g_autoptr(GError) cleanup_error = NULL;
      release_interface (self, &cleanup_error);
      if (cleanup_error)
        g_prefix_error (&error, "Interface cleanup also failed (%s): ", cleanup_error->message);
      g_clear_pointer (&self->tls, g5120_tls_free);
    }

  fpi_image_device_open_complete (FP_IMAGE_DEVICE (dev), error);
}

static void
dev_open (FpImageDevice *dev)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);
  FpiSsm *ssm;

  self->session_valid = FALSE;
  if (self->interface_cleanup_failed)
    {
      fpi_image_device_open_complete (dev,
                                      fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                                "Previous interface cleanup failed; recreate "
                                                                "the device before reopening"));
      return;
    }
  ssm = fpi_ssm_new (FP_DEVICE (dev), open_run_state, OPEN_NUM_STATES);
  fpi_ssm_start (ssm, open_done);
}

static void
dev_close (FpImageDevice *dev)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);
  GError *error = NULL;

  /* Nothing is sent: no command that ends a session is known. The EC keeps
   * the TLS session and whatever FDT arm it last had, as Windows leaves it;
   * a later open repeats the full init and handshake, which Runs 20-22 showed
   * works after a completed handshake, four times with no EC reset. */
  self->session_valid = FALSE;
  g_clear_pointer (&self->tls, g5120_tls_free);
  release_interface (self, &error);
  fpi_image_device_close_complete (dev, error);
}

/* ---- Finger detection -----------------------------------------------------
 *
 * Arm (0x32 down or 0x34 up), take the ACK, then wait with no timeout for the
 * event, which the EC sends unprompted. The wait is the only cancellable
 * point, and nothing is written while it is outstanding.
 */

enum {
  FDT_ARM,
  FDT_WAIT,
  FDT_NUM_STATES,
};

static gboolean
zones_all_zero (const guint16 *zones)
{
  for (guint i = 0; i < G5120_FDT_ZONES; i++)
    if (zones[i] != 0)
      return FALSE;
  return TRUE;
}

static void
fdt_handle_event (FpiSsm *ssm, FpiDeviceGoodix5120 *self)
{
  const G5120FdtEvent *ev = &self->rx_fdt;

  if (self->rx_fdt_cmd != self->fdt_mode)
    {
      fp_dbg ("event 0x%02x while armed with 0x%02x; ignored", self->rx_fdt_cmd, self->fdt_mode);
      fpi_ssm_jump_to_state (ssm, FDT_WAIT);
      return;
    }

  switch (ev->kind)
    {
    case G5120_FDT_EVENT_DOWN:
      /* Up thresholds come from the readings with the finger on. */
      g5120_fdt_up_thresholds (ev->zones, ev->touchflags, self->fdt_delta, self->up_thr);
      self->base_invalid = 0;
      self->result = RESULT_FINGER_DOWN;
      fpi_ssm_mark_completed (ssm);
      return;

    case G5120_FDT_EVENT_BASE_INVALID:
      /* The zones carry the current no-finger readings: re-arm from them
       * at once, as the vendor driver does. */
      if (++self->base_invalid > G5120_MAX_BASE_INVALID)
        {
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                         "%u consecutive 'base invalid' replies to "
                                                         "the finger-down arm", self->base_invalid - 1));
          return;
        }
      if (zones_all_zero (ev->zones))
        fp_warn ("'base invalid' with all-zero readings; re-arming with the previous thresholds");
      else
        g5120_fdt_down_thresholds (ev->zones, self->down_thr);
      fpi_ssm_jump_to_state (ssm, FDT_ARM);
      return;

    case G5120_FDT_EVENT_UP:
      /* The next down arm comes from the readings with the finger off. */
      g5120_fdt_down_thresholds (ev->zones, self->down_thr);
      self->result = RESULT_FINGER_UP;
      fpi_ssm_mark_completed (ssm);
      return;

    case G5120_FDT_EVENT_MANUAL:
    case G5120_FDT_EVENT_UNKNOWN:
    default:
      fp_dbg ("%s event while armed with 0x%02x; still waiting",
              g5120_fdt_event_kind_name (ev->kind), self->fdt_mode);
      fpi_ssm_jump_to_state (ssm, FDT_WAIT);
      return;
    }
}

static void
fdt_wait_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);
  FpiSsm *ssm = transfer->ssm;

  if (error)
    {
      if (self->deactivating && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
        {
          g_error_free (error);
          fpi_ssm_mark_completed (ssm);
          return;
        }
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  if (rx_classify (self, transfer->buffer, transfer->actual_length, self->fdt_mode, FALSE) == RX_FDT)
    {
      fdt_handle_event (ssm, self);
      return;
    }

  fpi_ssm_jump_to_state (ssm, FDT_WAIT);
}

static void
fdt_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);

  if (self->deactivating)
    {
      fpi_ssm_mark_completed (ssm);
      return;
    }

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case FDT_ARM:
      {
        guint8 payload[G5120_FDT_DOWN_ARM_LEN];
        const guint8 *thr = self->fdt_mode == G5120_CMD_FDT_DOWN ? self->down_thr : self->up_thr;
        /* The vendor sends the low 16 bits of a millisecond counter. */
        guint16 ts = (guint16) ((g_get_monotonic_time () / 1000) & 0xffff);
        gsize len = g5120_fdt_encode_arm (self->fdt_mode, thr, ts, payload);

        fp_dbg ("arming 0x%02x with thresholds %02x %02x %02x %02x %02x %02x",
                self->fdt_mode, thr[0], thr[1], thr[2], thr[3], thr[4], thr[5]);
        start_exchange (ssm, self, self->fdt_mode, payload, len, G5120_REPLY_ACK, FALSE,
                        self->fdt_mode == G5120_CMD_FDT_DOWN ? "arm finger-down" : "arm finger-up");
      }
      break;

    case FDT_WAIT:
      g_clear_object (&self->fdt_cancel);
      self->fdt_cancel = g_cancellable_new ();
      submit_read (ssm, dev, 0, self->fdt_cancel, fdt_wait_cb);
      break;

    default:
      g_assert_not_reached ();
    }
}

/* ---- Capture ----------------------------------------------------------- */

enum {
  CAP_REQUEST,
  CAP_READ,
  CAP_DECODE,
  CAP_NUM_STATES,
};

static void
cap_read_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);
  FpiSsm *ssm = transfer->ssm;
  GError *terr = NULL;

  if (error)
    {
      if (is_timeout (error))
        {
          g_error_free (error);
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                              "no image after mcu_get_image (0x20)"));
          return;
        }
      fpi_ssm_mark_failed (ssm, error);
      return;
    }

  if (rx_classify (self, transfer->buffer, transfer->actual_length, 0x20, TRUE) == RX_TLS &&
      !g5120_tls_feed (self->tls, self->rx_tls->data, self->rx_tls->len, &terr))
    {
      fpi_ssm_mark_failed (ssm, proto_error (terr, "TLS"));
      return;
    }

  self->cap_reads++;
  fpi_ssm_jump_to_state (ssm, CAP_READ);
}

static void
cap_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);
  GError *error = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case CAP_REQUEST:
      if (self->deactivating)
        {
          fpi_ssm_mark_completed (ssm);
          return;
        }
      g_byte_array_set_size (self->plain, 0);
      self->cap_reads = 0;
      /* Completes once the ACK has come and the image pack has been fed. */
      start_step (ssm, self, g5120_step_get_image ());
      break;

    case CAP_READ:
      {
        guint8 buf[4096];
        gssize n;

        while ((n = g5120_tls_read (self->tls, buf, sizeof (buf), &error)) > 0)
          g_byte_array_append (self->plain, buf, n);
        memset (buf, 0, sizeof (buf));
        if (n < 0)
          {
            fpi_ssm_mark_failed (ssm, proto_error (error, "decrypting the image"));
            return;
          }

        /* The frame is one record, so once a record has decrypted, the
         * plaintext is complete; its length decides the layout. */
        if (self->plain->len > 0)
          fpi_ssm_next_state (ssm);
        else if (self->cap_reads >= G5120_MAX_READS_PER_STEP)
          fpi_ssm_mark_failed (ssm, fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                            "no whole image after %u transfers",
                                                            self->cap_reads));
        else
          submit_read (ssm, dev, G5120_TIMEOUT_IMAGE, NULL, cap_read_cb);
      }
      break;

    case CAP_DECODE:
      {
        g_autofree guint16 *samples = g_new (guint16, G5120_IMG_SAMPLES);
        g_autoptr(FpImage) img = NULL;
        const guint8 *packed;
        gboolean wrapped;

        packed = g5120_frame_samples (self->plain->data, self->plain->len, &wrapped, &error);
        if (packed == NULL ||
            !g5120_decode_12bit (packed, G5120_IMG_PACKED_LEN, samples, G5120_IMG_SAMPLES, &error))
          {
            memset (self->plain->data, 0, self->plain->len);
            fpi_ssm_mark_failed (ssm, proto_error (error, "image"));
            return;
          }
        fp_dbg ("image: %u plaintext bytes, %s", self->plain->len,
                wrapped ? "8-byte header + samples + 5-byte trailer" : "bare samples");

        img = fp_image_new (G5120_IMG_WIDTH, G5120_IMG_HEIGHT);
        g5120_samples_to_gray8 (samples, G5120_IMG_SAMPLES, img->data);
        memset (samples, 0, G5120_IMG_SAMPLES * sizeof (guint16));
        memset (self->plain->data, 0, self->plain->len);
        g_byte_array_set_size (self->plain, 0);

        g_clear_object (&self->captured);
        if (G5120_ENLARGE_FACTOR > 1)
          self->captured = fpi_image_resize (img, G5120_ENLARGE_FACTOR, G5120_ENLARGE_FACTOR);
        else
          self->captured = g_steal_pointer (&img);
        self->result = RESULT_IMAGE;
        fpi_ssm_mark_completed (ssm);
      }
      break;

    default:
      g_assert_not_reached ();
    }
}

/* ---- Activation and the session loop ------------------------------------ */

static void
session_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);
  FpImageDevice *img_dev = FP_IMAGE_DEVICE (dev);
  G5120Result result = self->result;

  self->ssm = NULL;
  self->result = RESULT_NONE;
  g_clear_object (&self->fdt_cancel);

  if (error)
    {
      /* Neither TLS nor the EC's state is trustworthy after a failed exchange.
       * Invalidate before notifying libfprint, whose callbacks may re-enter.
       * This also applies to errors suppressed during deactivation. Expected
       * cancellation of an FDT wait completes without an error. */
      self->session_valid = FALSE;
      g_clear_pointer (&self->tls, g5120_tls_free);
      if (self->plain->len)
        memset (self->plain->data, 0, self->plain->len);
      g_byte_array_set_size (self->plain, 0);
      g_byte_array_set_size (self->rx_tls, 0);
    }

  if (self->deactivating)
    {
      if (error)
        fp_dbg ("session ended while deactivating: %s", error->message);
      g_clear_error (&error);
      g_clear_object (&self->captured);
      self->deactivating = FALSE;
      fpi_image_device_deactivate_complete (img_dev, NULL);
      return;
    }

  if (error)
    {
      g_clear_object (&self->captured);
      fpi_image_device_session_error (img_dev, error);
      return;
    }

  switch (result)
    {
    case RESULT_FINGER_DOWN:
      fpi_image_device_report_finger_status (img_dev, TRUE);
      break;

    case RESULT_FINGER_UP:
      fpi_image_device_report_finger_status (img_dev, FALSE);
      break;

    case RESULT_IMAGE:
      fpi_image_device_image_captured (img_dev, g_steal_pointer (&self->captured));
      break;

    case RESULT_NONE:
      break;
    }
}

static void
start_session (FpiDeviceGoodix5120 *self, FpiSsmHandlerCallback handler, int nr_states)
{
  if (self->ssm != NULL)
    {
      /* Two machines on the device at once would break half duplex. */
      fp_warn ("a session machine is already running; not starting another");
      return;
    }
  self->result = RESULT_NONE;
  self->ssm = fpi_ssm_new (FP_DEVICE (self), handler, nr_states);
  fpi_ssm_start (self->ssm, session_done);
}

static void
dev_change_state (FpImageDevice *dev, FpiImageDeviceState state)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);

  if (self->deactivating || !self->session_valid)
    return;

  switch (state)
    {
    case FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON:
      self->fdt_mode = G5120_CMD_FDT_DOWN;
      start_session (self, fdt_run_state, FDT_NUM_STATES);
      break;

    case FPI_IMAGE_DEVICE_STATE_CAPTURE:
      start_session (self, cap_run_state, CAP_NUM_STATES);
      break;

    case FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_OFF:
      self->fdt_mode = G5120_CMD_FDT_UP;
      start_session (self, fdt_run_state, FDT_NUM_STATES);
      break;

    case FPI_IMAGE_DEVICE_STATE_INACTIVE:
    case FPI_IMAGE_DEVICE_STATE_ACTIVATING:
    case FPI_IMAGE_DEVICE_STATE_DEACTIVATING:
    case FPI_IMAGE_DEVICE_STATE_IDLE:
      break;
    }
}

static void
dev_activate (FpImageDevice *dev)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);

  if (!self->session_valid)
    {
      fpi_image_device_activate_complete (dev,
                                          fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                                    "Session unavailable; close and reopen "
                                                                    "the device before another operation"));
      return;
    }

  /* The TLS session was set up at open; there is nothing to send here. */
  self->base_invalid = 0; /* a fresh operation, including after cancellation */
  self->deactivating = FALSE;
  fpi_image_device_activate_complete (dev, NULL);
}

static void
dev_deactivate (FpImageDevice *dev)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);

  if (self->ssm == NULL)
    {
      fpi_image_device_deactivate_complete (dev, NULL);
      return;
    }

  /* A command in flight finishes first (the machines check the flag at each
   * state); a wait for a finger is cancelled. The EC stays armed. */
  self->deactivating = TRUE;
  if (self->fdt_cancel)
    g_cancellable_cancel (self->fdt_cancel);
}

/* ---- GObject ------------------------------------------------------------ */

static const FpIdEntry id_table[] = {
  { .vid = 0x27c6, .pid = 0x5120, },
  { .vid = 0,      .pid = 0,      },
};

static void
fpi_device_goodix5120_init (FpiDeviceGoodix5120 *self)
{
  self->x_data = g_byte_array_new ();
  self->rx_tls = g_byte_array_new ();
  self->plain = g_byte_array_new ();
  memcpy (self->down_thr, g5120_fdt_initial_down_thresholds, sizeof (self->down_thr));
  /* TODO: derive from the OTP ("OTP tcode 272, fdt delta 27" on this unit;
   * the vendor falls back to 21). */
  self->fdt_delta = G5120_FDT_DELTA_THIS_DEVICE;
}

static void
fpi_device_goodix5120_finalize (GObject *object)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (object);

  g_clear_pointer (&self->tls, g5120_tls_free);
  g_clear_object (&self->captured);
  g_clear_object (&self->fdt_cancel);
  if (self->plain->len)
    memset (self->plain->data, 0, self->plain->len);
  g_byte_array_unref (self->plain);
  g_byte_array_unref (self->x_data);
  g_byte_array_unref (self->rx_tls);

  G_OBJECT_CLASS (fpi_device_goodix5120_parent_class)->finalize (object);
}

static void
fpi_device_goodix5120_class_init (FpiDeviceGoodix5120Class *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);
  FpImageDeviceClass *img_class = FP_IMAGE_DEVICE_CLASS (klass);

  object_class->finalize = fpi_device_goodix5120_finalize;

  dev_class->id = "goodix5120";
  dev_class->full_name = "Goodix 27c6:5120 behind an ITE EC (TLS-PSK)";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;

  img_class->img_open = dev_open;
  img_class->img_close = dev_close;
  img_class->activate = dev_activate;
  img_class->deactivate = dev_deactivate;
  img_class->change_state = dev_change_state;

  img_class->img_width = G5120_IMG_WIDTH * G5120_ENLARGE_FACTOR;
  img_class->img_height = G5120_IMG_HEIGHT * G5120_ENLARGE_FACTOR;
  img_class->bz3_threshold = G5120_BZ3_THRESHOLD;
}
