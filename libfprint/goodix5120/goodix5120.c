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
 *          0xd4, 5 s listen-only read, 0xae
 *   touch: 0x32 arm -> finger-down event -> 0x20 -> image (one TLS
 *          application-data record in a 0xb0 pack) -> 0x34 arm ->
 *          finger-up event -> re-arm 0x32 from the up readings
 *   close: nothing is sent
 *
 * Enroll, verify, identify and capture are this driver's own actions, one
 * touch each (enroll: one per stage), matched with SIGFM rather than NBIS
 * (goodix5120_match.h). Matching never sends anything.
 *
 * Never logged: the PSK, the 0xe4 reply (a hash of the PSK), the 0xa6 reply
 * (OTP), TLS record bodies, and image data.
 */

#define FP_COMPONENT "goodix5120"

#include <string.h>

#include "drivers_api.h"
#include "goodix5120.h"
#include "goodix5120_match.h"
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
  FpDevice      parent;

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
  gint64        x_listen_until; /* drain only: keep reading until then, 0 = until quiet */
  guint         x_quiet;        /* drain only: ms of silence that ends it */
  gint64        open_started;   /* monotonic time of dev_open, for the "open: N ms" line */
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
  gint64        finger_down_at; /* monotonic time of this touch's finger-down */
  gint64        contact_ms;     /* how long the last touch stayed on the sensor */

  /* Matching (goodix5120_match.h). */
  G5120View    *probe;          /* this touch's features */
  GError       *probe_retry;    /* or why this touch cannot be used (FP_DEVICE_RETRY) */
  GPtrArray    *enroll_views;   /* enroll: G5120View * so far */
  GPtrArray    *gallery;        /* verify/identify: per print, a GPtrArray of its views */

  /* The action's touch loop. */
  FpiSsm       *ssm;            /* the one running session machine, if any */
  G5120Result   result;
  GCancellable *fdt_cancel;
  gboolean      cancelling;
};

G_DEFINE_TYPE (FpiDeviceGoodix5120, fpi_device_goodix5120, FP_TYPE_DEVICE)

static void session_done (FpiSsm *ssm, FpDevice *dev, GError *error);
static void matching_clear (FpiDeviceGoodix5120 *self);

/* ---- Helpers ------------------------------------------------------------- */

/* Wire-level detail, only with GOODIX5120_TRACE=1 (g5120_trace_enabled). */
#define trace(...) G_STMT_START { if (g5120_trace_enabled ()) fp_dbg (__VA_ARGS__); } G_STMT_END

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
      trace ("empty transfer");
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
      trace ("TLS pack (flags 0x%02x), %" G_GSIZE_FORMAT " bytes", flags, pl_len);
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
          trace ("ACK for %s (0x%02x), status 0x%02x", opcode_name (acked), acked, status);
          self->rx_ack_status = status;
          return RX_ACK;
        }
      trace ("ACK for 0x%02x while waiting on 0x%02x; ignored", acked, expect);
      return RX_OTHER;
    }

  /* Finger-detect events come unprompted, so they are recognised before a
   * data reply: an 0x32 event is not the reply to an 0x32 arm. */
  if (g5120_is_fdt_cmd (cmd) &&
      g5120_fdt_decode_event (cmd, mp, mp_len, &self->rx_fdt, NULL))
    {
      trace ("FDT event 0x%02x (%s): header %02x %02x %02x %02x, zones %u %u %u %u %u %u",
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
          trace ("reply to %s (0x%02x): %" G_GSIZE_FORMAT " bytes (contents not logged)",
                 opcode_name (cmd), cmd, mp_len);
        }
      else if (g5120_trace_enabled ())
        {
          g_autofree gchar *h = hexstr (mp, mp_len);

          fp_dbg ("reply to %s (0x%02x): %s", opcode_name (cmd), cmd, h);
        }
      g_byte_array_set_size (self->x_data, 0);
      g_byte_array_append (self->x_data, mp, mp_len);
      return RX_DATA;
    }

  trace ("unsolicited message 0x%02x, %" G_GSIZE_FORMAT " bytes; ignored", cmd, mp_len);
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
          if (self->x_reply != G5120_REPLY_NONE)
            fpi_ssm_mark_failed (ssm, missing_reply_error (self));
          else if (self->x_listen_until > g_get_monotonic_time ())
            fpi_ssm_jump_to_state (ssm, XCHG_RECV);
          else
            fpi_ssm_mark_completed (ssm);
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
      if (self->x_listen_until)
        {
          /* Dropping it would desynchronise the record sequence numbers. */
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                         "TLS record of %u bytes from the EC after the "
                                                         "0xd4 ACK, before any request; stopping",
                                                         self->rx_tls->len));
          return;
        }
      fp_warn ("unexpected TLS pack of %u bytes while waiting on 0x%02x; dropped",
               self->rx_tls->len, self->x_cmd);
      break;

    case RX_FDT:
      /* Before the arm's own ACK, an event is stale: it answers an earlier
       * arm (the EC stays armed across sessions; Windows leaves it armed). */
      trace ("finger-detect event while waiting on 0x%02x; dropped as stale", self->x_cmd);
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

        trace ("-> %s (0x%02x), %" G_GSIZE_FORMAT "-byte payload: %s",
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
      if (self->x_listen_until)
        {
          gint64 remaining = self->x_listen_until - g_get_monotonic_time ();

          if (remaining <= 0)
            {
              fpi_ssm_mark_completed (ssm);
              return;
            }
          submit_read (ssm, dev, (guint) ((remaining + 999) / 1000), NULL, xchg_recv_cb);
          return;
        }
      submit_read (ssm, dev,
                   self->x_reply == G5120_REPLY_NONE ? self->x_quiet : G5120_TIMEOUT_REPLY,
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
                guint                listen_ms,
                guint                quiet_ms,
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
  self->x_listen_until = listen_ms ? g_get_monotonic_time () + (gint64) listen_ms * 1000 : 0;
  self->x_quiet = quiet_ms;
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
  begin_exchange (parent, self, TRUE, FALSE, cmd, payload, payload_len, reply, secret, 0, G5120_TIMEOUT_QUIET, purpose);
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
                  step->reply, step->secret_reply, 0, G5120_TIMEOUT_QUIET, step->purpose);
}

/* Reads until the device has been quiet for @quiet_ms, so no reply is left
 * queued in the EC. Sends nothing. */
static void
start_drain (FpiSsm *parent, FpiDeviceGoodix5120 *self, guint quiet_ms)
{
  begin_exchange (parent, self, FALSE, FALSE, 0x00, NULL, 0, G5120_REPLY_NONE, TRUE, 0, quiet_ms, "drain");
}

/* Reads IN for a fixed time, quiet or not. Sends nothing. A TLS record in
 * that window fails the exchange instead of being dropped. */
static void
start_listen (FpiSsm *parent, FpiDeviceGoodix5120 *self, guint ms)
{
  begin_exchange (parent, self, FALSE, FALSE, 0x00, NULL, 0, G5120_REPLY_NONE, TRUE, ms, G5120_TIMEOUT_QUIET, "listen");
}

/* ---- TLS-PSK handshake ------------------------------------------------------
 *
 * Read one transfer from the EC, feed it to the server, send every record the
 * server produced in its own 0xb0 pack, and go straight back to reading.
 * Read through the EC's flight without waiting for new host output: its
 * ClientKeyExchange, ChangeCipherSpec and Finished are separate transfers,
 * 22 ms and 5 ms apart. Waiting on the host here stalled Runs 11 and 17.
 *
 * Between ServerHello and ServerHelloDone there is a bounded read interval
 * (HS_PACE). The vendor's log has 61 ms there; the Go probe, which completed
 * Runs 18-22, left ~3 ms. Runs 24 and 25 sent both records within a
 * millisecond and drew decode_error both times. This is a timing hypothesis,
 * not a confirmed fix. Read any complete alert before sending another record;
 * record counts describe progress when it was seen.
 *
 * The final flight (ChangeCipherSpec, Finished) is paced the same way, and
 * HS_SETTLE then reads for G5120_TIMEOUT_HS_SETTLE before the handshake counts
 * as complete. Every failing C run had one pair of host writes within ~1 ms
 * (Runs 24/25 ServerHello/ServerHelloDone, 26/27 Finished/0xd4, 28-30
 * ChangeCipherSpec/Finished); Go's working runs never went below ~2.5 ms
 * (Run 31). Also a timing hypothesis. A record the EC sends after the
 * handshake completed locally (an alert) fails open before 0xd4.
 */

enum {
  HS_READ,
  HS_WRITE,
  HS_PACE,
  HS_SETTLE,
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

/* After the handshake, any complete record from the EC is processed now: an
 * alert fails, and application data before 0xd4 has no place in the protocol. */
static gboolean
hs_settle_check (FpiDeviceGoodix5120 *self, GError **error)
{
  guint8 buf[64];
  gssize n;

  if (g5120_tls_has_partial_input (self->tls))
    return TRUE;
  n = g5120_tls_read (self->tls, buf, sizeof (buf), error);
  memset (buf, 0, sizeof (buf));
  if (n > 0)
    g_set_error (error, G5120_TLS_ERROR, G5120_TLS_ERROR_FAILED,
                 "application data from the EC before 0xd4");
  return n == 0;
}

/* HS_PACE and HS_SETTLE keep their original deadline across stale/empty reads.
 * Complete a fragmented incoming record before output, even if the interval has
 * expired; the overall handshake budget bounds that additional wait. */
static void
hs_receive (FpiUsbTransfer *transfer, FpDevice *dev, GError *error, int next)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);
  FpiSsm *ssm = transfer->ssm;
  GError *terr = NULL;
  gboolean done = FALSE;
  gboolean pacing = next == HS_PACE;

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
      if (self->hs_done)
        {
          if (!g5120_tls_feed (self->tls, self->rx_tls->data, self->rx_tls->len, &terr) ||
              !hs_settle_check (self, &terr))
            {
              fpi_ssm_mark_failed (ssm, handshake_error (self, terr));
              return;
            }
          fpi_ssm_jump_to_state (ssm, next);
          return;
        }
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
      if (next == HS_READ)
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
  hs_receive (transfer, dev, error, HS_READ);
}

static void
hs_pace_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  hs_receive (transfer, dev, error, HS_PACE);
}

static void
hs_settle_cb (FpiUsbTransfer *transfer, FpDevice *dev, gpointer user_data, GError *error)
{
  hs_receive (transfer, dev, error, HS_SETTLE);
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
  /* Every pair of host records is paced (see the section comment). */
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
            trace ("TLS: inter-record interval completed (%d ms); sending the next record",
                   G5120_TIMEOUT_HS_PACE);
            fpi_ssm_jump_to_state (ssm, HS_WRITE);
            return;
          }
        if (gap > 0)
          read_budget = (guint) MIN ((gap + 999) / 1000, read_budget);
        submit_read (ssm, dev, read_budget, NULL, hs_pace_cb);
      }
      break;

    case HS_SETTLE:
      {
        gint64 gap = self->hs_pace_deadline - g_get_monotonic_time ();

        if (gap <= 0 && !g5120_tls_has_partial_input (self->tls))
          {
            trace ("TLS: EC quiet for %d ms after the host's Finished; handshake complete",
                   G5120_TIMEOUT_HS_SETTLE);
            fpi_ssm_mark_completed (ssm);
            return;
          }
        if (gap > 0)
          read_budget = (guint) MIN ((gap + 999) / 1000, read_budget);
        submit_read (ssm, dev, read_budget, NULL, hs_settle_cb);
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
              {
                self->hs_pace_deadline = g_get_monotonic_time () +
                                         (gint64) G5120_TIMEOUT_HS_SETTLE * 1000;
                fpi_ssm_jump_to_state (ssm, HS_SETTLE);
              }
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
  OPEN_LISTEN_AFTER_D4,
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
      /* After attach: stale finger-detect events and the unsolicited 0x32
       * arrive here (Run 29), so this one waits for the long silence. */
      start_drain (ssm, self, G5120_TIMEOUT_QUIET);
      break;

    case OPEN_DRAIN_AFTER_HEALTH:
    case OPEN_INIT_DRAIN:
    case OPEN_DRAIN_FINAL:
      /* Each exchange has already read its ACK and data reply in full. */
      start_drain (ssm, self, G5120_TIMEOUT_DRAIN_STEP);
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

    case OPEN_LISTEN_AFTER_D4:
      /* This was 5 s, after Go's collect (Runs 18/20), for the hypothesis
       * that the EC needs time undisturbed to mark the session up. Run 30
       * ruled that out; Runs 32/33 showed the cause was two host writes
       * under ~1 ms apart. The EC was silent in every 5 s window (Runs 30,
       * 32-34). A short window keeps every host write gap >= 10 ms. */
      trace ("reading IN for %d ms after the 0xd4 ACK before the next command",
             G5120_TIMEOUT_POST_D4);
      start_listen (ssm, self, G5120_TIMEOUT_POST_D4);
      break;

    case OPEN_MCU_STATE:
      start_step (ssm, self, g5120_step_mcu_state ());
      break;

    case OPEN_LOG_MCU_STATE:
      /* This state follows authenticated peer Finished, completed host records
       * and a positive d4 ACK. The owner's 08:03 run then returned status 00
       * immediately, despite completing TLS. Do not infer that its TLS bit is
       * set or invent a delay/retry. Accept that observed value here only;
       * other bit-clear states, including the known stuck 08, remain errors. */
      if (self->x_data->len != 20 ||
          (!(self->x_data->data[1] & 0x02) && self->x_data->data[1] != 0x00))
        {
          fpi_ssm_mark_failed (ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                         "unexpected MCU state after authenticated TLS "
                                                         "and the TLS-established ACK; refusing to activate"));
          return;
        }
      if (self->x_data->data[1] == 0x00)
        fp_info ("immediate MCU status 0x00: TLS status bit is clear; continuing after "
                 "authenticated TLS and the positive TLS-established ACK");
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
  if (!error)
    fp_dbg ("open: %" G_GINT64_FORMAT " ms", (g_get_monotonic_time () - self->open_started) / 1000);
  if (error)
    {
      g_autoptr(GError) cleanup_error = NULL;
      release_interface (self, &cleanup_error);
      if (cleanup_error)
        g_prefix_error (&error, "Interface cleanup also failed (%s): ", cleanup_error->message);
      g_clear_pointer (&self->tls, g5120_tls_free);
    }

  fpi_device_open_complete (dev, error);
}

static void
dev_open (FpDevice *dev)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);
  FpiSsm *ssm;

  self->session_valid = FALSE;
  if (self->interface_cleanup_failed)
    {
      fpi_device_open_complete (dev,
                                fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                          "Previous interface cleanup failed; recreate "
                                                          "the device before reopening"));
      return;
    }
  self->open_started = g_get_monotonic_time ();
  ssm = fpi_ssm_new (dev, open_run_state, OPEN_NUM_STATES);
  fpi_ssm_start (ssm, open_done);
}

static void
dev_close (FpDevice *dev)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);
  GError *error = NULL;

  /* Nothing is sent: no command that ends a session is known. The EC keeps
   * the TLS session and whatever FDT arm it last had, as Windows leaves it;
   * a later open repeats the full init and handshake, which Runs 20-22 showed
   * works after a completed handshake, four times with no EC reset. */
  self->session_valid = FALSE;
  matching_clear (self);
  g_clear_pointer (&self->tls, g5120_tls_free);
  release_interface (self, &error);
  fpi_device_close_complete (dev, error);
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
      trace ("event 0x%02x while armed with 0x%02x; ignored", self->rx_fdt_cmd, self->fdt_mode);
      fpi_ssm_jump_to_state (ssm, FDT_WAIT);
      return;
    }

  switch (ev->kind)
    {
    case G5120_FDT_EVENT_DOWN:
      /* Up thresholds come from the readings with the finger on. */
      g5120_fdt_up_thresholds (ev->zones, ev->touchflags, self->fdt_delta, self->up_thr);
      fp_dbg ("finger down");
      self->finger_down_at = g_get_monotonic_time ();
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
        {
          fp_dbg ("'base invalid'; re-arming with the current readings");
          g5120_fdt_down_thresholds (ev->zones, self->down_thr);
        }
      fpi_ssm_jump_to_state (ssm, FDT_ARM);
      return;

    case G5120_FDT_EVENT_UP:
      /* The next down arm comes from the readings with the finger off. */
      g5120_fdt_down_thresholds (ev->zones, self->down_thr);
      self->contact_ms = (g_get_monotonic_time () - self->finger_down_at) / 1000;
      fp_dbg ("finger up after %" G_GINT64_FORMAT " ms", self->contact_ms);
      self->result = RESULT_FINGER_UP;
      fpi_ssm_mark_completed (ssm);
      return;

    case G5120_FDT_EVENT_MANUAL:
    case G5120_FDT_EVENT_UNKNOWN:
    default:
      trace ("%s event while armed with 0x%02x; still waiting",
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
      if (self->cancelling && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
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

  if (self->cancelling)
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

        trace ("arming 0x%02x with thresholds %02x %02x %02x %02x %02x %02x",
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
      if (self->cancelling)
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
        guint16 lo, hi;

        packed = g5120_frame_samples (self->plain->data, self->plain->len, &wrapped, &error);
        if (packed == NULL ||
            !g5120_decode_12bit (packed, G5120_IMG_PACKED_LEN, samples, G5120_IMG_SAMPLES, &error))
          {
            memset (self->plain->data, 0, self->plain->len);
            fpi_ssm_mark_failed (ssm, proto_error (error, "image"));
            return;
          }
        trace ("image: %u plaintext bytes, %s", self->plain->len,
               wrapped ? "8-byte header + samples + 5-byte trailer" : "bare samples");

        img = fp_image_new (G5120_IMG_WIDTH, G5120_IMG_HEIGHT);
        g5120_samples_to_gray8_stretched (samples, G5120_IMG_SAMPLES, img->data, &lo, &hi);
        /* Two percentile bounds, not pixels: they show the frame's contrast. */
        fp_dbg ("image: stretched 12-bit samples %u..%u to 0..255", lo, hi);
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

/* ---- Actions: the touch loop ---------------------------------------------
 *
 * Every action is one touch or more, and a touch is three machines in turn,
 * one at a time (half duplex):
 *
 *   FDT down (arm 0x32, wait) -> capture (0x20, image) -> FDT up (arm 0x34, wait)
 *
 * SIGFM features are extracted between capture and lift, and the result is
 * reported after the lift, so an action always ends with the finger off and
 * nothing outstanding, as the image-device class did. Enroll repeats the touch
 * until G5120_ENROLL_STAGES views are usable. Nothing new goes on the wire:
 * the frames are those of Runs 34-40.
 */

#define G5120_TEMPLATE_WIDTH  (G5120_IMG_WIDTH * G5120_ENLARGE_FACTOR)
#define G5120_TEMPLATE_HEIGHT (G5120_IMG_HEIGHT * G5120_ENLARGE_FACTOR)

static void
clear_captured (FpiDeviceGoodix5120 *self)
{
  if (self->captured)
    memset (self->captured->data, 0, self->captured->width * self->captured->height);
  g_clear_object (&self->captured);
}

static void
matching_clear (FpiDeviceGoodix5120 *self)
{
  g_clear_pointer (&self->probe, g5120_view_free);
  g_clear_error (&self->probe_retry);
  g_clear_pointer (&self->enroll_views, g_ptr_array_unref);
  g_clear_pointer (&self->gallery, g_ptr_array_unref);
  clear_captured (self);
}

/* Ends the action with @error (owned), which is never a retry error. */
static void
action_fail (FpiDeviceGoodix5120 *self, GError *error)
{
  matching_clear (self);
  fpi_device_action_error (FP_DEVICE (self), error);
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
start_touch (FpiDeviceGoodix5120 *self)
{
  fpi_device_report_finger_status_changes (FP_DEVICE (self), FP_FINGER_STATUS_NEEDED, FP_FINGER_STATUS_NONE);
  self->fdt_mode = G5120_CMD_FDT_DOWN;
  start_session (self, fdt_run_state, FDT_NUM_STATES);
}

/* The captured image becomes this touch's probe, or the reason to touch again. */
static void
extract_probe (FpiDeviceGoodix5120 *self)
{
  g_autoptr(GError) error = NULL;
  FpImage *img = self->captured;
  guint keypoints;

  g_clear_pointer (&self->probe, g5120_view_free);
  g_clear_error (&self->probe_retry);
  self->probe = g5120_view_extract (img->data, img->width, img->height, &error);
  clear_captured (self);
  if (self->probe == NULL)
    {
      fp_warn ("%s", error->message);
      self->probe_retry = fpi_device_retry_new_msg (FP_DEVICE_RETRY_GENERAL,
                                                    "This touch could not be read, please try again");
      return;
    }

  keypoints = g5120_view_keypoints (self->probe);
  fp_dbg ("SIGFM: %u keypoints", keypoints);
  if (keypoints < G5120_MATCH_MIN_KEYPOINTS)
    {
      g_clear_pointer (&self->probe, g5120_view_free);
      self->probe_retry = fpi_device_retry_new_msg (FP_DEVICE_RETRY_CENTER_FINGER,
                                                    "Too few features in this touch (%u < %u); "
                                                    "press the finger flat on the sensor",
                                                    keypoints, G5120_MATCH_MIN_KEYPOINTS);
    }
}

/* A brush is a retry, whatever its image scored. */
static void
check_contact (FpiDeviceGoodix5120 *self)
{
  if (self->probe_retry || self->contact_ms >= G5120_MIN_CONTACT_MS)
    return;
  g_clear_pointer (&self->probe, g5120_view_free);
  self->probe_retry = fpi_device_retry_new_msg (FP_DEVICE_RETRY_TOO_SHORT,
                                                "The finger left the sensor after %" G_GINT64_FORMAT
                                                " ms; leave it on a little longer", self->contact_ms);
}

static void
enroll_touch_done (FpiDeviceGoodix5120 *self)
{
  FpDevice *dev = FP_DEVICE (self);
  FpPrint *print = NULL;
  GVariant *data;

  if (self->probe_retry)
    {
      fpi_device_enroll_progress (dev, self->enroll_views->len, NULL, g_steal_pointer (&self->probe_retry));
      start_touch (self);
      return;
    }

  /* A number, not biometric data: how much this view overlaps the others. */
  if (self->enroll_views->len > 0)
    fp_dbg ("enroll view %u: best SIGFM score against the earlier views %d", self->enroll_views->len + 1,
            g5120_template_best_score (self->enroll_views, self->probe, NULL));
  g_ptr_array_add (self->enroll_views, g_steal_pointer (&self->probe));
  fpi_device_enroll_progress (dev, self->enroll_views->len, NULL, NULL);
  if (self->enroll_views->len < G5120_ENROLL_STAGES)
    {
      start_touch (self);
      return;
    }

  fpi_device_get_enroll_data (dev, &print);
  data = g5120_template_new (self->enroll_views, G5120_TEMPLATE_WIDTH, G5120_TEMPLATE_HEIGHT);
  fpi_print_set_type (print, FPI_PRINT_RAW);
  g_object_set (print, "fpi-data", data, NULL);
  matching_clear (self);
  fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
}

/* The best score of the probe against each print of the gallery, logged. */
static gint
gallery_score (FpiDeviceGoodix5120 *self, guint print)
{
  gint score = g5120_template_best_score (g_ptr_array_index (self->gallery, print), self->probe, NULL);

  if (score < 0)
    fp_warn ("SIGFM failed to compare against print %u; treating it as no match", print);
  fp_info ("print %u: best SIGFM score %d, threshold %d", print, score, G5120_MATCH_THRESHOLD);
  return score;
}

static void
verify_touch_done (FpiDeviceGoodix5120 *self)
{
  FpDevice *dev = FP_DEVICE (self);
  FpiMatchResult result;

  if (self->probe_retry)
    {
      fpi_device_verify_report (dev, FPI_MATCH_ERROR, NULL, g_steal_pointer (&self->probe_retry));
      matching_clear (self);
      fpi_device_verify_complete (dev, NULL);
      return;
    }

  result = gallery_score (self, 0) >= G5120_MATCH_THRESHOLD ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL;
  matching_clear (self);
  /* No scanned print: a raw print is compared by its data, which a one-view
   * probe never equals, so libfprint would discard it with a warning. */
  fpi_device_verify_report (dev, result, NULL, NULL);
  fpi_device_verify_complete (dev, NULL);
}

static void
identify_touch_done (FpiDeviceGoodix5120 *self)
{
  FpDevice *dev = FP_DEVICE (self);
  GPtrArray *prints = NULL;
  FpPrint *match = NULL;
  gint best = -1;

  if (self->probe_retry)
    {
      fpi_device_identify_report (dev, NULL, NULL, g_steal_pointer (&self->probe_retry));
      matching_clear (self);
      fpi_device_identify_complete (dev, NULL);
      return;
    }

  fpi_device_get_identify_data (dev, &prints);
  for (guint i = 0; i < self->gallery->len; i++)
    {
      gint score = gallery_score (self, i);

      if (score >= G5120_MATCH_THRESHOLD && score > best)
        {
          best = score;
          match = g_ptr_array_index (prints, i);
        }
    }
  matching_clear (self);
  fpi_device_identify_report (dev, match, NULL, NULL);
  fpi_device_identify_complete (dev, NULL);
}

static void
touch_done (FpiDeviceGoodix5120 *self)
{
  FpDevice *dev = FP_DEVICE (self);

  switch (fpi_device_get_current_action (dev))
    {
    case FPI_DEVICE_ACTION_ENROLL:
      enroll_touch_done (self);
      break;

    case FPI_DEVICE_ACTION_VERIFY:
      verify_touch_done (self);
      break;

    case FPI_DEVICE_ACTION_IDENTIFY:
      identify_touch_done (self);
      break;

    case FPI_DEVICE_ACTION_CAPTURE:
      {
        FpImage *image = g_steal_pointer (&self->captured);

        matching_clear (self);
        fpi_device_capture_complete (dev, image, NULL);
      }
      break;

    case FPI_DEVICE_ACTION_NONE:
    case FPI_DEVICE_ACTION_PROBE:
    case FPI_DEVICE_ACTION_OPEN:
    case FPI_DEVICE_ACTION_CLOSE:
    case FPI_DEVICE_ACTION_LIST:
    case FPI_DEVICE_ACTION_DELETE:
    case FPI_DEVICE_ACTION_CLEAR_STORAGE:
    default:
      action_fail (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "touch finished outside an action"));
    }
}

static void
session_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);
  G5120Result result = self->result;

  self->ssm = NULL;
  self->result = RESULT_NONE;
  g_clear_object (&self->fdt_cancel);

  if (error)
    {
      /* Neither TLS nor the EC's state is trustworthy after a failed exchange.
       * Invalidate before notifying libfprint, whose callbacks may re-enter.
       * This also applies to errors suppressed while cancelling. Expected
       * cancellation of an FDT wait completes without an error. */
      self->session_valid = FALSE;
      g_clear_pointer (&self->tls, g5120_tls_free);
      if (self->plain->len)
        memset (self->plain->data, 0, self->plain->len);
      g_byte_array_set_size (self->plain, 0);
      g_byte_array_set_size (self->rx_tls, 0);
    }

  if (self->cancelling)
    {
      if (error)
        fp_dbg ("session ended while cancelling: %s", error->message);
      g_clear_error (&error);
      self->cancelling = FALSE;
      action_fail (self, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "Operation was cancelled"));
      return;
    }

  if (error)
    {
      action_fail (self, error);
      return;
    }

  switch (result)
    {
    case RESULT_FINGER_DOWN:
      fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_PRESENT, FP_FINGER_STATUS_NEEDED);
      start_session (self, cap_run_state, CAP_NUM_STATES);
      break;

    case RESULT_IMAGE:
      if (fpi_device_get_current_action (dev) != FPI_DEVICE_ACTION_CAPTURE)
        extract_probe (self);
      self->fdt_mode = G5120_CMD_FDT_UP;
      start_session (self, fdt_run_state, FDT_NUM_STATES);
      break;

    case RESULT_FINGER_UP:
      fpi_device_report_finger_status_changes (dev, FP_FINGER_STATUS_NONE, FP_FINGER_STATUS_PRESENT);
      if (fpi_device_get_current_action (dev) != FPI_DEVICE_ACTION_CAPTURE)
        check_contact (self);
      touch_done (self);
      break;

    case RESULT_NONE:
      action_fail (self, fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL, "touch ended without a result"));
      break;
    }
}

/* Common to every action: refuse without a valid session, before any I/O. */
static gboolean
action_begin (FpiDeviceGoodix5120 *self)
{
  if (!self->session_valid || self->ssm != NULL)
    {
      fpi_device_action_error (FP_DEVICE (self),
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_GENERAL,
                                                         "Session unavailable; close and reopen "
                                                         "the device before another operation"));
      return FALSE;
    }

  /* The TLS session was set up at open; there is nothing to send here. */
  self->base_invalid = 0; /* a fresh operation, including after cancellation */
  self->cancelling = FALSE;
  return TRUE;
}

/* The views stored in @print, or NULL with a DATA_INVALID @error. */
static GPtrArray *
print_views (FpPrint *print, GError **error)
{
  g_autoptr(GVariant) data = NULL;
  g_autoptr(GError) local = NULL;
  GPtrArray *views;

  g_object_get (print, "fpi-data", &data, NULL);
  views = g5120_template_parse (data, G5120_TEMPLATE_WIDTH, G5120_TEMPLATE_HEIGHT, &local);
  if (views == NULL)
    g_propagate_error (error, fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID, "%s", local->message));
  return views;
}

static void
dev_enroll (FpDevice *dev)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);

  if (!action_begin (self))
    return;
  self->enroll_views = g_ptr_array_new_with_free_func ((GDestroyNotify) g5120_view_free);
  start_touch (self);
}

static void
dev_verify (FpDevice *dev)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);
  FpPrint *print = NULL;
  GPtrArray *views;
  GError *error = NULL;

  if (!action_begin (self))
    return;
  fpi_device_get_verify_data (dev, &print);
  views = print_views (print, &error);
  if (views == NULL)
    {
      action_fail (self, error);
      return;
    }
  self->gallery = g_ptr_array_new_with_free_func ((GDestroyNotify) g_ptr_array_unref);
  g_ptr_array_add (self->gallery, views);
  start_touch (self);
}

static void
dev_identify (FpDevice *dev)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);
  GPtrArray *prints = NULL;

  if (!action_begin (self))
    return;
  fpi_device_get_identify_data (dev, &prints);
  self->gallery = g_ptr_array_new_with_free_func ((GDestroyNotify) g_ptr_array_unref);
  for (guint i = 0; i < prints->len; i++)
    {
      GError *error = NULL;
      GPtrArray *views = print_views (g_ptr_array_index (prints, i), &error);

      if (views == NULL)
        {
          g_prefix_error (&error, "Print %u: ", i);
          action_fail (self, error);
          return;
        }
      g_ptr_array_add (self->gallery, views);
    }
  start_touch (self);
}

static void
dev_capture (FpDevice *dev)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);
  gboolean wait_for_finger = FALSE;

  fpi_device_get_capture_data (dev, &wait_for_finger);
  if (!wait_for_finger)
    {
      /* An image is only requested after a finger-down event. */
      fpi_device_action_error (dev, fpi_device_error_new (FP_DEVICE_ERROR_NOT_SUPPORTED));
      return;
    }
  if (!action_begin (self))
    return;
  start_touch (self);
}

static void
dev_cancel (FpDevice *dev)
{
  FpiDeviceGoodix5120 *self = FPI_DEVICE_GOODIX5120 (dev);

  if (self->ssm == NULL)
    return;

  /* A command in flight finishes first (the machines check the flag at each
   * state); a wait for a finger is cancelled. The EC stays armed. */
  self->cancelling = TRUE;
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
  matching_clear (self);
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

  object_class->finalize = fpi_device_goodix5120_finalize;

  dev_class->id = "goodix5120";
  dev_class->full_name = "Goodix 27c6:5120 behind an ITE EC (TLS-PSK)";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = G5120_ENROLL_STAGES;
  /* libfprint's default heat model fails an action after ~4 min of use, which
   * a slow 15-touch enroll can reach. The sensor images only on a touch and
   * otherwise waits in finger detection, which Windows leaves armed. */
  dev_class->temp_hot_seconds = -1;

  dev_class->open = dev_open;
  dev_class->close = dev_close;
  dev_class->enroll = dev_enroll;
  dev_class->verify = dev_verify;
  dev_class->identify = dev_identify;
  dev_class->capture = dev_capture;
  dev_class->cancel = dev_cancel;

  fpi_device_class_auto_initialize_features (dev_class);
}
