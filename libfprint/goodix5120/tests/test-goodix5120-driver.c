/*
 * Exercise the actual driver through its registered device vfuncs, one
 * libfprint action at a time. Only libfprint/USB boundaries and the SIGFM view
 * backend are faked; framing, TLS, image decode and the template format are real.
 * All key material and images are synthetic. This binary cannot access USB.
 */
#include <unistd.h>
#include <glib/gstdio.h>
#include <openssl/ssl.h>
#include "fake-libfprint.h"
#include "fake-matcher.h"
#include "goodix5120.h"
#include "goodix5120_match.h"
#include "goodix5120_proto.h"
#include "goodix5120_tls.h"
#include "shared-fixtures.h"

static GKeyFile *corpus;

typedef struct {
  FakeUsb usb;
  FpDevice *dev;
  gchar *key_path;
  SSL_CTX *ctx;
  SSL *client;
  guint8 key[32];
  guint frames, handshakes;
  gboolean check_init;
  guint corpus_position;
  gboolean auto_events;
  gboolean no_hello, corrupt_image;
  gboolean wrong_key;
  gboolean alert_after_hello; /* answer ServerHello alone with decode_error */
  gboolean close_after_finished; /* answer the host's Finished with close_notify */
  guint tls_fault; /* synthetic image: 1 = bad record type, 2 = bad ciphertext */
  guint image_parts;
  guint pattern; /* which synthetic image the fake EC sends: a different "finger" */
  const char *cancel_machine;
  gint cancel_state;
  guint cancel_phase;
  guint cancel_hits;
  GByteArray *out_frame;
  GPtrArray *sent_frames;
  gint64 tls_start;
} Fixture;

static void pump (Fixture *f);
static void peer_write (const guint8 *buf, gsize len, gpointer data);

/* Independent pack/message encoder: input fixtures do not come from the driver. */
static void
queue_pack (Fixture *f, guint8 flags, const guint8 *payload, gsize len)
{
  g_autofree guint8 *pack = g_malloc (len + 4);
  pack[0] = flags;
  pack[1] = len & 0xff;
  pack[2] = len >> 8;
  pack[3] = (pack[0] + pack[1] + pack[2]) & 0xff;
  memcpy (pack + 4, payload, len);
  fake_queue_bytes (&f->usb, pack, len + 4);
}

static void
queue_message (Fixture *f, guint8 cmd, const guint8 *payload, gsize len)
{
  g_autofree guint8 *msg = g_malloc (len + 4);
  guint8 sum = 0;
  msg[0] = cmd;
  msg[1] = (len + 1) & 0xff;
  msg[2] = (len + 1) >> 8;
  memcpy (msg + 3, payload, len);
  for (gsize i = 0; i < len + 3; i++)
    sum += msg[i];
  msg[len + 3] = 0xaa - sum;
  queue_pack (f, 0xa0, msg, len + 4);
}

static void
queue_ack (Fixture *f, guint8 cmd, guint8 status)
{
  const guint8 data[] = { cmd, status };
  queue_message (f, 0xb0, data, sizeof (data));
}

static void
queue_event (Fixture *f, guint8 cmd)
{
  /* Synthetic six-zone events; explicitly not a copied biometric fixture. */
  guint8 data[16] = { 0 };
  if (cmd == 0x32)
    {
      data[0] = 2;
      data[2] = 0x3f;
    }
  else
    data[1] = 2;
  for (guint i = 0; i < 6; i++)
    {
      data[4 + i * 2] = 0x90 + i * 2;
      data[5 + i * 2] = 1;
    }
  queue_message (f, cmd, data, sizeof (data));
}

static unsigned int
client_psk (SSL *ssl, const char *hint, char *identity, unsigned int identity_len,
            unsigned char *key, unsigned int key_len)
{
  Fixture *f = SSL_get_app_data (ssl);
  g_assert_null (hint);
  g_assert_cmpuint (key_len, >=, 32);
  g_assert_cmpuint (identity_len, >, strlen ("Client_identity"));
  g_strlcpy (identity, "Client_identity", identity_len);
  memcpy (key, f->key, 32);
  if (f->wrong_key)
    key[0] ^= 1;
  return 32;
}

static void
collect_client_records (Fixture *f)
{
  guint8 record[20000];
  BIO *out = SSL_get_wbio (f->client);
  int n;
  while (BIO_ctrl_pending (out))
    {
      gsize len;
      g_assert_cmpint (BIO_read (out, record, 5), ==, 5);
      len = ((gsize) record[3] << 8) | record[4];
      g_assert_cmpuint (len, <=, sizeof (record) - 5);
      n = BIO_read (out, record + 5, len);
      g_assert_cmpint (n, ==, len);
      if (record[0] == 0x17 && f->tls_fault)
        {
          if (f->tls_fault == 1)
            record[0] = 0x18;
          else
            record[len + 4] ^= 1;
        }
      if (record[0] == 0x17 && f->image_parts > 1)
        {
          gsize pos = 0;
          for (guint i = 0; i < f->image_parts; i++)
            {
              gsize end = (len + 5) * (i + 1) / f->image_parts;
              queue_pack (f, 0xb0, record + pos, end - pos);
              pos = end;
            }
        }
      else
        queue_pack (f, 0xb0, record, len + 5);
    }
}

static void
client_step (Fixture *f)
{
  int n = SSL_do_handshake (f->client);
  if (n != 1)
    g_assert_cmpint (SSL_get_error (f->client, n), ==, SSL_ERROR_WANT_READ);
  collect_client_records (f);
}

static void
start_client (Fixture *f)
{
  BIO *in, *out;
  SSL_free (f->client);
  SSL_CTX_free (f->ctx);
  f->ctx = SSL_CTX_new (TLS_client_method ());
  g_assert_nonnull (f->ctx);
  g_assert_true (SSL_CTX_set_min_proto_version (f->ctx, TLS1_2_VERSION));
  g_assert_true (SSL_CTX_set_max_proto_version (f->ctx, TLS1_2_VERSION));
  g_assert_true (SSL_CTX_set_cipher_list (f->ctx, "PSK-AES128-CBC-SHA256"));
  SSL_CTX_set_options (f->ctx, SSL_OP_NO_EXTENDED_MASTER_SECRET | SSL_OP_NO_ENCRYPT_THEN_MAC | SSL_OP_NO_TICKET);
  SSL_CTX_set_psk_client_callback (f->ctx, client_psk);
  f->client = SSL_new (f->ctx);
  g_assert_nonnull (f->client);
  SSL_set_app_data (f->client, f);
  in = BIO_new (BIO_s_mem ());
  out = BIO_new (BIO_s_mem ());
  BIO_set_mem_eof_return (in, -1);
  SSL_set_bio (f->client, in, out);
  SSL_set_connect_state (f->client);
  f->handshakes++;
  client_step (f);
}

static void
queue_image (Fixture *f)
{
  guint8 frame[7693] = { 0 };
  const guint8 patterns[][6] = {
    { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc },
    { 0x21, 0x43, 0x65, 0x87, 0xa9, 0xcb },
    { 0x55, 0x05, 0x50, 0x0a, 0xa0, 0xaa },
  };
  g_assert_cmpuint (f->pattern, <, G_N_ELEMENTS (patterns));
  for (gsize i = 8; i < 7688; i += 6)
    memcpy (frame + i, patterns[f->pattern], 6);
  g_assert_true (SSL_is_init_finished (f->client));
  g_assert_cmpint (SSL_write (f->client, frame, f->corrupt_image ? 17 : sizeof (frame)),
                   ==, f->corrupt_image ? 17 : sizeof (frame));
  f->frames++;
  collect_client_records (f);
}

static void
peer_frame (const guint8 *buf, gsize len, gpointer data)
{
  Fixture *f = data;
  const guint8 *payload, *mp;
  gsize payload_len, mp_len;
  guint8 flags, cmd;
  GError *error = NULL;

  g_assert_cmpuint (len % 64, ==, 0);
  g_assert_true (g5120_pack_decode (buf, len, &flags, &payload, &payload_len, &error));
  g_assert_no_error (error);
  if (flags == 0xb0)
    {
      g_assert_nonnull (f->client);
      if (f->alert_after_hello && payload_len > 5 && payload[0] == 0x16 && payload[5] == 0x02)
        {
          static const guint8 alert[] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 50 };
          queue_pack (f, 0xb0, alert, sizeof (alert));
          return;
        }
      g_assert_cmpint (BIO_write (SSL_get_rbio (f->client), payload, payload_len), ==, payload_len);
      client_step (f);
      if (f->close_after_finished && SSL_is_init_finished (f->client))
        {
          SSL_shutdown (f->client);
          collect_client_records (f);
        }
      return;
    }
  g_assert_cmphex (flags, ==, 0xa0);
  g_assert_true (g5120_message_decode (payload, payload_len, &cmd, &mp, &mp_len, &error));
  g_assert_no_error (error);
  /* A strict lifecycle scenario checks every submitted init byte, including
   * the health check, before replying from the independent corpus. */
  const char *section = NULL;
  g_autofree gchar *ordered = NULL;
  if (f->check_init && f->corpus_position < 15)
    {
      ordered = f->corpus_position == 0 ? g_strdup ("health") :
                g_strdup_printf ("init.%02u", f->corpus_position - 1);
      section = ordered;
      g_autoptr(GByteArray) expected = fixture_hex (corpus, section, "payload");
      g_assert_cmphex (cmd, ==, fixture_cmd (corpus, section, "cmd"));
      g_assert_cmpmem (mp, mp_len, expected->data, expected->len);
      f->corpus_position++;
    }
  else
    switch (cmd)
      {
      case 0x96: section = "init.00"; break;
      case 0xa8: section = "health"; break;
      case 0xae: section = f->client && SSL_is_init_finished (f->client) ? "init.13" : "init.02"; break;
      case 0xe4: section = "init.03"; break;
      case 0xa2: section = "init.04"; break;
      case 0x82: section = "init.05"; break;
      case 0xa6: section = "init.06"; break;
      case 0x70: section = "init.08"; break;
      case 0x98: section = "init.09"; break;
      case 0x90: section = "init.10"; break;
      case 0xd0: section = "init.11"; break;
      case 0xd4: section = "init.12"; break;
      }
  if (section)
    {
      G5120Reply mode = fixture_reply (corpus, section);
      if (mode & G5120_REPLY_ACK)
        queue_ack (f, cmd, 1);
      if (mode & G5120_REPLY_DATA)
        {
          g_autoptr(GByteArray) data_bytes = fixture_hex (corpus, section, "data");
          queue_message (f, cmd, data_bytes->data, data_bytes->len);
        }
      if ((mode & G5120_REPLY_TLS) && !f->no_hello)
        {
          f->tls_start = g_get_monotonic_time ();
          start_client (f);
        }
      return;
    }
  /* The fake speaks only the documented exchanges, never generic success. */
  switch (cmd)
    {
    case 0x32:
    case 0x34:
      queue_ack (f, cmd, 1);
      if (f->auto_events)
        queue_event (f, cmd);
      return;
    case 0x20:
      queue_ack (f, cmd, 1);
      queue_image (f);
      return;
    default:
      g_error ("unexpected outbound command 0x%02x", cmd);
    }
}

/* Assemble successful USB submissions using the literal outer wire length.
 * Keep usb.writes as the raw submission history for failure/packet assertions. */
static void
peer_write (const guint8 *buf, gsize len, gpointer data)
{
  Fixture *f = data;
  if (len == 0)
    return; /* no delivered bytes; let the real driver judge completion */
  g_assert_cmpuint (len % 64, ==, 0);
  g_byte_array_append (f->out_frame, buf, len);
  g_assert_cmpuint (f->out_frame->len, >=, 4);
  gsize packed = 4 + f->out_frame->data[1] + ((gsize) f->out_frame->data[2] << 8);
  gsize padded = ((packed + 63) / 64) * 64;
  g_assert_cmpuint (f->out_frame->len, <=, padded);
  if (f->out_frame->len < padded)
    return;
  g_autoptr(GBytes) frame = g_bytes_new (f->out_frame->data, padded);
  g_byte_array_set_size (f->out_frame, 0);
  g_ptr_array_add (f->sent_frames, g_bytes_ref (frame));
  peer_frame (g_bytes_get_data (frame, NULL), padded, f);
}

static void
pump (Fixture *f)
{
  guint steps = 0;
  while (fake_usb_step (&f->usb))
    g_assert_cmpuint (++steps, <, 2000);
}

static void
setup (Fixture *f, gconstpointer data)
{
  gint fd;
  GError *error = NULL;

  (void) data;
  for (guint i = 0; i < sizeof (f->key); i++)
    f->key[i] = i;
  fd = g_file_open_tmp ("goodix5120-synthetic-XXXXXX", &f->key_path, &error);
  g_assert_no_error (error);
  g_assert_cmpint (close (fd), ==, 0);
  g_assert_true (g_file_set_contents (f->key_path, (char *) f->key, sizeof (f->key), &error));
  g_assert_no_error (error);
  g_setenv (G5120_PSK_ENV, f->key_path, TRUE);
  fake_matcher_reset ();
  f->dev = g_object_new (fpi_device_goodix5120_get_type (), NULL);
  f->out_frame = g_byte_array_new ();
  f->sent_frames = g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);
  fake_attach (&f->usb, FP_DEVICE (f->dev));
  f->usb.write_hook = peer_write;
  f->usb.hook_data = f;
}

static void
teardown (Fixture *f, gconstpointer data)
{
  (void) data;
  g_assert_null (f->usb.pending);
  g_assert_cmpuint (f->usb.machines, ==, 0);
  g_assert_cmpint (f->usb.action, ==, FPI_DEVICE_ACTION_NONE);
  if (f->usb.claimed)
    fake_close (&f->usb);
  g_object_unref (f->dev);
  fake_matcher_reset ();
  fake_clear (&f->usb);
  g_byte_array_unref (f->out_frame);
  g_ptr_array_unref (f->sent_frames);
  SSL_free (f->client);
  SSL_CTX_free (f->ctx);
  g_assert_cmpint (g_unlink (f->key_path), ==, 0);
  g_free (f->key_path);
  g_unsetenv (G5120_PSK_ENV);
}

static FpPrint *
new_print (void)
{
  return g_object_new (fp_print_get_type (), NULL);
}

/* The views a completed enrollment stored, through the real template parser. */
static GPtrArray *
stored_views (FpPrint *print)
{
  g_autoptr(GError) error = NULL;
  GPtrArray *views = g5120_template_parse (print->data, 192, 240, &error);
  g_assert_no_error (error);
  return views;
}

static void
test_enrollment (Fixture *f, gconstpointer data)
{
  g_autoptr(FpPrint) print = new_print ();
  g_autoptr(GPtrArray) views = NULL;

  (void) data;
  f->auto_events = TRUE;
  fake_open (&f->usb);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
  g_assert_cmpuint (f->handshakes, ==, 1);
  g_assert_cmpint (FP_DEVICE_GET_CLASS (f->dev)->nr_enroll_stages, ==, 15);
  g_assert_cmphex (FP_DEVICE_GET_CLASS (f->dev)->features, ==,
                   FP_DEVICE_FEATURE_CAPTURE | FP_DEVICE_FEATURE_IDENTIFY | FP_DEVICE_FEATURE_VERIFY |
                   FP_DEVICE_FEATURE_ALWAYS_ON);

  fake_enroll (&f->usb, print);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.completions, ==, 1);
  g_assert_true (f->usb.notify.enrolled == print);
  g_assert_cmpuint (f->usb.notify.progress, ==, 15);
  g_assert_cmpint (f->usb.notify.stage, ==, 15);
  g_assert_cmpuint (f->usb.notify.retries, ==, 0);
  /* Every stage is a full touch, the last one included: arm, image, lift. */
  g_assert_cmpuint (f->usb.notify.needed, ==, 15);
  g_assert_cmpuint (f->usb.notify.fingers_on, ==, 15);
  g_assert_cmpuint (f->usb.notify.fingers_off, ==, 15);
  g_assert_cmpuint (f->frames, ==, 15);
  g_assert_cmpuint (f->handshakes, ==, 1);
  g_assert_null (f->usb.pending);

  g_assert_cmpint (print->type, ==, FPI_PRINT_RAW);
  views = stored_views (print);
  g_assert_cmpuint (views->len, ==, 15);
  /* SIGFM saw the driver's 192 x 240 image. Literal expectations for samples
   * 0x234 0x781 0xc56 0x9ab after the per-frame stretch (bounds 0x234..0xc56),
   * carried through fake resize. */
  g_assert_cmpuint (fake_matcher.extractions, ==, 15);
  g_assert_cmpuint (fake_matcher.width, ==, 192);
  g_assert_cmpuint (fake_matcher.height, ==, 240);
  const guint8 want[] = { 0x00, 0x85, 0xff, 0xbc };
  for (guint i = 0; i < 4; i++)
    g_assert_cmphex (fake_matcher.pixels[i * 3], ==, want[i]);
}

static void
open_driver (Fixture *f)
{
  static const guint8 want[] = {
    0xa8, 0x96, 0xa8, 0xae, 0xe4, 0xa2, 0x82, 0xa6, 0xa2, 0x70, 0x98, 0x90,
    0xd0, 0xd4, 0xae,
  };
  guint command = 0;
  fake_open (&f->usb);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
  for (guint i = 0; i < f->sent_frames->len; i++)
    {
      gsize len, plen, mlen;
      const guint8 *buf = g_bytes_get_data (g_ptr_array_index (f->sent_frames, i), &len);
      const guint8 *payload, *mp;
      guint8 flags, cmd;
      g_assert_true (g5120_pack_decode (buf, len, &flags, &payload, &plen, NULL));
      if (flags == 0xb0)
        continue;
      g_assert_true (g5120_message_decode (payload, plen, &cmd, &mp, &mlen, NULL));
      g_assert_cmpuint (command, <, G_N_ELEMENTS (want));
      g_assert_cmphex (cmd, ==, want[command++]);
    }
  g_assert_cmpuint (command, ==, G_N_ELEMENTS (want));
}

static guint8
pending_command (Fixture *f)
{
  FpiUsbTransfer *t = f->usb.pending;
  if (!t || (t->endpoint & 0x80) || f->out_frame->len)
    return 0;
  /* The first packet identifies a command before its complete payload arrives. */
  g_assert_cmpuint (t->length, >=, 7);
  if (t->buffer[0] != 0xa0)
    return 0;
  return t->buffer[4];
}

/* Changing OUT to one whole padded frame must fail this transport contract.
 * The strict init peer still checks every logical command byte independently. */
static void
test_packet_writes (Fixture *f, gconstpointer data)
{
  f->check_init = TRUE;
  open_driver (f);
  for (guint i = 0; i < f->usb.writes->len; i++)
    {
      GBytes *packet = g_ptr_array_index (f->usb.writes, i);
      g_assert_cmpuint (g_bytes_get_size (packet), ==, 64);
    }
  g_assert_cmpuint (f->usb.writes->len, >, f->sent_frames->len);
  g_assert_cmpuint (f->out_frame->len, ==, 0);
}

static guint
tls_frames_sent (Fixture *f)
{
  guint n = 0;
  for (guint i = 0; i < f->sent_frames->len; i++)
    if (((const guint8 *) g_bytes_get_data (g_ptr_array_index (f->sent_frames, i), NULL))[0] == 0xb0)
      n++;
  return n;
}

static void
open_to_server_hello (Fixture *f)
{
  guint steps = 0;

  fake_open (&f->usb);
  while (tls_frames_sent (f) == 0)
    {
      g_assert_true (fake_usb_step (&f->usb));
      g_assert_cmpuint (++steps, <, 400);
    }
  g_assert_cmpuint (tls_frames_sent (f), ==, 1);
  g_assert_nonnull (f->usb.pending);
  g_assert_true (f->usb.pending->endpoint & FPI_USB_ENDPOINT_IN);
}

/* Stale input must neither shorten the gap nor restart its deadline. */
static void
test_tls_pacing_noise (Fixture *f, gconstpointer data)
{
  gint64 start;

  (void) data;
  open_to_server_hello (f);
  start = g_get_monotonic_time ();
  queue_ack (f, 0xa8, 1);
  queue_event (f, 0x32);
  fake_queue_bytes (&f->usb, NULL, 0);
  for (guint i = 0; i < 3; i++)
    {
      fake_advance_time (5000);
      g_assert_true (fake_usb_step (&f->usb));
      g_assert_cmpuint (tls_frames_sent (f), ==, 1);
      g_assert_nonnull (f->usb.pending);
      g_assert_true (f->usb.pending->endpoint & FPI_USB_ENDPOINT_IN);
    }
  g_assert_cmpuint (f->usb.timeout, ==, 45);
  g_assert_true (fake_usb_step (&f->usb)); /* remaining interval expires */
  g_assert_cmpint (g_get_monotonic_time () - start, ==, 60000);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
}

/* A partially received alert must finish before another record is submitted,
 * including when its suffix arrives after the pacing interval. */
static void
test_tls_pacing_fragmented_alert (Fixture *f, gconstpointer data)
{
  static const guint8 alert[] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 50 };
  guint split = GPOINTER_TO_UINT (data);
  guint writes;

  open_to_server_hello (f);
  writes = f->usb.writes->len;
  queue_pack (f, 0xb0, alert, split);
  g_assert_true (fake_usb_step (&f->usb));
  g_assert_nonnull (f->usb.pending);
  g_assert_true (f->usb.pending->endpoint & FPI_USB_ENDPOINT_IN);
  fake_advance_time (60000);
  fake_usb_complete (&f->usb, NULL, 0,
                     g_error_new_literal (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT, "timeout"));
  g_assert_nonnull (f->usb.pending);
  g_assert_true (f->usb.pending->endpoint & FPI_USB_ENDPOINT_IN);
  g_assert_cmpuint (f->usb.writes->len, ==, writes);
  queue_pack (f, 0xb0, alert + split, sizeof (alert) - split);
  pump (f);
  g_assert_nonnull (f->usb.notify.error);
  g_assert_nonnull (strstr (f->usb.notify.error->message, "decode_error (50)"));
  g_assert_cmpuint (tls_frames_sent (f), ==, 1);
  g_assert_cmpuint (f->usb.writes->len, ==, writes);
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
  g_assert_false (f->usb.claimed);
}

/* Pacing cannot send another record or report success after the total budget.
 * Check the first flight's interval and the settle window after the final
 * flight, where the SSL has already completed. */
static void
test_tls_pacing_budget (Fixture *f, gconstpointer data)
{
  guint target = GPOINTER_TO_UINT (data);
  guint steps = 0, writes;

  fake_open (&f->usb);
  while (tls_frames_sent (f) < target)
    {
      g_assert_true (fake_usb_step (&f->usb));
      g_assert_cmpuint (++steps, <, 400);
    }
  g_assert_true (f->usb.pending->endpoint & FPI_USB_ENDPOINT_IN);
  writes = f->usb.writes->len;
  fake_advance_time (G5120_HANDSHAKE_BUDGET * 1000);
  g_assert_true (fake_usb_step (&f->usb));
  g_assert_nonnull (f->usb.notify.error);
  g_assert_cmpuint (f->usb.writes->len, ==, writes);
  g_assert_cmpuint (tls_frames_sent (f), ==, target);
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
  g_assert_null (f->usb.pending);
  g_assert_false (f->usb.claimed);
}

/* A nearly expired handshake cannot start a fresh two-second frame budget. */
static void
test_tls_write_budget (Fixture *f, gconstpointer data)
{
  guint steps = 0, writes;
  gboolean allocation_expires = GPOINTER_TO_UINT (data);

  fake_open (&f->usb);
  while (!f->client)
    {
      g_assert_true (fake_usb_step (&f->usb));
      g_assert_cmpuint (++steps, <, 400);
    }
  fake_advance_time (f->tls_start + 4999000 - g_get_monotonic_time ());
  writes = f->usb.writes->len;
  if (allocation_expires)
    f->usb.next_transfer_delay = 1000;
  g_assert_true (fake_usb_step (&f->usb)); /* feed ClientHello */
  if (allocation_expires)
    {
      g_assert_nonnull (f->usb.notify.error);
      g_assert_cmpuint (f->usb.writes->len, ==, writes);
      g_assert_cmpuint (f->usb.notify.opens, ==, 1);
      g_assert_null (f->usb.pending);
      g_assert_false (f->usb.claimed);
      return;
    }
  g_assert_nonnull (f->usb.pending);
  g_assert_false (f->usb.pending->endpoint & FPI_USB_ENDPOINT_IN);
  g_assert_cmpuint (f->usb.timeout, ==, 1);
  writes = f->usb.writes->len;
  fake_advance_time (1000);
  g_assert_true (fake_usb_step (&f->usb)); /* first packet completes at deadline */
  g_assert_nonnull (f->usb.notify.error);
  g_assert_cmpuint (f->usb.writes->len, ==, writes);
  g_assert_cmpuint (tls_frames_sent (f), ==, 0);
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
  g_assert_null (f->usb.pending);
  g_assert_false (f->usb.claimed);
}

/* Every pair of host records is separated by a minimum read interval, as the
 * vendor's logged gap suggests, and 0xd4 follows only after a settle read. Each
 * failing run had one pair of host writes within ~1 ms: ServerHello/ServerHelloDone
 * (Runs 24/25), Finished/0xd4 (26/27), ChangeCipherSpec/Finished (28-30). */
static void
test_tls_pacing (Fixture *f, gconstpointer data)
{
  guint seen = 0, steps = 0;
  gint64 finished_at = 0, ccs_at = 0;

  (void) data;
  fake_open (&f->usb);
  while (seen < 4)
    {
      g_assert_true (fake_usb_step (&f->usb));
      g_assert_cmpuint (++steps, <, 400);
      if (tls_frames_sent (f) == seen)
        continue;
      g_assert_cmpuint (tls_frames_sent (f), ==, seen + 1);
      g_assert_nonnull (f->usb.pending);
      switch (seen)
        {
        case 0: /* ServerHello: pace before ServerHelloDone */
          g_assert_true (f->usb.pending->endpoint & FPI_USB_ENDPOINT_IN);
          g_assert_cmpuint (f->usb.timeout, ==, G5120_TIMEOUT_HS_PACE);
          break;
        case 1: /* ServerHelloDone: wait for the EC's flight */
          g_assert_true (f->usb.pending->endpoint & FPI_USB_ENDPOINT_IN);
          g_assert_cmpuint (f->usb.timeout, ==, G5120_TIMEOUT_HS_READ);
          break;
        case 2: /* ChangeCipherSpec: pace before Finished */
          g_assert_true (f->usb.pending->endpoint & FPI_USB_ENDPOINT_IN);
          g_assert_cmpuint (f->usb.timeout, ==, G5120_TIMEOUT_HS_PACE);
          ccs_at = g_get_monotonic_time ();
          break;
        default: /* Finished: settle read, not yet 0xd4 */
          g_assert_true (f->usb.pending->endpoint & FPI_USB_ENDPOINT_IN);
          g_assert_cmpuint (f->usb.timeout, ==, G5120_TIMEOUT_HS_SETTLE);
          finished_at = g_get_monotonic_time ();
          g_assert_cmpint (finished_at - ccs_at, >=, G5120_TIMEOUT_HS_PACE * 1000);
          break;
        }
      seen++;
    }
  g_assert_true (fake_usb_step (&f->usb)); /* the settle window expires */
  g_assert_cmphex (pending_command (f), ==, 0xd4);
  g_assert_cmpint (g_get_monotonic_time () - finished_at, ==, G5120_TIMEOUT_HS_SETTLE * 1000);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
}

static guint
commands_sent (Fixture *f, guint8 cmd)
{
  guint n = 0;
  for (guint i = 0; i < f->sent_frames->len; i++)
    {
      gsize len;
      const guint8 *b = g_bytes_get_data (g_ptr_array_index (f->sent_frames, i), &len);
      if (len > 4 && b[0] == 0xa0 && b[4] == cmd)
        n++;
    }
  return n;
}

static gboolean
command_sent (Fixture *f, guint8 cmd)
{
  return commands_sent (f, cmd) > 0;
}

/* A record the EC sends after the host's Finished is read in the settle window
 * and fails open before 0xd4; here it is an encrypted close_notify. */
static void
test_tls_record_before_d4 (Fixture *f, gconstpointer data)
{
  (void) data;
  f->close_after_finished = TRUE;
  fake_open (&f->usb);
  pump (f);
  g_assert_nonnull (f->usb.notify.error);
  g_assert_nonnull (strstr (f->usb.notify.error->message, "close_notify"));
  g_assert_cmpuint (tls_frames_sent (f), ==, 4);
  g_assert_false (command_sent (f, 0xd4));
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
  g_assert_false (f->usb.claimed);
}

static void before_command (Fixture *f, guint8 cmd);

/* After the 0xd4 ACK the driver reads IN for G5120_TIMEOUT_POST_D4 before 0xae,
 * as Go's collect did after 0xd4 in Run 18. Input in that window, here a stale
 * finger-down event, neither shortens nor restarts it. */
static void
test_listen_after_d4 (Fixture *f, gconstpointer data)
{
  gint64 acked_at;
  guint ae;

  (void) data;
  fake_open (&f->usb);
  before_command (f, 0xd4);
  ae = commands_sent (f, 0xae);
  g_assert_true (fake_usb_step (&f->usb)); /* 0xd4 goes out */
  g_assert_true (fake_usb_step (&f->usb)); /* its ACK */
  acked_at = g_get_monotonic_time ();
  g_assert_nonnull (f->usb.pending);
  g_assert_true (f->usb.pending->endpoint & FPI_USB_ENDPOINT_IN);
  g_assert_cmpuint (f->usb.timeout, ==, G5120_TIMEOUT_POST_D4);
  queue_event (f, 0x32);
  fake_advance_time (1000000);
  g_assert_true (fake_usb_step (&f->usb));
  g_assert_cmpuint (commands_sent (f, 0xae), ==, ae);
  g_assert_true (f->usb.pending->endpoint & FPI_USB_ENDPOINT_IN);
  g_assert_cmpuint (f->usb.timeout, ==, G5120_TIMEOUT_POST_D4 - 1000);
  g_assert_true (fake_usb_step (&f->usb)); /* the window expires */
  g_assert_cmphex (pending_command (f), ==, 0xae);
  g_assert_cmpint (g_get_monotonic_time () - acked_at, ==, G5120_TIMEOUT_POST_D4 * 1000);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
}

/* A TLS record in the listen window cannot be dropped without desynchronising
 * the record sequence; open fails before 0xae. Here an encrypted close_notify. */
static void
test_tls_record_after_d4 (Fixture *f, gconstpointer data)
{
  guint ae;

  (void) data;
  fake_open (&f->usb);
  before_command (f, 0xd4);
  ae = commands_sent (f, 0xae);
  g_assert_true (fake_usb_step (&f->usb)); /* 0xd4 goes out; its ACK is queued */
  SSL_shutdown (f->client);
  collect_client_records (f);
  pump (f);
  g_assert_nonnull (f->usb.notify.error);
  g_assert_nonnull (strstr (f->usb.notify.error->message, "after the 0xd4 ACK"));
  g_assert_cmpuint (commands_sent (f, 0xae), ==, ae);
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
  g_assert_false (f->usb.claimed);
}

/* A synthetic alert after ServerHello alone is read before ServerHelloDone goes
 * out, and the error says how far the handshake got. */
static void
test_tls_alert_after_hello (Fixture *f, gconstpointer data)
{
  (void) data;
  f->alert_after_hello = TRUE;
  fake_open (&f->usb);
  pump (f);
  g_assert_nonnull (f->usb.notify.error);
  g_assert_nonnull (strstr (f->usb.notify.error->message, "decode_error (50)"));
  g_assert_nonnull (strstr (f->usb.notify.error->message, "from the EC and 1 to it"));
  g_assert_cmpuint (tls_frames_sent (f), ==, 1);
  g_assert_false (f->usb.claimed);
}

static void
before_command (Fixture *f, guint8 cmd)
{
  guint steps = 0;
  while (pending_command (f) != cmd)
    {
      g_assert_true (fake_usb_step (&f->usb));
      g_assert_cmpuint (++steps, <, 300);
    }
}

/* One capture action with automatic finger events: down, image, lift. */
static void
start_operation (Fixture *f)
{
  f->auto_events = TRUE;
  f->image_parts = 2; /* include the additional-image-read boundary */
  fake_capture (&f->usb, TRUE);
}

/* With auto_events off: one finger-down, the image and the lift. */
static void
touch (Fixture *f)
{
  queue_event (f, 0x32);
  pump (f);
  queue_event (f, 0x34);
  pump (f);
}

/* Enroll with the current pattern on an open device; the print is returned. */
static FpPrint *
enroll_print (Fixture *f)
{
  FpPrint *print = new_print ();
  guint completions = f->usb.notify.completions;

  f->auto_events = TRUE;
  fake_enroll (&f->usb, print);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.completions, ==, completions + 1);
  g_assert_true (f->usb.notify.enrolled == print);
  return print;
}

static void
test_reopen (Fixture *f, gconstpointer data)
{
  (void) data;
  open_driver (f);
  start_operation (f);
  pump (f);
  g_assert_cmpuint (f->usb.notify.images, ==, 1);
  fake_close (&f->usb);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.closes, ==, 1);
  g_assert_false (f->usb.claimed);
  guint writes = f->usb.writes->len;
  f->auto_events = FALSE;
  fake_open (&f->usb);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.opens, ==, 2);
  g_assert_cmpuint (f->handshakes, ==, 2);
  g_assert_cmpuint (f->usb.claims, ==, 2);
  g_assert_cmpuint (f->usb.writes->len, >, writes);
}

/* Mutation targets: writes after an open failure; lost child failure; duplicate
 * completion. Sweep every actual USB yield, rather than copying open's states. */
static void
test_open_unplug_sweep (void)
{
  Fixture baseline = { 0 };
  setup (&baseline, NULL);
  open_driver (&baseline);
  guint count = baseline.usb.completions;
  teardown (&baseline, NULL);
  g_assert_cmpuint (count, >, 40);
  for (guint fault = 0; fault < count; fault++)
    {
      Fixture f = { 0 };
      setup (&f, NULL);
      fake_open (&f.usb);
      for (guint i = 0; i < fault; i++)
        g_assert_true (fake_usb_step (&f.usb));
      guint writes = f.usb.writes->len;
      fake_usb_complete (&f.usb, NULL, 0,
                         g_error_new_literal (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_NO_DEVICE, "unplug"));
      g_assert_nonnull (f.usb.notify.error);
      g_assert_cmpuint (f.usb.notify.opens, ==, 1);
      g_assert_null (f.usb.pending);
      g_assert_cmpuint (f.usb.writes->len, ==, writes);
      g_assert_false (f.usb.claimed);
      teardown (&f, NULL);
    }
}

static void
test_operation_sweep (gconstpointer data)
{
  guint mode = GPOINTER_TO_UINT (data); /* unplug, generic I/O, or cancellation */
  Fixture baseline = { 0 };
  setup (&baseline, NULL);
  open_driver (&baseline);
  guint start = baseline.usb.completions;
  start_operation (&baseline);
  pump (&baseline);
  g_assert_cmpuint (baseline.usb.notify.images, ==, 1);
  guint count = baseline.usb.completions - start;
  teardown (&baseline, NULL);
  g_assert_cmpuint (count, ==, 10); /* arm/ACK/event, capture/ACK/2 fragments, lift/ACK/event */
  for (guint fault = 0; fault < count; fault++)
    {
      Fixture f = { 0 };
      setup (&f, NULL);
      open_driver (&f);
      start_operation (&f);
      for (guint i = 0; i < fault; i++)
        g_assert_true (fake_usb_step (&f.usb));
      guint writes = f.usb.writes->len;
      if (mode == 2)
        {
          fake_cancel (&f.usb);
          pump (&f);
          g_assert_error (f.usb.notify.error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
        }
      else
        {
          fake_usb_complete (&f.usb, NULL, 0, g_error_new_literal (G_USB_DEVICE_ERROR,
                             mode ? G_USB_DEVICE_ERROR_FAILED : G_USB_DEVICE_ERROR_NO_DEVICE, "I/O failure"));
          g_assert_nonnull (f.usb.notify.error);
          g_assert_false (g_error_matches (f.usb.notify.error, G_IO_ERROR, G_IO_ERROR_CANCELLED));
        }
      g_assert_cmpuint (f.usb.notify.completions, ==, 1);
      g_assert_cmpuint (f.usb.notify.action_errors, ==, 1);
      g_assert_cmpuint (f.usb.notify.images, ==, 0);
      g_assert_null (f.usb.pending);
      g_assert_cmpuint (f.usb.writes->len, ==, writes);
      if (mode == 2)
        {
          /* Cancellation keeps the session: the next action needs no handshake,
           * and an event the cancelled wait left behind is ignored. */
          g_clear_error (&f.usb.notify.error);
          start_operation (&f);
          pump (&f);
          g_assert_no_error (f.usb.notify.error);
          g_assert_cmpuint (f.usb.notify.images, ==, 1);
          g_assert_cmpuint (f.handshakes, ==, 1);
        }
      teardown (&f, NULL);
    }
}

/* Phases of one enroll touch, told apart by what the driver has reported. */
static guint
touch_phase (Fixture *f)
{
  if (f->usb.notify.fingers_on == 0)
    return 0;                                   /* waiting for the finger */
  return fake_matcher.extractions == 0 ? 1 : 2; /* capturing; then lifting */
}

static void
cancel_state_hook (FpDevice *dev, const char *machine, int state, gpointer data)
{
  Fixture *f = data;
  if (g_strcmp0 (machine, f->cancel_machine) || state != f->cancel_state ||
      touch_phase (f) != f->cancel_phase || f->cancel_hits)
    return;
  f->cancel_hits++;
  fake_cancel (fpi_device_get_usb_device (dev));
}

static void
test_cancel_synchronous_state (Fixture *f, gconstpointer data)
{
  /* These are the driver's CAP/FDT enum positions, not a substitute machine. */
  static const struct { guint phase; int state; } cases[] = {
    { 0, 0 }, { 0, 1 },
    { 1, 0 }, { 1, 1 }, { 1, 2 },
    { 2, 0 }, { 2, 1 },
  };
  guint index = GPOINTER_TO_UINT (data);
  g_autoptr(FpPrint) print = new_print ();
  open_driver (f);
  /* start_session passes the nr_states argument to upstream's name macro. */
  f->cancel_machine = "nr_states";
  f->cancel_state = cases[index].state;
  f->cancel_phase = cases[index].phase;
  f->usb.state_hook = cancel_state_hook;
  f->usb.hook_data = f;
  f->auto_events = TRUE;
  f->image_parts = 2;
  fake_enroll (&f->usb, print);
  pump (f);
  g_assert_cmpuint (f->cancel_hits, ==, 1);
  g_assert_cmpuint (f->usb.notify.completions, ==, 1);
  g_assert_error (f->usb.notify.error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
  g_assert_cmpuint (f->usb.notify.progress, ==, 0);
  g_assert_null (f->usb.notify.enrolled);
  g_assert_null (f->usb.pending);
  /* Cancellation keeps the session. */
  f->usb.state_hook = NULL;
  g_clear_error (&f->usb.notify.error);
  start_operation (f);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.images, ==, 1);
  g_assert_cmpuint (f->handshakes, ==, 1);
}

static void
test_open_failure (Fixture *f, gconstpointer data)
{
  guint mode = GPOINTER_TO_UINT (data);
  f->usb.kernel_bound = TRUE;
  if (mode == 0)
    g_assert_cmpint (g_unlink (f->key_path), ==, 0);
  else if (mode == 1)
    g_assert_true (g_file_set_contents (f->key_path, "short", 5, NULL));
  else if (mode == 2)
    f->usb.claim_fails = TRUE;
  else if (mode == 3)
    f->no_hello = TRUE;
  else if (mode == 9)
    f->wrong_key = TRUE;
  fake_open (&f->usb);
  if (mode >= 4 && mode <= 8)
    {
      before_command (f, 0xa8);
      g_assert_true (fake_usb_step (&f->usb)); /* sends health command */
      fake_drop_replies (&f->usb);
      if (mode == 4) /* negative ACK */
        {
          queue_ack (f, 0xa8, 0);
          /* A valid data reply must not conceal an accepted negative ACK. */
          queue_message (f, 0xa8, (guint8 *) "GF_ITE_EC_20063", 15);
        }
      else if (mode == 5) /* wrong-command ACK */
        {
          queue_ack (f, 0xa2, 1);
          queue_message (f, 0xa8, (guint8 *) "GF_ITE_EC_20063", 15);
        }
      else if (mode == 6) /* data before ACK */
        queue_message (f, 0xa8, (guint8 *) "GF_ITE_EC_20063", 15);
      else if (mode == 7)
        {
          queue_ack (f, 0xa8, 1);
          queue_message (f, 0xa8, (guint8 *) "wrong_firmware", 14);
        }
      /* mode 8: no reply, finite health timeout */
    }
  guint writes = f->usb.writes->len;
  pump (f);
  g_assert_nonnull (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
  g_assert_false (f->usb.claimed);
  g_assert_cmpuint (f->usb.releases, ==, mode < 3 ? 0 : 1);
  if (mode != 2) /* GUsb itself cannot roll back detachment on a failed claim. */
    g_assert_true (f->usb.kernel_bound);
  if (mode < 3)
    g_assert_cmpuint (f->usb.writes->len, ==, 0);
  else if (mode >= 4 && mode <= 8)
    g_assert_cmpuint (f->usb.writes->len, ==, writes);
  /* Reopen after a failed open, with a healthy synthetic EC. */
  f->usb.claim_fails = f->no_hello = FALSE;
  f->wrong_key = FALSE;
  fake_drop_replies (&f->usb);
  g_clear_error (&f->usb.notify.error);
  g_assert_true (g_file_set_contents (f->key_path, (char *) f->key, 32, NULL));
  g_assert_cmpint (g_chmod (f->key_path, 0600), ==, 0);
  fake_open (&f->usb);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.opens, ==, 2);
}

static void
test_unexpected_messages (Fixture *f, gconstpointer data)
{
  (void) data;
  fake_open (&f->usb);
  before_command (f, 0xa8);
  g_assert_true (fake_usb_step (&f->usb));
  fake_drop_replies (&f->usb);
  queue_message (f, 0x82, (guint8 *) "\x00", 1);
  queue_ack (f, 0xa2, 1);
  queue_ack (f, 0xa8, 1);
  queue_message (f, 0xa8, (guint8 *) "GF_ITE_EC_20063", 15);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  /* Stale FDT before the new arm's ACK must not deliver finger-on. */
  fake_capture (&f->usb, TRUE);
  g_assert_true (fake_usb_step (&f->usb));
  fake_drop_replies (&f->usb);
  queue_event (f, 0x32);
  queue_ack (f, 0x32, 1);
  fake_queue_bytes (&f->usb, NULL, 0);
  queue_message (f, 0x82, (guint8 *) "\x00", 1);
  pump (f);
  g_assert_cmpuint (f->usb.notify.fingers_on, ==, 0);
  g_assert_nonnull (f->usb.pending);
  queue_event (f, 0x32);
  pump (f);
  g_assert_cmpuint (f->usb.notify.fingers_on, ==, 1);
  g_assert_no_error (f->usb.notify.error);
  queue_event (f, 0x34);
  pump (f);
  g_assert_cmpuint (f->usb.notify.images, ==, 1);
  g_assert_no_error (f->usb.notify.error);
}

static void
assert_session_invalid (Fixture *f)
{
  guint writes = f->usb.writes->len;
  guint images = f->usb.notify.images;
  guint completions = f->usb.notify.completions;
  guint handshakes = f->handshakes;
  guint extractions = fake_matcher.extractions;
  g_autoptr(FpPrint) print = new_print ();

  /* Clearing the framework's error or starting another action is not recovery. */
  for (guint i = 0; i < 2; i++)
    {
      g_clear_error (&f->usb.notify.error);
      fake_capture (&f->usb, TRUE);
      g_assert_nonnull (f->usb.notify.error);
      g_assert_nonnull (strstr (f->usb.notify.error->message, "close and reopen"));
      g_assert_cmpuint (f->usb.notify.completions, ==, completions + i + 1);
      g_assert_cmpuint (f->usb.writes->len, ==, writes);
      g_assert_null (f->usb.pending);
    }

  /* A real encrypted synthetic image can arrive after the failed operation.
   * No later action may read it. */
  f->corrupt_image = FALSE;
  f->tls_fault = 0;
  f->image_parts = 1;
  queue_image (f);
  g_clear_error (&f->usb.notify.error);
  fake_enroll (&f->usb, print);
  g_assert_nonnull (strstr (f->usb.notify.error->message, "close and reopen"));
  g_assert_null (f->usb.pending);
  g_assert_cmpuint (f->usb.writes->len, ==, writes);
  g_assert_cmpuint (f->usb.machines, ==, 0);
  g_assert_cmpuint (f->usb.notify.images, ==, images);
  g_assert_cmpuint (fake_matcher.extractions, ==, extractions);
  g_assert_cmpuint (f->handshakes, ==, handshakes);
}

static void
test_kernel_restore (Fixture *f, gconstpointer data)
{
  gboolean rollback = GPOINTER_TO_UINT (data);
  f->usb.kernel_bound = TRUE;
  if (rollback)
    {
      f->no_hello = TRUE;
      fake_open (&f->usb);
      pump (f);
      g_assert_nonnull (f->usb.notify.error);
    }
  else
    {
      open_driver (f);
      g_assert_false (f->usb.kernel_bound);
      g_assert_true (f->usb.claimed);
      fake_close (&f->usb);
      g_assert_no_error (f->usb.notify.error);
    }
  g_assert_false (f->usb.claimed);
  g_assert_true (f->usb.kernel_bound);
  g_assert_cmpuint (f->usb.releases, ==, 1);
  g_assert_cmpuint (f->usb.release_flags, ==, G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER);
}

static void
test_kernel_cleanup_failure (Fixture *f, gconstpointer data)
{
  guint mode = GPOINTER_TO_UINT (data);
  gboolean rollback = mode >= 2;
  gboolean attach = mode % 2;
  f->usb.kernel_bound = TRUE;
  f->usb.release_fails = !attach;
  f->usb.attach_fails = attach;
  if (rollback)
    {
      f->no_hello = TRUE;
      fake_open (&f->usb);
      pump (f);
    }
  else
    {
      open_driver (f);
      fake_close (&f->usb);
    }
  g_assert_nonnull (f->usb.notify.error);
  g_assert_nonnull (strstr (f->usb.notify.error->message, attach ? "attach failed" : "release failed"));
  if (rollback)
    g_assert_nonnull (strstr (f->usb.notify.error->message, "handshake"));
  g_assert_false (f->usb.kernel_bound);
  g_assert_cmpint (f->usb.claimed, ==, !attach);
  g_assert_cmpuint (f->usb.releases, ==, 1);
  g_assert_cmpuint (f->usb.release_flags, ==, G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER);

  guint writes = f->usb.writes->len;
  guint claims = f->usb.claims;
  guint opens = f->usb.notify.opens;
  fake_drop_replies (&f->usb);
  g_clear_error (&f->usb.notify.error);
  f->no_hello = FALSE;
  f->usb.release_fails = f->usb.attach_fails = FALSE;
  fake_open (&f->usb);
  pump (f);
  g_assert_nonnull (f->usb.notify.error);
  g_assert_nonnull (strstr (f->usb.notify.error->message, "cleanup"));
  g_assert_cmpuint (f->usb.notify.opens, ==, opens + 1);
  g_assert_cmpuint (f->usb.claims, ==, claims);
  g_assert_cmpuint (f->usb.releases, ==, 1);
  g_assert_cmpuint (f->usb.writes->len, ==, writes);
  g_assert_null (f->usb.pending);
  g_assert_cmpuint (f->usb.machines, ==, 0);
  if (rollback)
    {
      /* This open never completed a handshake, so it cannot encrypt a late image. */
      g_clear_error (&f->usb.notify.error);
      fake_capture (&f->usb, TRUE);
      g_assert_nonnull (f->usb.notify.error);
      g_assert_null (f->usb.pending);
      g_assert_cmpuint (f->usb.writes->len, ==, writes);
      g_assert_cmpuint (f->usb.notify.images, ==, 0);
    }
  else
    assert_session_invalid (f);
}

static void
test_image_final_read (Fixture *f, gconstpointer data)
{
  gboolean corrupt = GPOINTER_TO_UINT (data);
  open_driver (f);
  f->auto_events = TRUE;
  f->image_parts = 5; /* request's first fragment plus four additional reads */
  f->corrupt_image = corrupt;
  fake_capture (&f->usb, TRUE);
  before_command (f, 0x20);
  guint completions = f->usb.completions;
  pump (f);
  g_assert_null (f->usb.pending);
  g_assert_true (g_queue_is_empty (&f->usb.replies));
  if (corrupt)
    {
      g_assert_cmpuint (f->usb.completions - completions, ==, 7); /* OUT, ACK, five fragments */
      g_assert_nonnull (f->usb.notify.error);
      g_assert_nonnull (strstr (f->usb.notify.error->message, "image:"));
      g_assert_cmpuint (f->usb.notify.action_errors, ==, 1);
      g_assert_cmpuint (f->usb.notify.images, ==, 0);
    }
  else
    {
      g_assert_cmpuint (f->usb.completions - completions, ==, 10); /* and the lift's OUT, ACK, event */
      g_assert_no_error (f->usb.notify.error);
      g_assert_cmpuint (f->usb.notify.images, ==, 1);
      g_assert_cmpuint (f->usb.notify.last_image->width, ==, 192);
      g_assert_cmpuint (f->usb.notify.last_image->height, ==, 240);
      const guint8 want[] = { 0x00, 0x85, 0xff, 0xbc }; /* stretched */
      for (guint i = 0; i < G_N_ELEMENTS (want); i++)
        g_assert_cmphex (f->usb.notify.last_image->data[i * 3], ==, want[i]);
      /* A capture action returns the image and matches nothing. */
      g_assert_cmpuint (fake_matcher.extractions, ==, 0);
    }
}

static void
test_image_failure (Fixture *f, gconstpointer data)
{
  guint mode = GPOINTER_TO_UINT (data);
  open_driver (f);
  f->auto_events = TRUE;
  f->corrupt_image = mode == 0;
  f->image_parts = mode == 2 ? 6 : 1;
  fake_capture (&f->usb, TRUE);
  if (mode == 1)
    {
      before_command (f, 0x20);
      g_assert_true (fake_usb_step (&f->usb)); /* request image */
      fake_drop_replies (&f->usb);
      queue_ack (f, 0x20, 1);
      /* incomplete record -> image timeout after the exchange */
      const guint8 fragment[] = { 0x17, 3, 3, 0x1e, 0x40, 0 };
      queue_pack (f, 0xb0, fragment, sizeof (fragment));
    }
  pump (f);
  g_assert_nonnull (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.action_errors, ==, 1);
  g_assert_cmpuint (f->usb.notify.images, ==, 0);
  if (mode == 2)
    {
      g_assert_nonnull (strstr (f->usb.notify.error->message, "no whole image after 4 transfers"));
      /* The sixth fragment must remain unread: fixing ordering cannot widen the budget. */
      g_assert_cmpuint (g_queue_get_length (&f->usb.replies), ==, 1);
      g_assert_null (f->usb.pending);
    }
  assert_session_invalid (f);
  /* Recovery is tested only across an explicit close/reopen. */
  fake_close (&f->usb);
  fake_drop_replies (&f->usb);
  g_clear_error (&f->usb.notify.error);
  f->corrupt_image = FALSE;
  f->image_parts = 1;
  fake_open (&f->usb);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  start_operation (f);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.images, ==, 1);
}

/* Mutation targets: retaining a failed TLS session, a successful next action,
 * writes from a late action, and errors hidden by cancellation. */
static void
test_failed_session (Fixture *f, gconstpointer data)
{
  guint mode = GPOINTER_TO_UINT (data);
  open_driver (f);
  f->tls_fault = mode < 2 ? mode + 1 : 0;
  f->image_parts = 2;
  fake_capture (&f->usb, TRUE);
  pump (f); /* arm, ACK, cancellable indefinite FDT read */
  if (mode != 3)
    {
      queue_event (f, 0x32);
      before_command (f, 0x20);
      if (mode != 2)
        {
          g_assert_true (fake_usb_step (&f->usb)); /* image request */
          g_assert_true (fake_usb_step (&f->usb)); /* ACK */
          g_assert_true (fake_usb_step (&f->usb)); /* first TLS fragment */
        }
    }
  if (mode >= 2)
    {
      if (mode == 5)
        fake_cancel (&f->usb); /* an unrelated I/O error still invalidates */
      fake_usb_complete (&f->usb, NULL, 0,
                         g_error_new_literal (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_FAILED,
                                              "synthetic session I/O failure"));
    }
  pump (f);
  g_assert_null (f->usb.pending);
  g_assert_cmpuint (f->usb.notify.images, ==, 0);
  g_assert_cmpuint (f->usb.notify.completions, ==, 1);
  g_assert_cmpuint (f->usb.notify.action_errors, ==, 1);
  g_assert_nonnull (f->usb.notify.error);
  /* A cancelled action reports the cancellation, not the I/O error. */
  g_assert_cmpint (g_error_matches (f->usb.notify.error, G_IO_ERROR, G_IO_ERROR_CANCELLED), ==, mode == 5);
  assert_session_invalid (f);

  /* Only a fresh successful open with a healthy fake EC restores usability. */
  fake_close (&f->usb);
  fake_drop_replies (&f->usb);
  g_clear_error (&f->usb.notify.error);
  fake_open (&f->usb);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->handshakes, ==, 2);
  f->tls_fault = 0;
  start_operation (f);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.images, ==, 1);
}

static void
test_late_image_after_failure (Fixture *f, gconstpointer data)
{
  (void) data;
  open_driver (f);
  f->auto_events = TRUE;
  fake_capture (&f->usb, TRUE);
  before_command (f, 0x20);
  fake_usb_complete (&f->usb, NULL, 0,
                     g_error_new_literal (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_FAILED,
                                          "synthetic failed request"));
  g_assert_cmpuint (f->usb.notify.action_errors, ==, 1);
  guint writes = f->usb.writes->len;
  queue_image (f);
  fake_capture (&f->usb, TRUE);
  g_assert_cmpuint (f->usb.notify.action_errors, ==, 2);
  g_assert_cmpuint (f->usb.writes->len, ==, writes);
  g_assert_null (f->usb.pending);
  g_assert_cmpuint (f->usb.notify.images, ==, 0);
}

static void
test_cancel_reactivation (Fixture *f, gconstpointer data)
{
  gboolean capture = GPOINTER_TO_UINT (data);
  open_driver (f);
  if (capture)
    {
      f->auto_events = TRUE;
      f->image_parts = 2;
      fake_capture (&f->usb, TRUE);
      before_command (f, 0x20);
      for (guint i = 0; i < 3; i++)
        g_assert_true (fake_usb_step (&f->usb));
    }
  else
    {
      fake_capture (&f->usb, TRUE);
      pump (f);
    }
  fake_cancel (&f->usb);
  pump (f);
  g_assert_error (f->usb.notify.error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
  g_assert_cmpuint (f->usb.notify.images, ==, 0);
  g_assert_cmpuint (f->usb.notify.completions, ==, 1);
  g_clear_error (&f->usb.notify.error);
  start_operation (f);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.images, ==, 1);
  g_assert_cmpuint (f->handshakes, ==, 1);
}

static void
test_base_invalid (Fixture *f, gconstpointer data)
{
  gboolean exhaust = GPOINTER_TO_UINT (data);
  guint8 base[16] = { 0x80 };
  const guint8 want[] = { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45 };
  open_driver (f);
  fake_capture (&f->usb, TRUE);
  pump (f); /* arm ACK, held cancellable finger read */
  for (guint i = 0; i < (exhaust ? 9 : 2); i++)
    {
      for (guint z = 0; z < 6; z++)
        base[4 + z * 2] = 0x80 + z * 2;
      queue_message (f, 0x32, base, sizeof (base));
      pump (f);
      if (i == 8)
        break;
      /* Check actual rearm payload, without deriving expected values in a helper. */
      GBytes *last = g_ptr_array_index (f->usb.writes, f->usb.writes->len - 1);
      const guint8 *bytes = g_bytes_get_data (last, NULL);
      for (guint z = 0; z < 6; z++)
        g_assert_cmphex (bytes[10 + z * 2], ==, want[z]);
      g_assert_cmpuint (f->usb.notify.fingers_on, ==, 0);
      g_assert_nonnull (f->usb.pending);
    }
  if (exhaust)
    {
      g_assert_nonnull (f->usb.notify.error);
      g_assert_cmpuint (f->usb.notify.action_errors, ==, 1);
      g_assert_null (f->usb.pending);
    }
  else
    {
      /* Event from a different arm is ignored, followed by valid finger-down. */
      queue_event (f, 0x34);
      queue_event (f, 0x32);
      pump (f);
      g_assert_no_error (f->usb.notify.error);
      g_assert_cmpuint (f->usb.notify.fingers_on, ==, 1);
      queue_event (f, 0x34);
      pump (f);
      g_assert_cmpuint (f->usb.notify.images, ==, 1);
    }
}

static void
test_base_invalid_retry (Fixture *f, gconstpointer data)
{
  gboolean exhausted = GPOINTER_TO_UINT (data);
  guint8 base[16] = { 0x80 };
  open_driver (f);
  fake_capture (&f->usb, TRUE);
  pump (f);
  for (guint i = 0; i < (exhausted ? 9 : 8); i++)
    {
      queue_message (f, 0x32, base, sizeof (base));
      pump (f);
    }
  if (exhausted)
    {
      g_assert_nonnull (f->usb.notify.error);
      g_assert_cmpuint (f->usb.notify.action_errors, ==, 1);
      g_assert_null (f->usb.pending);
      fake_close (&f->usb);
      g_clear_error (&f->usb.notify.error);
      fake_open (&f->usb);
      pump (f);
      g_assert_no_error (f->usb.notify.error);
    }
  else
    {
      g_assert_no_error (f->usb.notify.error);
      fake_cancel (&f->usb);
      pump (f);
      g_assert_null (f->usb.pending);
      g_assert_error (f->usb.notify.error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
      g_clear_error (&f->usb.notify.error);
    }

  fake_capture (&f->usb, TRUE);
  pump (f);
  /* A new action gets the full budget; rearming within it does not. */
  for (guint i = 0; i < 8; i++)
    {
      queue_message (f, 0x32, base, sizeof (base));
      pump (f);
      g_assert_no_error (f->usb.notify.error);
      g_assert_nonnull (f->usb.pending);
      g_assert_cmpuint (f->usb.notify.fingers_on, ==, 0);
    }
  queue_event (f, 0x32);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.fingers_on, ==, 1);
  queue_event (f, 0x34);
  pump (f);
  g_assert_cmpuint (f->usb.notify.images, ==, 1);
  g_assert_null (f->usb.pending);
  g_assert_cmpuint (f->handshakes, ==, exhausted ? 2 : 1);
}

static void
test_completion_wins_cancel (Fixture *f, gconstpointer data)
{
  (void) data;
  open_driver (f);
  fake_capture (&f->usb, TRUE);
  pump (f);
  g_assert_nonnull (f->usb.cancel);
  guint writes = f->usb.writes->len;
  fake_cancel (&f->usb);
  /* A USB success already dispatched can beat the cancellable. Complete the
   * empty read directly: the driver must still end the action exactly once. */
  fake_usb_complete (&f->usb, NULL, 0, NULL);
  g_assert_cmpuint (f->usb.notify.completions, ==, 1);
  g_assert_error (f->usb.notify.error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
  g_assert_cmpuint (f->usb.notify.fingers_on, ==, 0);
  g_assert_cmpuint (f->usb.writes->len, ==, writes);
  g_assert_null (f->usb.pending);
}

static void
test_short_write (Fixture *f, gconstpointer data)
{
  (void) data;
  fake_open (&f->usb);
  before_command (f, 0xa8);
  fake_usb_complete (&f->usb, NULL, 1, NULL);
  g_assert_nonnull (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
  g_assert_cmpuint (f->usb.writes->len, ==, 1);
  g_assert_false (f->usb.claimed);
}

static void
test_init_reply_failure (Fixture *f, gconstpointer data)
{
  guint mode = GPOINTER_TO_UINT (data);
  const guint8 reply[] = { 1, 0, 8 };
  fake_open (&f->usb);
  before_command (f, 0xa2);
  g_assert_true (fake_usb_step (&f->usb));
  fake_drop_replies (&f->usb);
  if (mode == 1)
    queue_ack (f, 0xa2, 1); /* data reply timeout */
  else if (mode == 2)
    {
      queue_ack (f, 0xa2, 0);
      queue_message (f, 0xa2, reply, sizeof (reply));
    }
  guint writes = f->usb.writes->len;
  pump (f);
  g_assert_nonnull (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
  g_assert_cmpuint (f->usb.writes->len, ==, writes);
  g_assert_false (f->usb.claimed);
}

/* Literal documented reply shapes, independent of production validation.
 * The hash and OTP bytes are synthetic; MCU fields other than TLS are opaque. */
typedef struct {
  const char *name;
  const char *section;
  guint occurrence;
  guint8 cmd;
  gsize len;
  guint8 bytes[65];
} InitReply;

/* Ordering is retained for the existing malformed-field regressions; valid
 * bytes, commands and lengths are loaded from the independent reference. */
static InitReply init_replies[] = {
  { .name = "health-firmware", .section = "health", .occurrence = 1 },
  { .name = "init-firmware", .section = "init.01", .occurrence = 2 },
  { .name = "initial-state", .section = "init.02", .occurrence = 1 },
  { .name = "psk-hash", .section = "init.03", .occurrence = 1 },
  { .name = "first-reset", .section = "init.04", .occurrence = 1 },
  { .name = "chip-id", .section = "init.05", .occurrence = 1 },
  { .name = "otp", .section = "init.06", .occurrence = 1 },
  { .name = "second-reset", .section = "init.07", .occurrence = 2 },
  { .name = "dac", .section = "init.09", .occurrence = 1 },
  { .name = "config", .section = "init.10", .occurrence = 1 },
  { .name = "final-state", .section = "init.13", .occurrence = 2 },
};

static void
test_shared_init (Fixture *f, gconstpointer data)
{
  (void) data;
  f->check_init = TRUE;
  open_driver (f);
  g_assert_cmpuint (f->corpus_position, ==, 15);
  g_assert_cmpuint (f->handshakes, ==, 1);
  g_assert_cmpuint (f->usb.replies.length, ==, 0);
  g_assert_null (f->usb.pending);
}

static void
replace_init_reply (Fixture *f, const InitReply *reply, const guint8 *bytes, gsize len)
{
  fake_open (&f->usb);
  for (guint i = 0; i < reply->occurrence; i++)
    {
      before_command (f, reply->cmd);
      g_assert_true (fake_usb_step (&f->usb));
      while (f->out_frame->len)
        g_assert_true (fake_usb_step (&f->usb));
    }
  fake_drop_replies (&f->usb);
  if (reply->cmd != 0xae)
    queue_ack (f, reply->cmd, 1);
  queue_message (f, reply->cmd, bytes, len);
}

static void
assert_init_rejected (Fixture *f, guint8 cmd)
{
  guint writes = f->usb.writes->len;
  pump (f);
  g_assert_nonnull (f->usb.notify.error);
  g_assert_cmpint (f->usb.notify.error->code, ==,
                   cmd == 0xa8 ? FP_DEVICE_ERROR_NOT_SUPPORTED : FP_DEVICE_ERROR_PROTO);
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
  g_assert_cmpuint (f->usb.writes->len, ==, writes);
  g_assert_false (f->usb.claimed);
  g_assert_null (f->usb.pending);
}

/* A failure at any packet of the four-packet config must stop the entire
 * write and complete open only once, without any following submission. */
static void
test_packet_failure (Fixture *f, gconstpointer data)
{
  guint index = GPOINTER_TO_UINT (data);
  guint packet = index / 4, mode = index % 4;
  fake_open (&f->usb);
  before_command (f, 0x90);
  for (guint i = 0; i < packet; i++)
    g_assert_true (fake_usb_step (&f->usb));
  g_assert_nonnull (f->usb.pending);
  g_assert_cmpuint (f->usb.pending->length, ==, 64);
  g_assert_cmphex (f->usb.pending->endpoint, ==, 0x01);
  guint writes = f->usb.writes->len;
  GError *error = mode == 2 ? g_error_new_literal (G_IO_ERROR, G_IO_ERROR_FAILED, "write failed") :
                  mode == 3 ? g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "write cancelled") : NULL;
  fake_usb_complete (&f->usb, NULL, mode == 0 ? 7 : 0, error);
  g_assert_nonnull (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
  g_assert_cmpuint (f->usb.writes->len, ==, writes);
  g_assert_false (f->usb.claimed);
  g_assert_null (f->usb.pending);
}

static void
test_packet_budget (Fixture *f, gconstpointer data)
{
  fake_open (&f->usb);
  before_command (f, 0x90);
  guint writes = f->usb.writes->len;
  fake_advance_time (1000 * 1000);
  g_assert_true (fake_usb_step (&f->usb));
  g_assert_nonnull (f->usb.pending);
  g_assert_cmpuint (f->usb.timeout, <=, 1000);
  fake_advance_time (1000 * 1000);
  g_assert_true (fake_usb_step (&f->usb));
  g_assert_error (f->usb.notify.error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT);
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
  g_assert_cmpuint (f->usb.writes->len, ==, writes + 1);
  g_assert_false (f->usb.claimed);
  g_assert_null (f->usb.pending);
}

/* Mutation target: accepting empty, truncated or oversized data and continuing
 * init despite a valid ACK. Each occurrence is tested, including post-TLS state. */
static void
test_init_reply_length (Fixture *f, gconstpointer data)
{
  guint index = GPOINTER_TO_UINT (data);
  const InitReply *reply = &init_replies[index / 3];
  guint mode = index % 3;
  gsize len = mode == 0 ? 0 : mode == 1 ? reply->len - 1 : reply->len + 1;
  if (mode == 2 && reply->cmd == 0xa8)
    len++; /* one trailing NUL is supported; two is an oversized reply */
  replace_init_reply (f, reply, reply->bytes, len);
  assert_init_rejected (f, reply->cmd);
}

/* Every known non-secret status/header byte must be checked; length alone
 * must not admit a different chip, failed command or malformed PSK envelope. */
typedef struct {
  guint reply;
  guint offset;
} InitField;

static const InitField init_fields[] = {
  { 0, 0 }, { 1, 0 },
  { 3, 0 }, { 3, 1 }, { 3, 2 }, { 3, 3 },
  { 3, 4 }, { 3, 5 }, { 3, 6 }, { 3, 7 }, { 3, 8 },
  { 4, 0 }, { 4, 1 }, { 4, 2 }, { 7, 0 }, { 7, 1 }, { 7, 2 },
  { 5, 0 }, { 5, 1 }, { 5, 2 }, { 5, 3 },
  { 8, 0 }, { 8, 1 }, { 9, 0 }, { 9, 1 },
  { 10, 1 },
};

static void
test_init_reply_field (Fixture *f, gconstpointer data)
{
  const InitField *field = &init_fields[GPOINTER_TO_UINT (data)];
  const InitReply *reply = &init_replies[field->reply];
  guint8 bytes[65];
  memcpy (bytes, reply->bytes, sizeof (bytes));
  if (reply->cmd == 0xae)
    bytes[field->offset] = 0x08; /* known stuck state, not immediate status 0x00 */
  else
    bytes[field->offset] ^= 1;
  replace_init_reply (f, reply, bytes, reply->len);
  assert_init_rejected (f, reply->cmd);
}

/* Run 8 records this nine-byte envelope, not an echo of the request type.
 * The remaining 32 bytes below are a synthetic hash, never device data. */
static void
test_psk_reply_run8 (Fixture *f, gconstpointer data)
{
  const guint8 bytes[41] = { 0x00, 0x03, 0x00, 0x01, 0xbb, 0x20, 0x00, 0x00, 0x00 };
  replace_init_reply (f, &init_replies[3], bytes, sizeof (bytes));
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
  g_assert_cmpuint (f->handshakes, ==, 1);
}

/* The old synthetic echo + hash + unexplained trailing byte is not a
 * documented device reply and must not become a permissive fallback. */
static void
test_psk_reply_request_echo (Fixture *f, gconstpointer data)
{
  const guint8 bytes[41] = { 0x03, 0x00, 0x02, 0xbb, 0x20, 0x00, 0x00, 0x00 };
  replace_init_reply (f, &init_replies[3], bytes, sizeof (bytes));
  assert_init_rejected (f, 0xe4);
}

static void
test_immediate_mcu_zero_status (Fixture *f, gconstpointer data)
{
  /* Owner's 2026-10-01 08:03:59 reply after authenticated TLS and the d4 ACK.
   * This is non-secret state data, not a TLS-bit-set interpretation. */
  static const guint8 reply[] = {
    0x02, 0x00, 0x31, 0x03, 0x00, 0x00, 0x01, 0x00, 0x90, 0x63,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x04,
  };

  (void) data;
  replace_init_reply (f, &init_replies[10], reply, sizeof (reply));
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
  g_assert_cmpuint (f->handshakes, ==, 1);
  g_assert_true (SSL_is_init_finished (f->client));
  g_assert_null (f->usb.pending);

  start_operation (f);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.images, ==, 1);
  g_assert_cmpuint (f->usb.notify.fingers_on, ==, 1);
  g_assert_cmpuint (f->usb.notify.fingers_off, ==, 1);
  g_assert_cmpuint (f->usb.notify.completions, ==, 1);
  g_assert_cmpuint (f->handshakes, ==, 1);
  fake_close (&f->usb);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.closes, ==, 1);
  g_assert_false (f->usb.claimed);
  g_assert_null (f->usb.pending);
}

static void
test_immediate_mcu_invalid_status (Fixture *f, gconstpointer data)
{
  guint8 reply[20];

  memcpy (reply, init_replies[10].bytes, sizeof (reply));
  reply[1] = GPOINTER_TO_UINT (data);
  replace_init_reply (f, &init_replies[10], reply, sizeof (reply));
  assert_init_rejected (f, 0xae);
}

static void
test_tls_established_negative_ack (Fixture *f, gconstpointer data)
{
  (void) data;
  fake_open (&f->usb);
  before_command (f, 0xd4);
  g_assert_true (fake_usb_step (&f->usb));
  fake_drop_replies (&f->usb);
  queue_ack (f, 0xd4, 0);
  assert_init_rejected (f, 0xd4);
}

static void
test_firmware_hidden_suffix (Fixture *f, gconstpointer data)
{
  guint index = GPOINTER_TO_UINT (data);
  const InitReply *reply = &init_replies[index % 2];
  guint8 bytes[] = "GF_ITE_EC_20063\0unexpected";
  gsize len = sizeof (bytes) - 1;
  if (index >= 2)
    {
      bytes[15] = 0x5a;
      len = 16; /* an optional terminator must be NUL, not arbitrary data */
    }
  replace_init_reply (f, reply, bytes, len);
  assert_init_rejected (f, reply->cmd);
}

/* Mutation target: freezing undocumented fields or rejecting the observed
 * NUL-terminated firmware shape. These inputs must still complete open. */
static void
test_init_reply_opaque (Fixture *f, gconstpointer data)
{
  const InitReply *reply = &init_replies[GPOINTER_TO_UINT (data)];
  guint8 bytes[65];
  gsize len = reply->len;
  memcpy (bytes, reply->bytes, sizeof (bytes));
  if (reply->cmd == 0xa8)
    len++;
  else if (reply->cmd == 0xe4)
    memset (bytes + 9, 0x5a, len - 9); /* synthetic 32-byte hash */
  else if (reply->cmd == 0xa6)
    memset (bytes, 0x5a, len);
  else
    {
      memset (bytes, 0x5a, len);
      bytes[1] = reply->occurrence == 1 ? 0xfd : 0xff;
    }
  replace_init_reply (f, reply, bytes, len);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
  g_assert_cmpuint (f->handshakes, ==, 1);
}

/* A touch SIGFM cannot use is a retry stage, not a view and not an error. */
static void
test_enroll_retry (Fixture *f, gconstpointer data)
{
  gboolean failure = GPOINTER_TO_UINT (data);
  g_autoptr(FpPrint) print = NULL;
  g_autoptr(GPtrArray) views = NULL;

  open_driver (f);
  if (failure)
    fake_matcher.fail_extract = 1;
  else
    fake_matcher.low_keypoints = 1;
  print = enroll_print (f);
  g_assert_cmpuint (f->usb.notify.progress, ==, 16);
  g_assert_cmpuint (f->usb.notify.retries, ==, 1);
  FpDeviceRetry code = failure ? FP_DEVICE_RETRY_GENERAL : FP_DEVICE_RETRY_CENTER_FINGER;
  g_assert_error (f->usb.notify.retry, FP_DEVICE_RETRY, (gint) code);
  g_assert_cmpuint (f->usb.notify.fingers_on, ==, 16);
  g_assert_cmpuint (f->usb.notify.fingers_off, ==, 16);
  views = stored_views (print);
  g_assert_cmpuint (views->len, ==, 15);
  g_assert_cmpuint (f->handshakes, ==, 1);
}

/* Cancelling between stages keeps the session and returns no print. */
static void
test_enroll_cancel (Fixture *f, gconstpointer data)
{
  g_autoptr(FpPrint) print = new_print ();

  (void) data;
  open_driver (f);
  fake_enroll (&f->usb, print);
  pump (f); /* first arm, held wait */
  for (guint i = 0; i < 3; i++)
    touch (f);
  g_assert_cmpuint (f->usb.notify.progress, ==, 3);
  g_assert_nonnull (f->usb.pending);
  fake_cancel (&f->usb);
  pump (f);
  g_assert_error (f->usb.notify.error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
  g_assert_cmpuint (f->usb.notify.completions, ==, 1);
  g_assert_null (f->usb.notify.enrolled);
  g_assert_null (print->data);
  g_assert_null (f->usb.pending);
  g_clear_error (&f->usb.notify.error);
  start_operation (f);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.images, ==, 1);
  g_assert_cmpuint (f->handshakes, ==, 1);
}

/* Verify is one touch against the stored views: the same synthetic image
 * matches, another does not, an unusable touch is a retry result. */
static void
test_verify (Fixture *f, gconstpointer data)
{
  guint mode = GPOINTER_TO_UINT (data); /* match, no match, retry */
  g_autoptr(FpPrint) print = NULL;
  guint fingers;

  open_driver (f);
  print = enroll_print (f);
  fingers = f->usb.notify.fingers_on;
  if (mode == 1)
    f->pattern = 1;
  else if (mode == 2)
    fake_matcher.low_keypoints = 1;
  fake_verify (&f->usb, print);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.completions, ==, 2);
  g_assert_true (f->usb.notify.reported);
  g_assert_cmpuint (f->usb.notify.fingers_on, ==, fingers + 1);
  g_assert_cmpuint (f->usb.notify.fingers_off, ==, fingers + 1);
  g_assert_cmpuint (f->handshakes, ==, 1);
  g_assert_null (f->usb.pending);
  if (mode == 2)
    {
      g_assert_cmpint (f->usb.notify.result, ==, FPI_MATCH_ERROR);
      g_assert_error (f->usb.notify.retry, FP_DEVICE_RETRY, FP_DEVICE_RETRY_CENTER_FINGER);
    }
  else
    g_assert_cmpint (f->usb.notify.result, ==, mode == 0 ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL);
}

/* Identify reports the gallery print that matched, or none. */
static void
test_identify (Fixture *f, gconstpointer data)
{
  guint mode = GPOINTER_TO_UINT (data); /* match the second print, no match, retry */
  g_autoptr(FpPrint) other = NULL;
  g_autoptr(FpPrint) mine = NULL;
  g_autoptr(GPtrArray) gallery = g_ptr_array_new ();

  open_driver (f);
  f->pattern = 1;
  other = enroll_print (f);
  f->pattern = 0;
  mine = enroll_print (f);
  g_ptr_array_add (gallery, other);
  g_ptr_array_add (gallery, mine);
  if (mode == 1)
    f->pattern = 2;
  else if (mode == 2)
    fake_matcher.low_keypoints = 1;
  fake_identify (&f->usb, gallery);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.completions, ==, 3);
  g_assert_true (f->usb.notify.reported);
  g_assert_true (f->usb.notify.match == (mode == 0 ? mine : NULL));
  if (mode == 2)
    g_assert_error (f->usb.notify.retry, FP_DEVICE_RETRY, FP_DEVICE_RETRY_CENTER_FINGER);
  g_assert_cmpuint (f->handshakes, ==, 1);
  g_assert_null (f->usb.pending);
}

/* Stored data that is not a template for this driver fails the action before
 * anything is sent, for verify and for any print of an identify gallery. */
static void
test_invalid_template (Fixture *f, gconstpointer data)
{
  guint mode = GPOINTER_TO_UINT (data);
  gboolean identify = mode >= 6;
  g_autoptr(FpPrint) good = NULL;
  g_autoptr(FpPrint) bad = new_print ();
  g_autoptr(GPtrArray) gallery = g_ptr_array_new ();
  g_autoptr(GPtrArray) views = NULL;
  g_autoptr(GVariant) good_data = NULL;
  guint8 version;
  guint16 w, h;

  open_driver (f);
  good = enroll_print (f);
  good_data = g_variant_ref (good->data);
  switch (identify ? mode - 6 : mode)
    {
    case 0: /* no data */
      break;
    case 1: /* another driver's data type */
      bad->data = g_variant_ref_sink (g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, "raw", 3, 1));
      break;
    case 2: /* another format version */
    case 3: /* extracted at another image size */
    case 4: /* no views */
      {
        GVariant *list;
        g_variant_get (good_data, "(yqq@a" G5120_VIEW_TYPE_STRING ")", &version, &w, &h, &list);
        if (mode % 6 == 2)
          version++;
        else if (mode % 6 == 3)
          w = 64;
        else
          {
            g_variant_unref (list);
            list = g_variant_new_array (G5120_VIEW_TYPE, NULL, 0);
          }
        bad->data = g_variant_ref_sink (g_variant_new ("(yqq@a" G5120_VIEW_TYPE_STRING ")", version, w, h, list));
        if (mode % 6 != 4)
          g_variant_unref (list);
      }
      break;
    case 5: /* one keypoint less than its descriptors */
      {
        g_autoptr(GVariant) list = NULL;
        g_autoptr(GVariant) view = NULL;
        g_autoptr(GVariant) points = NULL;
        g_autoptr(GVariant) bytes = NULL;
        GVariantBuilder short_points;
        g_variant_get (good_data, "(yqq@a" G5120_VIEW_TYPE_STRING ")", &version, &w, &h, &list);
        view = g_variant_get_child_value (list, 0);
        g_variant_get (view, "(@a(qq)@ay)", &points, &bytes);
        g_variant_builder_init (&short_points, G_VARIANT_TYPE ("a(qq)"));
        for (gsize i = 1; i < g_variant_n_children (points); i++)
          {
            g_autoptr(GVariant) point = g_variant_get_child_value (points, i);
            g_variant_builder_add_value (&short_points, point);
          }
        bad->data = g_variant_ref_sink (g_variant_new ("(yqq@a" G5120_VIEW_TYPE_STRING ")", version, w, h,
                                                       g_variant_new_array (G5120_VIEW_TYPE, (GVariant *[]) {
                                                         g_variant_new ("(a(qq)@ay)", &short_points, bytes) }, 1)));
      }
      break;
    }

  guint writes = f->usb.writes->len;
  guint completions = f->usb.notify.completions;
  if (identify)
    {
      g_ptr_array_add (gallery, good);
      g_ptr_array_add (gallery, bad);
      fake_identify (&f->usb, gallery);
    }
  else
    fake_verify (&f->usb, bad);
  g_assert_error (f->usb.notify.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_DATA_INVALID);
  if (identify)
    g_assert_nonnull (strstr (f->usb.notify.error->message, "Print 1: "));
  g_assert_cmpuint (f->usb.notify.completions, ==, completions + 1);
  g_assert_false (f->usb.notify.reported);
  g_assert_cmpuint (f->usb.writes->len, ==, writes);
  g_assert_null (f->usb.pending);
  g_assert_cmpuint (f->usb.machines, ==, 0);

  /* The session is untouched: the good print still verifies. */
  g_clear_error (&f->usb.notify.error);
  fake_verify (&f->usb, good);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpint (f->usb.notify.result, ==, FPI_MATCH_SUCCESS);
  views = stored_views (good);
  g_assert_cmpuint (views->len, ==, 15);
}

/* The image is requested only after a finger-down event. */
static void
test_capture_without_finger (Fixture *f, gconstpointer data)
{
  (void) data;
  open_driver (f);
  guint writes = f->usb.writes->len;
  fake_capture (&f->usb, FALSE);
  g_assert_error (f->usb.notify.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_NOT_SUPPORTED);
  g_assert_cmpuint (f->usb.writes->len, ==, writes);
  g_assert_null (f->usb.pending);
  g_clear_error (&f->usb.notify.error);
  start_operation (f);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.images, ==, 1);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_autoptr(GKeyFile) owned = fixture_load ();
  corpus = owned;
  for (guint i = 0; i < G_N_ELEMENTS (init_replies); i++)
    {
      InitReply *r = &init_replies[i];
      g_autoptr(GByteArray) bytes = fixture_hex (corpus, r->section, "data");
      r->cmd = fixture_cmd (corpus, r->section, "cmd");
      r->len = bytes->len;
      g_assert_cmpuint (r->len, <, sizeof (r->bytes));
      memcpy (r->bytes, bytes->data, r->len);
    }
  g_test_add ("/goodix5120/driver/shared-init", Fixture, NULL, setup, test_shared_init, teardown);
  g_test_add ("/goodix5120/driver/mcu-state/immediate-zero", Fixture, NULL, setup,
              test_immediate_mcu_zero_status, teardown);
  static const guint rejected_mcu_statuses[] = { 0x08, 0x01, 0x10, 0x11 };
  for (guint i = 0; i < G_N_ELEMENTS (rejected_mcu_statuses); i++)
    {
      g_autofree gchar *name = g_strdup_printf ("/goodix5120/driver/mcu-state/reject-%02x",
                                               rejected_mcu_statuses[i]);
      g_test_add (name, Fixture, GUINT_TO_POINTER (rejected_mcu_statuses[i]), setup,
                  test_immediate_mcu_invalid_status, teardown);
    }
  g_test_add ("/goodix5120/driver/tls-established-negative-ack", Fixture, NULL, setup,
              test_tls_established_negative_ack, teardown);
  g_test_add ("/goodix5120/driver/packet-writes", Fixture, NULL, setup,
              test_packet_writes, teardown);
  g_test_add ("/goodix5120/driver/packet-budget", Fixture, NULL, setup,
              test_packet_budget, teardown);
  const char *packet_errors[] = { "short", "zero", "io", "cancel" };
  for (guint packet = 0; packet < 4; packet++)
    for (guint mode = 0; mode < G_N_ELEMENTS (packet_errors); mode++)
      {
        g_autofree gchar *name = g_strdup_printf ("/goodix5120/driver/packet-failure/%u/%s",
                                                 packet, packet_errors[mode]);
        g_test_add (name, Fixture, GUINT_TO_POINTER (packet * 4 + mode), setup,
                    test_packet_failure, teardown);
      }
  g_test_add ("/goodix5120/driver/psk-reply/run8", Fixture, NULL, setup,
              test_psk_reply_run8, teardown);
  g_test_add ("/goodix5120/driver/psk-reply/request-echo", Fixture, NULL, setup,
              test_psk_reply_request_echo, teardown);
  g_test_add ("/goodix5120/driver/enroll/complete", Fixture, NULL, setup, test_enrollment, teardown);
  g_test_add ("/goodix5120/driver/enroll/retry-keypoints", Fixture, NULL, setup, test_enroll_retry, teardown);
  g_test_add ("/goodix5120/driver/enroll/retry-extraction", Fixture, GUINT_TO_POINTER (1), setup,
              test_enroll_retry, teardown);
  g_test_add ("/goodix5120/driver/enroll/cancel", Fixture, NULL, setup, test_enroll_cancel, teardown);
  const char *verify_names[] = { "match", "no-match", "retry" };
  for (guint i = 0; i < G_N_ELEMENTS (verify_names); i++)
    {
      g_autofree gchar *vname = g_strdup_printf ("/goodix5120/driver/verify/%s", verify_names[i]);
      g_autofree gchar *iname = g_strdup_printf ("/goodix5120/driver/identify/%s", verify_names[i]);
      g_test_add (vname, Fixture, GUINT_TO_POINTER (i), setup, test_verify, teardown);
      g_test_add (iname, Fixture, GUINT_TO_POINTER (i), setup, test_identify, teardown);
    }
  const char *template_names[] = { "no-data", "wrong-type", "version", "image-size", "no-views",
                                   "descriptor-count" };
  for (guint i = 0; i < 2 * G_N_ELEMENTS (template_names); i++)
    {
      g_autofree gchar *name = g_strdup_printf ("/goodix5120/driver/invalid-template/%s/%s",
                                               i < 6 ? "verify" : "identify", template_names[i % 6]);
      g_test_add (name, Fixture, GUINT_TO_POINTER (i), setup, test_invalid_template, teardown);
    }
  g_test_add ("/goodix5120/driver/capture-without-finger", Fixture, NULL, setup,
              test_capture_without_finger, teardown);
  g_test_add ("/goodix5120/driver/tls-pacing", Fixture, NULL, setup, test_tls_pacing, teardown);
  g_test_add ("/goodix5120/driver/tls-alert-after-hello", Fixture, NULL, setup,
              test_tls_alert_after_hello, teardown);
  g_test_add ("/goodix5120/driver/tls-pacing-noise", Fixture, NULL, setup,
              test_tls_pacing_noise, teardown);
  for (guint split = 1; split < 7; split++)
    {
      g_autofree gchar *name = g_strdup_printf ("/goodix5120/driver/tls-pacing-alert-split/%u", split);
      g_test_add (name, Fixture, GUINT_TO_POINTER (split), setup,
                  test_tls_pacing_fragmented_alert, teardown);
    }
  g_test_add ("/goodix5120/driver/tls-pacing-budget/first-flight", Fixture,
              GUINT_TO_POINTER (1), setup, test_tls_pacing_budget, teardown);
  g_test_add ("/goodix5120/driver/tls-pacing-budget/settle", Fixture,
              GUINT_TO_POINTER (4), setup, test_tls_pacing_budget, teardown);
  g_test_add ("/goodix5120/driver/tls-record-before-d4", Fixture, NULL, setup,
              test_tls_record_before_d4, teardown);
  g_test_add ("/goodix5120/driver/listen-after-d4", Fixture, NULL, setup,
              test_listen_after_d4, teardown);
  g_test_add ("/goodix5120/driver/tls-record-after-d4", Fixture, NULL, setup,
              test_tls_record_after_d4, teardown);
  g_test_add ("/goodix5120/driver/tls-write-budget", Fixture, NULL, setup,
              test_tls_write_budget, teardown);
  g_test_add ("/goodix5120/driver/tls-write-budget-before-submit", Fixture,
              GUINT_TO_POINTER (1), setup, test_tls_write_budget, teardown);
  g_test_add ("/goodix5120/driver/reopen", Fixture, NULL, setup, test_reopen, teardown);
  g_test_add_func ("/goodix5120/driver/open-unplug-sweep", test_open_unplug_sweep);
  const char *sweep_names[] = { "unplug", "io-error", "cancel" };
  for (guint i = 0; i < G_N_ELEMENTS (sweep_names); i++)
    {
      g_autofree gchar *name = g_strdup_printf ("/goodix5120/driver/%s-sweep", sweep_names[i]);
      g_test_add_data_func (name, GUINT_TO_POINTER (i), test_operation_sweep);
    }
  const char *state_names[] = { "fdt-arm", "fdt-wait", "cap-request", "cap-read", "cap-decode",
                               "lift-arm", "lift-wait" };
  for (guint i = 0; i < G_N_ELEMENTS (state_names); i++)
    {
      g_autofree gchar *name = g_strdup_printf ("/goodix5120/driver/cancel-state/%s", state_names[i]);
      g_test_add (name, Fixture, GUINT_TO_POINTER (i), setup, test_cancel_synchronous_state, teardown);
    }
  const char *open_names[] = { "missing-key", "short-key", "claim-failure", "handshake-timeout",
                               "negative-ack", "wrong-ack", "data-before-ack", "wrong-firmware", "health-timeout",
                               "wrong-key" };
  for (guint i = 0; i < G_N_ELEMENTS (open_names); i++)
    {
      g_autofree gchar *name = g_strdup_printf ("/goodix5120/driver/open/%s", open_names[i]);
      g_test_add (name, Fixture, GUINT_TO_POINTER (i), setup, test_open_failure, teardown);
    }
  g_test_add ("/goodix5120/driver/unexpected-messages", Fixture, NULL, setup, test_unexpected_messages, teardown);
  g_test_add ("/goodix5120/driver/base-invalid-rearm", Fixture, NULL, setup, test_base_invalid, teardown);
  g_test_add ("/goodix5120/driver/base-invalid-exhausted", Fixture, GUINT_TO_POINTER (1), setup,
              test_base_invalid, teardown);
  g_test_add ("/goodix5120/driver/base-invalid-retry/cancel", Fixture, NULL, setup,
              test_base_invalid_retry, teardown);
  g_test_add ("/goodix5120/driver/base-invalid-retry/reopen", Fixture, GUINT_TO_POINTER (1), setup,
              test_base_invalid_retry, teardown);
  g_test_add ("/goodix5120/driver/completion-wins-cancel", Fixture, NULL, setup,
              test_completion_wins_cancel, teardown);
  g_test_add ("/goodix5120/driver/short-write", Fixture, NULL, setup, test_short_write, teardown);
  const char *init_names[] = { "ack-timeout", "data-timeout", "negative-ack" };
  for (guint i = 0; i < G_N_ELEMENTS (init_names); i++)
    {
      g_autofree gchar *name = g_strdup_printf ("/goodix5120/driver/init/%s", init_names[i]);
      g_test_add (name, Fixture, GUINT_TO_POINTER (i), setup, test_init_reply_failure, teardown);
    }
  const char *length_names[] = { "empty", "short", "long" };
  for (guint i = 0; i < G_N_ELEMENTS (init_replies); i++)
    for (guint mode = 0; mode < 3; mode++)
      {
        g_autofree gchar *name = g_strdup_printf ("/goodix5120/driver/init-length/%s/%s",
                                                 init_replies[i].name, length_names[mode]);
        g_test_add (name, Fixture, GUINT_TO_POINTER (i * 3 + mode), setup, test_init_reply_length, teardown);
      }
  for (guint i = 0; i < G_N_ELEMENTS (init_fields); i++)
    {
      const InitField *field = &init_fields[i];
      g_autofree gchar *name = g_strdup_printf ("/goodix5120/driver/init-field/%s/%u",
                                               init_replies[field->reply].name, field->offset);
      g_test_add (name, Fixture, GUINT_TO_POINTER (i), setup, test_init_reply_field, teardown);
    }
  for (guint i = 0; i < 4; i++)
    {
      g_autofree gchar *name = g_strdup_printf ("/goodix5120/driver/firmware-hidden-suffix/%u", i);
      g_test_add (name, Fixture, GUINT_TO_POINTER (i), setup, test_firmware_hidden_suffix, teardown);
    }
  const guint opaque_replies[] = { 0, 1, 2, 3, 6, 10 };
  for (guint i = 0; i < G_N_ELEMENTS (opaque_replies); i++)
    {
      guint index = opaque_replies[i];
      g_autofree gchar *name = g_strdup_printf ("/goodix5120/driver/init-opaque/%s", init_replies[index].name);
      g_test_add (name, Fixture, GUINT_TO_POINTER (index), setup, test_init_reply_opaque, teardown);
    }
  const char *image_names[] = { "wrong-layout", "timeout", "read-budget" };
  g_test_add ("/goodix5120/driver/kernel-restore/close", Fixture, NULL, setup,
              test_kernel_restore, teardown);
  g_test_add ("/goodix5120/driver/kernel-restore/rollback", Fixture, GUINT_TO_POINTER (1), setup,
              test_kernel_restore, teardown);
  const char *cleanup_names[] = { "release-close", "attach-close", "release-rollback", "attach-rollback" };
  for (guint i = 0; i < G_N_ELEMENTS (cleanup_names); i++)
    {
      g_autofree gchar *name = g_strdup_printf ("/goodix5120/driver/kernel-cleanup-failure/%s", cleanup_names[i]);
      g_test_add (name, Fixture, GUINT_TO_POINTER (i), setup, test_kernel_cleanup_failure, teardown);
    }
  g_test_add ("/goodix5120/driver/image/final-read", Fixture, NULL, setup,
              test_image_final_read, teardown);
  g_test_add ("/goodix5120/driver/image/final-read-wrong-layout", Fixture, GUINT_TO_POINTER (1), setup,
              test_image_final_read, teardown);
  for (guint i = 0; i < G_N_ELEMENTS (image_names); i++)
    {
      g_autofree gchar *name = g_strdup_printf ("/goodix5120/driver/image/%s", image_names[i]);
      g_test_add (name, Fixture, GUINT_TO_POINTER (i), setup, test_image_failure, teardown);
    }
  const char *failure_names[] = { "tls-record", "tls-ciphertext", "write", "fdt-read",
                                  "image-read", "io-during-deactivation" };
  for (guint i = 0; i < G_N_ELEMENTS (failure_names); i++)
    {
      g_autofree gchar *name = g_strdup_printf ("/goodix5120/driver/failed-session/%s", failure_names[i]);
      g_test_add (name, Fixture, GUINT_TO_POINTER (i), setup, test_failed_session, teardown);
    }
  g_test_add ("/goodix5120/driver/late-image-after-failure", Fixture, NULL, setup,
              test_late_image_after_failure, teardown);
  g_test_add ("/goodix5120/driver/cancel-reactivation/fdt", Fixture, NULL, setup,
              test_cancel_reactivation, teardown);
  g_test_add ("/goodix5120/driver/cancel-reactivation/capture", Fixture, GUINT_TO_POINTER (1), setup,
              test_cancel_reactivation, teardown);
  return g_test_run ();
}
