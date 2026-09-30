/*
 * Exercise the actual driver through its registered image-device vfuncs.
 * Only libfprint/USB boundaries are faked; framing, TLS and image decode are real.
 * All key material and images are synthetic. This binary cannot access USB.
 */
#include <unistd.h>
#include <glib/gstdio.h>
#include <openssl/ssl.h>
#include "fake-libfprint.h"
#include "goodix5120.h"
#include "goodix5120_proto.h"
#include "goodix5120_tls.h"

typedef struct {
  FakeUsb usb;
  FpImageDevice *dev;
  gchar *key_path;
  SSL_CTX *ctx;
  SSL *client;
  guint8 key[32];
  guint frames, handshakes;
  gboolean auto_events;
  gboolean no_hello, corrupt_image;
  gboolean wrong_key;
  guint image_parts;
  const char *cancel_machine;
  gint cancel_state;
  FpiImageDeviceState cancel_phase;
  guint cancel_hits;
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
  const guint8 pattern[] = { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc };
  for (gsize i = 8; i < 7688; i += 6)
    memcpy (frame + i, pattern, 6);
  g_assert_true (SSL_is_init_finished (f->client));
  g_assert_cmpint (SSL_write (f->client, frame, f->corrupt_image ? 17 : sizeof (frame)),
                   ==, f->corrupt_image ? 17 : sizeof (frame));
  f->frames++;
  collect_client_records (f);
}

static void
peer_write (const guint8 *buf, gsize len, gpointer data)
{
  Fixture *f = data;
  const guint8 *payload, *mp;
  gsize payload_len, mp_len;
  guint8 flags, cmd;
  GError *error = NULL;
  guint8 reply[64] = { 0 };

  g_assert_cmpuint (len % 64, ==, 0);
  g_assert_true (g5120_pack_decode (buf, len, &flags, &payload, &payload_len, &error));
  g_assert_no_error (error);
  if (flags == 0xb0)
    {
      g_assert_nonnull (f->client);
      g_assert_cmpint (BIO_write (SSL_get_rbio (f->client), payload, payload_len), ==, payload_len);
      client_step (f);
      return;
    }
  g_assert_cmphex (flags, ==, 0xa0);
  g_assert_true (g5120_message_decode (payload, payload_len, &cmd, &mp, &mp_len, &error));
  g_assert_no_error (error);
  /* The fake speaks only the documented exchanges, never generic success. */
  switch (cmd)
    {
    case 0x96:
      return; /* deliberately no reply */
    case 0xa8:
      queue_ack (f, cmd, 1);
      queue_message (f, cmd, (guint8 *) "GF_ITE_EC_20063", strlen ("GF_ITE_EC_20063"));
      return;
    case 0xae:
      reply[1] = f->client && SSL_is_init_finished (f->client) ? 2 : 0;
      queue_message (f, cmd, reply, 20);
      return;
    case 0xe4:
      reply[0] = 3; reply[2] = 2; reply[3] = 0xbb; reply[4] = 0x20;
      queue_ack (f, cmd, 1);
      queue_message (f, cmd, reply, 41);
      return;
    case 0xa2:
      reply[0] = 1; reply[2] = 8;
      queue_ack (f, cmd, 1);
      queue_message (f, cmd, reply, 3);
      return;
    case 0x82:
      reply[0] = 0xa2; reply[1] = 4; reply[2] = 0x25;
      queue_ack (f, cmd, 1);
      queue_message (f, cmd, reply, 4);
      return;
    case 0xa6:
      queue_ack (f, cmd, 1);
      queue_message (f, cmd, reply, 64);
      return;
    case 0x98:
    case 0x90:
      reply[0] = reply[1] = 1;
      queue_ack (f, cmd, 1);
      queue_message (f, cmd, reply, 2);
      return;
    case 0x70:
    case 0xd4:
      queue_ack (f, cmd, 1);
      return;
    case 0xd0:
      if (!f->no_hello)
        start_client (f);
      return;
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
  f->dev = g_object_new (fpi_device_goodix5120_get_type (), NULL);
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
  if (f->usb.claimed)
    FP_IMAGE_DEVICE_GET_CLASS (f->dev)->img_close (f->dev);
  g_object_unref (f->dev);
  fake_clear (&f->usb);
  SSL_free (f->client);
  SSL_CTX_free (f->ctx);
  g_assert_cmpint (g_unlink (f->key_path), ==, 0);
  g_free (f->key_path);
  g_unsetenv (G5120_PSK_ENV);
}

static void
test_enrollment (Fixture *f, gconstpointer data)
{
  (void) data;
  f->auto_events = TRUE;
  FP_IMAGE_DEVICE_GET_CLASS (f->dev)->img_open (f->dev);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
  g_assert_cmpuint (f->handshakes, ==, 1);

  f->usb.notify.automatic = TRUE;
  f->usb.notify.target_images = 5;
  FP_IMAGE_DEVICE_GET_CLASS (f->dev)->activate (f->dev);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.activations, ==, 1);
  g_assert_cmpuint (f->usb.notify.images, ==, 5);
  g_assert_cmpuint (f->usb.notify.fingers_on, ==, 5);
  /* The final processing completion ends enrollment without waiting for lift. */
  g_assert_cmpuint (f->usb.notify.fingers_off, ==, 4);
  g_assert_cmpuint (f->usb.notify.deactivations, ==, 1);
  g_assert_cmpuint (f->handshakes, ==, 1);
  g_assert_cmpuint (f->usb.notify.last_image->width, ==, 192);
  g_assert_cmpuint (f->usb.notify.last_image->height, ==, 240);
  /* Literal 12-bit decoding expectations, carried through fake resize. */
  const guint8 want[] = { 0x23, 0x78, 0xc5, 0x9a };
  for (guint i = 0; i < 4; i++)
    g_assert_cmphex (f->usb.notify.last_image->data[i * 3], ==, want[i]);
}

static void
open_driver (Fixture *f)
{
  static const guint8 want[] = {
    0xa8, 0x96, 0xa8, 0xae, 0xe4, 0xa2, 0x82, 0xa6, 0xa2, 0x70, 0x98, 0x90,
    0xd0, 0xd4, 0xae,
  };
  guint command = 0;
  FP_IMAGE_DEVICE_GET_CLASS (f->dev)->img_open (f->dev);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.opens, ==, 1);
  for (guint i = 0; i < f->usb.writes->len; i++)
    {
      gsize len, plen, mlen;
      const guint8 *buf = g_bytes_get_data (g_ptr_array_index (f->usb.writes, i), &len);
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
  const guint8 *payload, *mp;
  gsize plen, mlen;
  guint8 flags, cmd;
  FpiUsbTransfer *t = f->usb.pending;
  if (!t || (t->endpoint & 0x80))
    return 0;
  g_assert_true (g5120_pack_decode (t->buffer, t->length, &flags, &payload, &plen, NULL));
  if (flags != 0xa0)
    return 0;
  g_assert_true (g5120_message_decode (payload, plen, &cmd, &mp, &mlen, NULL));
  return cmd;
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

static void
start_operation (Fixture *f)
{
  f->auto_events = TRUE;
  f->image_parts = 2; /* include the additional-image-read boundary */
  f->usb.notify.automatic = TRUE;
  f->usb.notify.target_images = 1;
  FP_IMAGE_DEVICE_GET_CLASS (f->dev)->activate (f->dev);
}

static void
test_processing_after_lift (Fixture *f, gconstpointer data)
{
  (void) data;
  open_driver (f);
  f->usb.notify.defer_processing = TRUE;
  start_operation (f);
  f->usb.notify.target_images = 3;
  for (guint i = 1; i <= 3; i++)
    {
      pump (f);
      g_assert_no_error (f->usb.notify.error);
      g_assert_cmpuint (f->usb.notify.images, ==, i);
      g_assert_cmpuint (f->usb.notify.fingers_off, ==, i);
      g_assert_null (f->usb.pending);
      /* Processing completion may synchronously start a new machine. */
      fake_processing_complete (&f->usb);
    }
  g_assert_cmpuint (f->usb.notify.deactivations, ==, 1);
  g_assert_cmpuint (f->handshakes, ==, 1);
}

static void
test_reopen (Fixture *f, gconstpointer data)
{
  (void) data;
  open_driver (f);
  start_operation (f);
  pump (f);
  FP_IMAGE_DEVICE_GET_CLASS (f->dev)->img_close (f->dev);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.closes, ==, 1);
  g_assert_false (f->usb.claimed);
  guint writes = f->usb.writes->len;
  f->auto_events = FALSE;
  FP_IMAGE_DEVICE_GET_CLASS (f->dev)->img_open (f->dev);
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
      FP_IMAGE_DEVICE_GET_CLASS (f.dev)->img_open (f.dev);
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
  guint mode = GPOINTER_TO_UINT (data); /* unplug, generic I/O, or deactivation */
  Fixture baseline = { 0 };
  setup (&baseline, NULL);
  open_driver (&baseline);
  guint start = baseline.usb.completions;
  baseline.usb.notify.defer_processing = TRUE;
  start_operation (&baseline);
  pump (&baseline);
  fake_processing_complete (&baseline.usb);
  guint count = baseline.usb.completions - start;
  teardown (&baseline, NULL);
  g_assert_cmpuint (count, ==, 10); /* arm/ACK/event, capture/ACK/2 fragments, lift/ACK/event */
  for (guint fault = 0; fault < count; fault++)
    {
      Fixture f = { 0 };
      setup (&f, NULL);
      open_driver (&f);
      f.usb.notify.defer_processing = TRUE;
      start_operation (&f);
      for (guint i = 0; i < fault; i++)
        g_assert_true (fake_usb_step (&f.usb));
      guint writes = f.usb.writes->len;
      guint images = f.usb.notify.images;
      if (mode == 2)
        {
          fake_deactivate (&f.usb);
          pump (&f);
          g_assert_no_error (f.usb.notify.error);
          g_assert_cmpuint (f.usb.notify.images, ==, images);
          g_assert_cmpuint (f.usb.notify.session_errors, ==, 0);
        }
      else
        {
          fake_usb_complete (&f.usb, NULL, 0, g_error_new_literal (G_USB_DEVICE_ERROR,
                             mode ? G_USB_DEVICE_ERROR_FAILED : G_USB_DEVICE_ERROR_NO_DEVICE, "I/O failure"));
          g_assert_nonnull (f.usb.notify.error);
          g_assert_cmpuint (f.usb.notify.session_errors, ==, 1);
        }
      g_assert_cmpuint (f.usb.notify.deactivations, ==, 1);
      g_assert_null (f.usb.pending);
      g_assert_cmpuint (f.usb.writes->len, ==, writes);
      teardown (&f, NULL);
    }
}

static void
cancel_state_hook (FpDevice *dev, const char *machine, int state, gpointer data)
{
  Fixture *f = data;
  if (g_strcmp0 (machine, f->cancel_machine) || state != f->cancel_state ||
      f->usb.notify.state != f->cancel_phase || f->cancel_hits)
    return;
  f->cancel_hits++;
  fake_deactivate (fpi_device_get_usb_device (dev));
}

static void
test_cancel_synchronous_state (Fixture *f, gconstpointer data)
{
  /* These are the driver's CAP/FDT enum positions, not a substitute machine. */
  static const struct { FpiImageDeviceState phase; int state; } cases[] = {
    { FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON, 0 },
    { FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON, 1 },
    { FPI_IMAGE_DEVICE_STATE_CAPTURE, 0 }, { FPI_IMAGE_DEVICE_STATE_CAPTURE, 1 },
    { FPI_IMAGE_DEVICE_STATE_CAPTURE, 2 },
    { FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_OFF, 0 },
    { FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_OFF, 1 },
  };
  guint index = GPOINTER_TO_UINT (data);
  open_driver (f);
  /* start_session passes the nr_states argument to upstream's name macro. */
  f->cancel_machine = "nr_states";
  f->cancel_state = cases[index].state;
  f->cancel_phase = cases[index].phase;
  f->usb.state_hook = cancel_state_hook;
  f->usb.notify.defer_processing = TRUE;
  start_operation (f);
  pump (f);
  g_assert_cmpuint (f->cancel_hits, ==, 1);
  g_assert_cmpuint (f->usb.notify.images, ==, index >= 5 ? 1 : 0);
  g_assert_cmpuint (f->usb.notify.deactivations, ==, 1);
  g_assert_cmpuint (f->usb.notify.session_errors, ==, 0);
  g_assert_no_error (f->usb.notify.error);
}

static void
test_open_failure (Fixture *f, gconstpointer data)
{
  guint mode = GPOINTER_TO_UINT (data);
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
  FP_IMAGE_DEVICE_GET_CLASS (f->dev)->img_open (f->dev);
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
  FP_IMAGE_DEVICE_GET_CLASS (f->dev)->img_open (f->dev);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.opens, ==, 2);
}

static void
test_unexpected_messages (Fixture *f, gconstpointer data)
{
  (void) data;
  FP_IMAGE_DEVICE_GET_CLASS (f->dev)->img_open (f->dev);
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
  fake_change_state (&f->usb, FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON);
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
}

static void
test_image_failure (Fixture *f, gconstpointer data)
{
  guint mode = GPOINTER_TO_UINT (data);
  open_driver (f);
  f->corrupt_image = mode == 0;
  f->image_parts = mode == 2 ? 6 : 1;
  fake_change_state (&f->usb, FPI_IMAGE_DEVICE_STATE_CAPTURE);
  if (mode == 1)
    {
      g_assert_true (fake_usb_step (&f->usb)); /* request image */
      fake_drop_replies (&f->usb);
      queue_ack (f, 0x20, 1);
      /* incomplete record -> image timeout after the exchange */
      const guint8 fragment[] = { 0x17, 3, 3, 0x1e, 0x40, 0 };
      queue_pack (f, 0xb0, fragment, sizeof (fragment));
    }
  pump (f);
  g_assert_nonnull (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.session_errors, ==, 1);
  g_assert_cmpuint (f->usb.notify.images, ==, 0);
  /* Recovery is tested only across an explicit close/reopen. */
  FP_IMAGE_DEVICE_GET_CLASS (f->dev)->img_close (f->dev);
  fake_drop_replies (&f->usb);
  g_clear_error (&f->usb.notify.error);
  f->corrupt_image = FALSE;
  f->image_parts = 1;
  FP_IMAGE_DEVICE_GET_CLASS (f->dev)->img_open (f->dev);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  start_operation (f);
  pump (f);
  g_assert_no_error (f->usb.notify.error);
  g_assert_cmpuint (f->usb.notify.images, ==, 1);
}

static void
test_base_invalid (Fixture *f, gconstpointer data)
{
  gboolean exhaust = GPOINTER_TO_UINT (data);
  guint8 base[16] = { 0x80 };
  const guint8 want[] = { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45 };
  open_driver (f);
  fake_change_state (&f->usb, FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON);
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
      g_assert_cmpuint (f->usb.notify.session_errors, ==, 1);
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
    }
}

static void
test_completion_wins_cancel (Fixture *f, gconstpointer data)
{
  (void) data;
  open_driver (f);
  fake_change_state (&f->usb, FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON);
  pump (f);
  g_assert_nonnull (f->usb.cancel);
  guint writes = f->usb.writes->len;
  fake_deactivate (&f->usb);
  /* A USB success already dispatched can beat the cancellable. Complete the
   * empty read directly: the driver must still finish deactivation exactly once. */
  fake_usb_complete (&f->usb, NULL, 0, NULL);
  g_assert_cmpuint (f->usb.notify.deactivations, ==, 1);
  g_assert_cmpuint (f->usb.notify.fingers_on, ==, 0);
  g_assert_cmpuint (f->usb.writes->len, ==, writes);
  g_assert_null (f->usb.pending);
}

static void
test_short_write (Fixture *f, gconstpointer data)
{
  (void) data;
  FP_IMAGE_DEVICE_GET_CLASS (f->dev)->img_open (f->dev);
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
  FP_IMAGE_DEVICE_GET_CLASS (f->dev)->img_open (f->dev);
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

static void
test_late_processing_after_cancel (Fixture *f, gconstpointer data)
{
  (void) data;
  open_driver (f);
  f->usb.notify.defer_processing = TRUE;
  start_operation (f);
  f->usb.notify.target_images = 3;
  pump (f);
  g_assert_cmpuint (f->usb.notify.fingers_off, ==, 1);
  fake_deactivate (&f->usb);
  guint writes = f->usb.writes->len;
  fake_processing_complete (&f->usb);
  g_assert_null (f->usb.pending);
  g_assert_cmpuint (f->usb.writes->len, ==, writes);
  g_assert_cmpuint (f->usb.notify.state, ==, FPI_IMAGE_DEVICE_STATE_INACTIVE);
  g_assert_cmpuint (f->usb.notify.deactivations, ==, 1);
}

/* Literal documented reply shapes, independent of production validation.
 * The hash and OTP bytes are synthetic; MCU fields other than TLS are opaque. */
typedef struct {
  const char *name;
  guint8 cmd;
  guint occurrence;
  gsize len;
  guint8 bytes[65];
} InitReply;

static const InitReply init_replies[] = {
  { "health-firmware", 0xa8, 1, 15, "GF_ITE_EC_20063" },
  { "init-firmware",   0xa8, 2, 15, "GF_ITE_EC_20063" },
  { "initial-state",   0xae, 1, 20, { 0 } },
  { "psk-hash",        0xe4, 1, 41, { 3, 0, 2, 0xbb, 0x20, 0, 0, 0 } },
  { "first-reset",     0xa2, 1,  3, { 1, 0, 8 } },
  { "chip-id",         0x82, 1,  4, { 0xa2, 4, 0x25, 0 } },
  { "otp",             0xa6, 1, 64, { 0 } },
  { "second-reset",    0xa2, 2,  3, { 1, 0, 8 } },
  { "dac",             0x98, 1,  2, { 1, 1 } },
  { "config",          0x90, 1,  2, { 1, 1 } },
  { "final-state",     0xae, 2, 20, { 0, 2 } },
};

static void
replace_init_reply (Fixture *f, const InitReply *reply, const guint8 *bytes, gsize len)
{
  FP_IMAGE_DEVICE_GET_CLASS (f->dev)->img_open (f->dev);
  for (guint i = 0; i < reply->occurrence; i++)
    {
      before_command (f, reply->cmd);
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
  { 3, 4 }, { 3, 5 }, { 3, 6 }, { 3, 7 },
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
  bytes[field->offset] ^= reply->cmd == 0xae ? 2 : 1;
  replace_init_reply (f, reply, bytes, reply->len);
  assert_init_rejected (f, reply->cmd);
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
    memset (bytes + 8, 0x5a, len - 8); /* synthetic hash + unexplained last byte */
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

static void
test_final_processing_during_lift (Fixture *f, gconstpointer data)
{
  guint boundary = GPOINTER_TO_UINT (data);
  open_driver (f);
  f->usb.notify.defer_processing = TRUE;
  start_operation (f);
  before_command (f, 0x34);
  for (guint i = 0; i < boundary; i++)
    g_assert_true (fake_usb_step (&f->usb)); /* lift write, ACK, indefinite wait */
  g_assert_cmpuint (f->usb.notify.images, ==, 1);
  g_assert_cmpuint (f->usb.notify.fingers_off, ==, 0);
  fake_processing_complete (&f->usb);
  g_assert_cmpuint (f->usb.notify.state, ==, FPI_IMAGE_DEVICE_STATE_DEACTIVATING);
  pump (f);
  g_assert_cmpuint (f->usb.notify.deactivations, ==, 1);
  g_assert_cmpuint (f->usb.notify.fingers_off, ==, 0);
  g_assert_no_error (f->usb.notify.error);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add ("/goodix5120/driver/enrollment", Fixture, NULL, setup, test_enrollment, teardown);
  g_test_add ("/goodix5120/driver/processing-after-lift", Fixture, NULL, setup,
              test_processing_after_lift, teardown);
  g_test_add ("/goodix5120/driver/reopen", Fixture, NULL, setup, test_reopen, teardown);
  g_test_add_func ("/goodix5120/driver/open-unplug-sweep", test_open_unplug_sweep);
  const char *sweep_names[] = { "unplug", "io-error", "cancel-transfer" };
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
  g_test_add ("/goodix5120/driver/completion-wins-cancel", Fixture, NULL, setup,
              test_completion_wins_cancel, teardown);
  g_test_add ("/goodix5120/driver/short-write", Fixture, NULL, setup, test_short_write, teardown);
  g_test_add ("/goodix5120/driver/late-processing-after-cancel", Fixture, NULL, setup,
              test_late_processing_after_cancel, teardown);
  for (guint i = 0; i < 3; i++)
    {
      g_autofree gchar *name = g_strdup_printf ("/goodix5120/driver/final-processing-during-lift/%u", i);
      g_test_add (name, Fixture, GUINT_TO_POINTER (i), setup, test_final_processing_during_lift, teardown);
    }
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
  for (guint i = 0; i < G_N_ELEMENTS (image_names); i++)
    {
      g_autofree gchar *name = g_strdup_printf ("/goodix5120/driver/image/%s", image_names[i]);
      g_test_add (name, Fixture, GUINT_TO_POINTER (i), setup, test_image_failure, teardown);
    }
  return g_test_run ();
}
