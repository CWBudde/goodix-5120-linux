/*
 * Offline rehearsal of goodix5120_tls.c against an in-process OpenSSL TLS-PSK
 * *client* standing in for the EC. The C counterpart of the Go reference's
 * session.LoopbackEC: it proves the server half, the record splitting and
 * the decryption against a real TLS implementation. It proves nothing about
 * the EC's own timing or stack.
 *
 * The record lengths asserted below are the vendor driver's, from its log of
 * a completed handshake (docs/protocol.md, "The vendor's handshake, read from
 * the driver log") and from the image record in dump.pcapng.
 *
 * The PSK here is a throwaway test key, never a device key.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <string.h>
#include <glib/gstdio.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include "goodix5120_proto.h"
#include "goodix5120_tls.h"

static guint8 test_psk[G5120_PSK_LEN];

typedef struct
{
  SSL_CTX *ctx;
  SSL     *ssl;
  BIO     *rbio;
  BIO     *wbio;
  guint8   psk[G5120_PSK_LEN];
  guint8   pending[1 << 15];
  gsize    pending_len;
} FakeEC;

static unsigned int
client_psk_cb (SSL *ssl, const char *hint, char *identity, unsigned int max_identity_len,
               unsigned char *psk, unsigned int max_psk_len)
{
  FakeEC *ec = SSL_get_app_data (ssl);

  g_assert_null (hint);  /* the host must not send an identity hint */
  g_strlcpy (identity, G5120_PSK_IDENTITY, max_identity_len);
  g_assert_cmpuint (max_psk_len, >=, G5120_PSK_LEN);
  memcpy (psk, ec->psk, G5120_PSK_LEN);
  return G5120_PSK_LEN;
}

static FakeEC *
fake_ec_new (const guint8 *psk)
{
  FakeEC *ec = g_new0 (FakeEC, 1);

  memcpy (ec->psk, psk, G5120_PSK_LEN);
  ec->ctx = SSL_CTX_new (TLS_client_method ());
  g_assert_nonnull (ec->ctx);
  SSL_CTX_set_min_proto_version (ec->ctx, TLS1_2_VERSION);
  SSL_CTX_set_max_proto_version (ec->ctx, TLS1_2_VERSION);
  g_assert_true (SSL_CTX_set_cipher_list (ec->ctx, G5120_TLS_CIPHER));
  /* Like the EC: no extended master secret, no encrypt-then-MAC, no tickets. */
  SSL_CTX_set_options (ec->ctx, SSL_OP_NO_EXTENDED_MASTER_SECRET | SSL_OP_NO_ENCRYPT_THEN_MAC | SSL_OP_NO_TICKET);
  SSL_CTX_set_psk_client_callback (ec->ctx, client_psk_cb);

  ec->ssl = SSL_new (ec->ctx);
  SSL_set_app_data (ec->ssl, ec);
  ec->rbio = BIO_new (BIO_s_mem ());
  ec->wbio = BIO_new (BIO_s_mem ());
  BIO_set_mem_eof_return (ec->rbio, -1);
  SSL_set_bio (ec->ssl, ec->rbio, ec->wbio);
  SSL_set_connect_state (ec->ssl);
  return ec;
}

static void
fake_ec_free (FakeEC *ec)
{
  SSL_free (ec->ssl);
  SSL_CTX_free (ec->ctx);
  g_free (ec);
}

/* Runs the client and collects what it wrote. */
static void
fake_ec_step (FakeEC *ec)
{
  int n;

  SSL_do_handshake (ec->ssl);
  while ((n = BIO_read (ec->wbio, ec->pending + ec->pending_len,
                        sizeof (ec->pending) - ec->pending_len)) > 0)
    ec->pending_len += n;
}

/* Pops one record the fake EC wants to send — the EC sends each record as its
 * own 0xb0 pack. Returns its length, or 0. */
static gsize
fake_ec_pop (FakeEC *ec, guint8 *out)
{
  gsize n = g5120_tls_record_len (ec->pending, ec->pending_len);

  if (n == 0)
    return 0;
  memcpy (out, ec->pending, n);
  memmove (ec->pending, ec->pending + n, ec->pending_len - n);
  ec->pending_len -= n;
  return n;
}

/* Delivers one host record to the fake EC exactly as the driver would: framed
 * in a 0xb0 pack and unframed again on the far side. */
static void
deliver_to_ec (FakeEC *ec, GBytes *rec)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GByteArray) pack = NULL;
  const guint8 *payload;
  gsize payload_len, len;
  const guint8 *data = g_bytes_get_data (rec, &len);
  guint8 flags;

  pack = g5120_tls_frame (data, len, &error);
  g_assert_no_error (error);
  g_assert_true (g5120_pack_decode (pack->data, pack->len, &flags, &payload, &payload_len, &error));
  g_assert_cmphex (flags, ==, G5120_FLAG_TLS);
  g_assert_cmpint (BIO_write (ec->rbio, payload, payload_len), ==, (int) payload_len);
}

typedef struct
{
  guint flight1_types[4];
  gsize flight1_lens[4];
  guint flight1_n;
  gsize flight2_lens[4];
  guint flight2_n;
  guint ec_records;
} Transcript;

/* Drives a whole handshake the way the driver does: read one EC record,
 * feed it, advance the server, send every record it produced one pack each,
 * and go back to reading the EC. Returns FALSE with @error on a server-side
 * failure. */
static gboolean
run_handshake (G5120Tls *tls, FakeEC *ec, Transcript *t, GError **error)
{
  gboolean done = FALSE;
  guint round = 0;

  memset (t, 0, sizeof (*t));
  fake_ec_step (ec);   /* ClientHello, as the EC sends after 0xd0 */

  while (!done)
    {
      guint8 rec[4096];
      gsize n;
      GBytes *out;
      gboolean sent = FALSE;

      g_assert_cmpuint (round++, <, 20);

      n = fake_ec_pop (ec, rec);
      if (n == 0)
        {
          fake_ec_step (ec);
          n = fake_ec_pop (ec, rec);
        }
      g_assert_cmpuint (n, >, 0);
      t->ec_records++;

      if (!g5120_tls_feed (tls, rec, n, error))
        return FALSE;
      if (!g5120_tls_handshake (tls, &done, error))
        return FALSE;

      while ((out = g5120_tls_pop_record (tls)) != NULL)
        {
          gsize len = g_bytes_get_size (out);
          const guint8 *d = g_bytes_get_data (out, NULL);

          g_assert_cmphex (d[0], !=, G5120_TLS_ALERT);
          if (!done && t->flight1_n < 4)
            {
              t->flight1_types[t->flight1_n] = d[0] == G5120_TLS_HANDSHAKE ? d[5] : 0x100 | d[0];
              t->flight1_lens[t->flight1_n++] = len;
            }
          else if (done && t->flight2_n < 4)
            {
              t->flight2_lens[t->flight2_n++] = len;
            }
          deliver_to_ec (ec, out);
          g_bytes_unref (out);
          sent = TRUE;
        }

      if (sent)
        fake_ec_step (ec);
    }

  return TRUE;
}

static void
test_handshake_and_image (void)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(G5120Tls) tls = g5120_tls_new (test_psk, &error);
  FakeEC *ec = fake_ec_new (test_psk);
  Transcript t;
  guint from_ec, to_ec;
  g_autofree guint8 *frame = g_malloc (G5120_IMG_WRAPPED_LEN);
  g_autofree guint8 *plain = g_malloc (2 * G5120_IMG_WRAPPED_LEN);
  guint8 record[8192];
  gsize rlen = 0, got = 0;
  int n;

  g_assert_no_error (error);
  g_assert_true (run_handshake (tls, ec, &t, &error));
  g_assert_no_error (error);
  g_assert_cmpint (SSL_is_init_finished (ec->ssl), ==, 1);

  /* Server's first flight: ServerHello (86-byte record) then
   * ServerHelloDone (9), two packs — the vendor's "SENT DATA LEN: 86" and
   * "SENT DATA LEN: 9". No ServerKeyExchange. */
  g_assert_cmpuint (t.flight1_n, ==, 2);
  g_assert_cmphex (t.flight1_types[0], ==, 0x02);
  g_assert_cmpuint (t.flight1_lens[0], ==, 86);
  g_assert_cmphex (t.flight1_types[1], ==, 0x0e);
  g_assert_cmpuint (t.flight1_lens[1], ==, 9);
  /* Final flight: ChangeCipherSpec (6) and Finished (85), two packs. */
  g_assert_cmpuint (t.flight2_n, ==, 2);
  g_assert_cmpuint (t.flight2_lens[0], ==, 6);
  g_assert_cmpuint (t.flight2_lens[1], ==, 85);
  /* The EC side: ClientHello, then ClientKeyExchange, ChangeCipherSpec,
   * Finished as three separate records. */
  g_assert_cmpuint (t.ec_records, ==, 4);
  g5120_tls_counts (tls, &from_ec, &to_ec);
  g_assert_cmpuint (from_ec, ==, 4);
  g_assert_cmpuint (to_ec, ==, 4);

  /* An image: 7693 plaintext bytes (Run 20) must produce the 7744-byte record
   * body the vendor capture shows, inside a 7749-byte record and a 7753-byte
   * pack. */
  for (gsize i = 0; i < G5120_IMG_WRAPPED_LEN; i++)
    frame[i] = (guint8) (i * 13 + 5);
  g_assert_cmpint (SSL_write (ec->ssl, frame, G5120_IMG_WRAPPED_LEN), ==, G5120_IMG_WRAPPED_LEN);
  while ((n = BIO_read (ec->wbio, record + rlen, sizeof (record) - rlen)) > 0)
    rlen += n;
  g_assert_cmpuint (rlen, ==, 7749);
  g_assert_cmphex (record[0], ==, G5120_TLS_APPLICATION_DATA);
  g_assert_cmpuint ((record[3] << 8) | record[4], ==, 7744);
  {
    g_autoptr(GByteArray) pack = g5120_pack_encode (G5120_FLAG_TLS, record, rlen);

    g_assert_cmpuint (pack->len, ==, 7753);
  }

  /* Fed in two halves, as a short USB read might split it. */
  g_assert_true (g5120_tls_feed (tls, record, 100, &error));
  g_assert_cmpint (g5120_tls_read (tls, plain, 2 * G5120_IMG_WRAPPED_LEN, &error), ==, 0);
  g_assert_true (g5120_tls_feed (tls, record + 100, rlen - 100, &error));
  g_assert_no_error (error);
  for (;; )
    {
      gssize r = g5120_tls_read (tls, plain + got, 2 * G5120_IMG_WRAPPED_LEN - got, &error);

      g_assert_no_error (error);
      g_assert_cmpint (r, >=, 0);
      if (r == 0)
        break;
      got += r;
    }
  g_assert_cmpmem (plain, got, frame, G5120_IMG_WRAPPED_LEN);

  fake_ec_free (ec);
}

static void
test_wrong_psk_is_reported_and_no_alert_is_sent (void)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(G5120Tls) tls = g5120_tls_new (test_psk, &error);
  guint8 wrong[G5120_PSK_LEN];
  FakeEC *ec;
  Transcript t;

  for (guint i = 0; i < G5120_PSK_LEN; i++)
    wrong[i] = ~test_psk[i];
  ec = fake_ec_new (wrong);

  g_assert_false (run_handshake (tls, ec, &t, &error));
  /* The server finds the EC's Finished undecryptable or its MAC wrong. */
  g_assert_error (error, G5120_TLS_ERROR, G5120_TLS_ERROR_PSK_MISMATCH);
  g_test_message ("%s", error->message);
  /* Nothing left queued for the EC, alert included. */
  g_assert_null (g5120_tls_pop_record (tls));

  fake_ec_free (ec);
}

static void
test_alert_from_ec (void)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(G5120Tls) tls = g5120_tls_new (test_psk, &error);
  const guint8 bad_mac[] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 20 };
  const guint8 internal[] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 80 };

  g_assert_false (g5120_tls_feed (tls, bad_mac, sizeof (bad_mac), &error));
  g_assert_error (error, G5120_TLS_ERROR, G5120_TLS_ERROR_PSK_MISMATCH);
  g_clear_error (&error);
  g_assert_false (g5120_tls_feed (tls, internal, sizeof (internal), &error));
  g_assert_error (error, G5120_TLS_ERROR, G5120_TLS_ERROR_ALERT);
}

/* A ciphertext fragment can itself look like a complete cleartext alert.
 * It remains part of the application record, regardless of USB boundaries. */
static void
test_fragment_boundaries (void)
{
  guint8 rec[64] = { 0x17, 0x03, 0x03, 0x00, 59 };
  const guint8 apparent_alert[] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 20 };

  memcpy (rec + 30, apparent_alert, sizeof (apparent_alert));
  for (gsize split = 1; split < sizeof (rec); split++)
    {
      g_autoptr(GError) error = NULL;
      g_autoptr(G5120Tls) tls = g5120_tls_new (test_psk, &error);
      guint from_ec, to_ec;

      g_assert_no_error (error);
      g_assert_true (g5120_tls_feed (tls, rec, split, &error));
      g5120_tls_counts (tls, &from_ec, &to_ec);
      g_assert_cmpuint (from_ec, ==, 0);
      g_assert_true (g5120_tls_feed (tls, rec + split, sizeof (rec) - split, &error));
      g_assert_no_error (error);
      g5120_tls_counts (tls, &from_ec, &to_ec);
      g_assert_cmpuint (from_ec, ==, 1);
    }
}

static void
test_ciphertext_fragment_looks_like_alert (void)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(G5120Tls) tls = g5120_tls_new (test_psk, &error);
  guint8 rec[64] = { 0x17, 0x03, 0x03, 0x00, 59 };
  const guint8 apparent_alert[] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 20 };

  memcpy (rec + 30, apparent_alert, sizeof (apparent_alert));
  g_assert_no_error (error);
  g_assert_true (g5120_tls_feed (tls, rec, 30, &error));
  g_assert_true (g5120_tls_feed (tls, rec + 30, sizeof (rec) - 30, &error));
  g_assert_no_error (error);
}

static void
test_fragmented_alert (void)
{
  const guint8 rec[] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 20 };

  for (gsize split = 1; split < sizeof (rec); split++)
    {
      g_autoptr(GError) error = NULL;
      g_autoptr(G5120Tls) tls = g5120_tls_new (test_psk, &error);

      g_assert_no_error (error);
      g_assert_true (g5120_tls_feed (tls, rec, split, &error));
      g_assert_false (g5120_tls_feed (tls, rec + split, sizeof (rec) - split, &error));
      g_assert_error (error, G5120_TLS_ERROR, G5120_TLS_ERROR_PSK_MISMATCH);
    }
}

static void
test_handshake_failure_is_ambiguous (void)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(G5120Tls) tls = g5120_tls_new (test_psk, &error);
  const guint8 rec[] = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 40 };

  g_assert_no_error (error);
  g_assert_false (g5120_tls_feed (tls, rec, sizeof (rec), &error));
  g_assert_error (error, G5120_TLS_ERROR, G5120_TLS_ERROR_ALERT);
}

static void
test_encrypted_image_every_split (void)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(G5120Tls) tls = g5120_tls_new (test_psk, &error);
  FakeEC *ec = fake_ec_new (test_psk);
  Transcript t;
  guint8 frame[G5120_IMG_WRAPPED_LEN], plain[G5120_IMG_WRAPPED_LEN];
  guint8 rec[8192];
  guint from_ec, to_ec;

  g_assert_no_error (error);
  g_assert_true (run_handshake (tls, ec, &t, &error));
  for (gsize i = 0; i < sizeof (frame); i++)
    frame[i] = (guint8) (i * 13 + 5);

  for (gsize split = 1; split < 7749; split++)
    {
      int n;
      gsize rlen = 0;

      g_assert_cmpint (SSL_write (ec->ssl, frame, sizeof (frame)), ==, sizeof (frame));
      while ((n = BIO_read (ec->wbio, rec + rlen, sizeof (rec) - rlen)) > 0)
        rlen += n;
      g_assert_cmpuint (rlen, ==, 7749);
      g_assert_true (g5120_tls_feed (tls, rec, split, &error));
      g_assert_cmpint (g5120_tls_read (tls, plain, sizeof (plain), &error), ==, 0);
      g_assert_no_error (error);
      g_assert_true (g5120_tls_feed (tls, rec + split, rlen - split, &error));
      g_assert_cmpint (g5120_tls_read (tls, plain, sizeof (plain), &error), ==, sizeof (frame));
      g_assert_no_error (error);
      g_assert_cmpmem (plain, sizeof (plain), frame, sizeof (frame));
      g5120_tls_counts (tls, &from_ec, &to_ec);
      g_assert_cmpuint (from_ec, ==, 4 + split);
    }
  fake_ec_free (ec);
}

static void
test_concatenated_records (void)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(G5120Tls) tls = g5120_tls_new (test_psk, &error);
  FakeEC *ec = fake_ec_new (test_psk);
  Transcript t;
  const guint8 one[] = { 1, 2, 3 }, two[] = { 4, 5, 6, 7 };
  guint8 rec[1024], plain[16];
  gsize len = 0, first;
  guint from_ec, to_ec;
  int n;

  g_assert_no_error (error);
  g_assert_true (run_handshake (tls, ec, &t, &error));
  g_assert_cmpint (SSL_write (ec->ssl, one, sizeof (one)), ==, sizeof (one));
  g_assert_cmpint (SSL_write (ec->ssl, two, sizeof (two)), ==, sizeof (two));
  while ((n = BIO_read (ec->wbio, rec + len, sizeof (rec) - len)) > 0)
    len += n;
  first = g5120_tls_record_len (rec, len);
  /* A partial first header, then its tail plus a partial second header. */
  g_assert_true (g5120_tls_feed (tls, rec, 2, &error));
  g_assert_true (g5120_tls_feed (tls, rec + 2, first, &error));
  g5120_tls_counts (tls, &from_ec, &to_ec);
  g_assert_cmpuint (from_ec, ==, 5);
  g_assert_true (g5120_tls_feed (tls, rec + first + 2, len - first - 2, &error));
  g_assert_cmpint (g5120_tls_read (tls, plain, sizeof (plain), &error), ==, sizeof (one));
  g_assert_cmpmem (plain, sizeof (one), one, sizeof (one));
  g_assert_cmpint (g5120_tls_read (tls, plain, sizeof (plain), &error), ==, sizeof (two));
  g_assert_cmpmem (plain, sizeof (two), two, sizeof (two));
  g_assert_no_error (error);
  g5120_tls_counts (tls, &from_ec, &to_ec);
  g_assert_cmpuint (from_ec, ==, 6);
  fake_ec_free (ec);
}

static void
test_corrupted_encrypted_record (void)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(G5120Tls) tls = g5120_tls_new (test_psk, &error);
  FakeEC *ec = fake_ec_new (test_psk);
  Transcript t;
  guint8 rec[256], plain[16];
  const guint8 message[] = { 1, 2, 3, 4 };
  int len;

  g_assert_no_error (error);
  g_assert_true (run_handshake (tls, ec, &t, &error));
  g_assert_cmpint (SSL_write (ec->ssl, message, sizeof (message)), ==, sizeof (message));
  len = BIO_read (ec->wbio, rec, sizeof (rec));
  g_assert_cmpint (len, >, 21);
  rec[21] ^= 1;  /* corrupt ciphertext, leaving framing intact */
  g_assert_true (g5120_tls_feed (tls, rec, len, &error));
  g_assert_cmpint (g5120_tls_read (tls, plain, sizeof (plain), &error), ==, -1);
  g_assert_error (error, G5120_TLS_ERROR, G5120_TLS_ERROR_PSK_MISMATCH);
  g_assert_null (g5120_tls_pop_record (tls));
  fake_ec_free (ec);
}

static void
test_encrypted_close_notify_fragments (void)
{
  for (gsize split = 1; split < 69; split++)
    {
      g_autoptr(GError) error = NULL;
      g_autoptr(G5120Tls) tls = g5120_tls_new (test_psk, &error);
      FakeEC *ec = fake_ec_new (test_psk);
      Transcript t;
      guint8 rec[256], plain[16];
      int len;

      g_assert_no_error (error);
      g_assert_true (run_handshake (tls, ec, &t, &error));
      g_assert_cmpint (SSL_shutdown (ec->ssl), ==, 0);
      len = BIO_read (ec->wbio, rec, sizeof (rec));
      g_assert_cmpint (len, ==, 69);
      g_assert_cmphex (rec[0], ==, G5120_TLS_ALERT);
      g_assert_true (g5120_tls_feed (tls, rec, split, &error));
      g_assert_cmpint (g5120_tls_read (tls, plain, sizeof (plain), &error), ==, 0);
      g_assert_true (g5120_tls_feed (tls, rec + split, len - split, &error));
      g_assert_no_error (error);
      g_assert_cmpint (g5120_tls_read (tls, plain, sizeof (plain), &error), ==, -1);
      g_assert_error (error, G5120_TLS_ERROR, G5120_TLS_ERROR_CLOSED);
      g_assert_null (g5120_tls_pop_record (tls));
      fake_ec_free (ec);
    }
}

/* Each child starts a fresh OpenSSL library and reads this effective system
 * policy. No test or production helper mutates the process security level. */
static void
test_security_level (gconstpointer data)
{
  guint level = GPOINTER_TO_UINT (data);

  if (g_test_subprocess ())
    {
      g_autoptr(GError) error = NULL;
      g_autoptr(G5120Tls) tls = g5120_tls_new (test_psk, &error);

      if (level <= 2)
        {
          FakeEC *ec;
          Transcript t;

          g_assert_no_error (error);
          g_assert_nonnull (tls);
          ec = fake_ec_new (test_psk);
          g_assert_true (run_handshake (tls, ec, &t, &error));
          g_assert_no_error (error);
          fake_ec_free (ec);
        }
      else
        {
          g_assert_null (tls);
          g_assert_nonnull (error);
          g_assert_cmpuint (error->domain, ==, G5120_TLS_ERROR);
          g_assert_error (error, G5120_TLS_ERROR, G5120_TLS_ERROR_POLICY);
        }
      return;
    }

  {
    g_autofree gchar *dir = g_dir_make_tmp ("g5120-policy-XXXXXX", NULL);
    g_autofree gchar *path = g_build_filename (dir, "openssl.cnf", NULL);
    g_autofree gchar *config = g_strdup_printf (
      "openssl_conf = init\n[init]\nssl_conf = ssl\n[ssl]\n"
      "system_default = policy\n[policy]\nCipherString = DEFAULT:@SECLEVEL=%u\n", level);
    g_autofree gchar *old = g_strdup (g_getenv ("OPENSSL_CONF"));

    g_assert_true (g_file_set_contents (path, config, -1, NULL));
    g_setenv ("OPENSSL_CONF", path, TRUE);
    g_test_trap_subprocess (NULL, 10 * G_USEC_PER_SEC, G_TEST_SUBPROCESS_DEFAULT);
    if (old)
      g_setenv ("OPENSSL_CONF", old, TRUE);
    else
      g_unsetenv ("OPENSSL_CONF");
    g_unlink (path);
    g_rmdir (dir);
    g_test_trap_assert_passed ();
  }
}

static void
test_configured_policy_restriction (gconstpointer data)
{
  const char *restriction = data;

  if (g_test_subprocess ())
    {
      g_autoptr(GError) error = NULL;
      g_autoptr(G5120Tls) tls = g5120_tls_new (test_psk, &error);

      g_assert_null (tls);
      g_assert_error (error, G5120_TLS_ERROR, G5120_TLS_ERROR_POLICY);
      return;
    }
  {
    g_autofree gchar *dir = g_dir_make_tmp ("g5120-restrict-XXXXXX", NULL);
    g_autofree gchar *path = g_build_filename (dir, "openssl.cnf", NULL);
    g_autofree gchar *config = g_strdup_printf (
      "openssl_conf = init\n[init]\nssl_conf = ssl\n[ssl]\n"
      "system_default = policy\n[policy]\nCipherString = DEFAULT:@SECLEVEL=2\n%s\n", restriction);
    g_autofree gchar *old = g_strdup (g_getenv ("OPENSSL_CONF"));

    g_assert_true (g_file_set_contents (path, config, -1, NULL));
    g_setenv ("OPENSSL_CONF", path, TRUE);
    g_test_trap_subprocess (NULL, 10 * G_USEC_PER_SEC, G_TEST_SUBPROCESS_DEFAULT);
    if (old)
      g_setenv ("OPENSSL_CONF", old, TRUE);
    else
      g_unsetenv ("OPENSSL_CONF");
    g_unlink (path);
    g_rmdir (dir);
    g_test_trap_assert_passed ();
  }
}

static void
test_psk_file (void)
{
  g_autoptr(GError) error = NULL;
  g_autofree gchar *dir = g_dir_make_tmp ("g5120-psk-XXXXXX", NULL);
  g_autofree gchar *good = g_build_filename (dir, "psk.bin", NULL);
  g_autofree gchar *hexfile = g_build_filename (dir, "psk.hex", NULL);
  g_autofree gchar *missing = g_build_filename (dir, "absent.bin", NULL);
  guint8 psk[G5120_PSK_LEN];

  g_assert_true (g_file_set_contents (good, (const gchar *) test_psk, G5120_PSK_LEN, NULL));
  g_chmod (good, 0600);
  g_assert_true (g5120_psk_load (good, psk, &error));
  g_assert_no_error (error);
  g_assert_cmpmem (psk, sizeof (psk), test_psk, sizeof (test_psk));

  /* 64 hex characters is the classic mistake; it must not be truncated. */
  g_assert_true (g_file_set_contents (hexfile, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", 64, NULL));
  g_assert_false (g5120_psk_load (hexfile, psk, &error));
  g_assert_error (error, G5120_TLS_ERROR, G5120_TLS_ERROR_PSK_FILE);
  g_clear_error (&error);

  g_assert_false (g5120_psk_load (missing, psk, &error));
  g_assert_error (error, G5120_TLS_ERROR, G5120_TLS_ERROR_PSK_FILE);
  g_clear_error (&error);
  g_assert_false (g5120_psk_load (NULL, psk, &error));
  g_assert_error (error, G5120_TLS_ERROR, G5120_TLS_ERROR_PSK_FILE);

  g_unlink (good);
  g_unlink (hexfile);
  g_rmdir (dir);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);

  for (guint i = 0; i < G5120_PSK_LEN; i++)
    test_psk[i] = (guint8) (0x40 + i);   /* throwaway test key */

  g_test_add_func ("/goodix5120/tls/handshake-and-image", test_handshake_and_image);
  g_test_add_func ("/goodix5120/tls/wrong-psk", test_wrong_psk_is_reported_and_no_alert_is_sent);
  g_test_add_func ("/goodix5120/tls/alert-from-ec", test_alert_from_ec);
  g_test_add_func ("/goodix5120/tls/psk-file", test_psk_file);
  g_test_add_func ("/goodix5120/tls/fragment-boundaries", test_fragment_boundaries);
  g_test_add_func ("/goodix5120/tls/ciphertext-resembling-alert", test_ciphertext_fragment_looks_like_alert);
  g_test_add_func ("/goodix5120/tls/fragmented-alert", test_fragmented_alert);
  g_test_add_func ("/goodix5120/tls/ambiguous-handshake-failure", test_handshake_failure_is_ambiguous);
  g_test_add_func ("/goodix5120/tls/encrypted-image-every-split", test_encrypted_image_every_split);
  g_test_add_func ("/goodix5120/tls/concatenated-records", test_concatenated_records);
  g_test_add_func ("/goodix5120/tls/corrupted-encrypted-record", test_corrupted_encrypted_record);
  g_test_add_func ("/goodix5120/tls/encrypted-close-notify-fragments", test_encrypted_close_notify_fragments);
  g_test_add_data_func ("/goodix5120/tls/policy/minimum-tls13",
                        "MinProtocol = TLSv1.3", test_configured_policy_restriction);
  g_test_add_data_func ("/goodix5120/tls/policy/maximum-tls11",
                        "MaxProtocol = TLSv1.1", test_configured_policy_restriction);
  g_test_add_data_func ("/goodix5120/tls/policy/suite-excluded",
                        "CipherString = DEFAULT:!PSK-AES128-CBC-SHA256:@SECLEVEL=2",
                        test_configured_policy_restriction);
  for (guint level = 0; level <= 5; level++)
    {
      g_autofree gchar *name = g_strdup_printf ("/goodix5120/tls/policy/level-%u", level);
      g_test_add_data_func (name, GUINT_TO_POINTER (level), test_security_level);
    }

  return g_test_run ();
}
