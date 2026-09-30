/*
 * Goodix 27c6:5120 — TLS-PSK server over OpenSSL memory BIOs
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
 * Like the Go reference's TLS endpoint (internal/tlspsk), the server runs
 * in-process on memory BIOs. This removes the part that
 * stalled Runs 11 and 17 — waiting on a subprocess while the EC was still
 * sending — because nothing here ever waits: the driver reads the EC, feeds
 * the bytes in, and sends whatever comes out, one record per pack.
 *
 * Logging rule, as in the Go reference: record types and lengths only. Never
 * the PSK, and never an application-data body (on this device it is a
 * fingerprint image).
 */

#include <errno.h>
#include <string.h>
#include <sys/stat.h>

#include <glib/gstdio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "goodix5120_proto.h"
#include "goodix5120_tls.h"

G_DEFINE_QUARK (g5120 - tls - error - quark, g5120_tls_error)

struct _G5120Tls
{
  SSL_CTX    *ctx;
  SSL        *ssl;
  BIO        *rbio;  /* EC -> server (ciphertext in) */
  BIO        *wbio;  /* server -> EC (ciphertext out) */

  guint8      psk[G5120_PSK_LEN];

  GByteArray *out;   /* bytes the server wrote, not yet popped as records */
  guint       from_ec;
  guint       to_ec;

  guint8      input_header[G5120_TLS_RECORD_HEADER_LEN];
  gsize       input_header_len;
  gsize       input_body_len;
  gsize       input_remaining;
  guint8      input_alert[2];
  gboolean    input_encrypted;
};

/* TLS alert descriptions (RFC 5246 7.2) suggesting different keys. This is
 * an interpretation, also consistent with corrupted records. Generic
 * handshake_failure is ambiguous and must not be classified as a PSK mismatch. */
static gboolean
alert_means_key_mismatch (guint8 desc)
{
  switch (desc)
    {
    case 20:  /* bad_record_mac */
    case 51:  /* decrypt_error */
    case 115: /* unknown_psk_identity */
      return TRUE;

    default:
      return FALSE;
    }
}

static const char *
alert_name (guint8 desc)
{
  switch (desc)
    {
    case 0:
      return "close_notify";

    case 10:
      return "unexpected_message";

    case 20:
      return "bad_record_mac";

    case 40:
      return "handshake_failure";

    case 47:
      return "illegal_parameter";

    case 50:
      return "decode_error";

    case 51:
      return "decrypt_error";

    case 70:
      return "protocol_version";

    case 71:
      return "insufficient_security";

    case 80:
      return "internal_error";

    case 115:
      return "unknown_psk_identity";

    default:
      return "unnamed alert";
    }
}

/* ---- PSK ----------------------------------------------------------------- */

gboolean
g5120_psk_load (const char *path, guint8 psk[G5120_PSK_LEN], GError **error)
{
  g_autofree gchar *contents = NULL;
  gsize len = 0;
  GStatBuf st;

  if (path == NULL || *path == '\0')
    {
      g_set_error (error, G5120_TLS_ERROR, G5120_TLS_ERROR_PSK_FILE,
                   "no PSK file configured");
      return FALSE;
    }

  if (!g_file_get_contents (path, &contents, &len, NULL))
    {
      /* Say where it was looked for, not what the GIO error might echo. */
      g_set_error (error, G5120_TLS_ERROR, G5120_TLS_ERROR_PSK_FILE,
                   "cannot read the device PSK from %s", path);
      return FALSE;
    }

  if (len != G5120_PSK_LEN)
    {
      OPENSSL_cleanse (contents, len);
      g_set_error (error, G5120_TLS_ERROR, G5120_TLS_ERROR_PSK_FILE,
                   "PSK file %s is %" G_GSIZE_FORMAT " bytes, want %d "
                   "(a raw key as written by goodix-dpapi -out, not hex)",
                   path, len, G5120_PSK_LEN);
      return FALSE;
    }

  if (g_stat (path, &st) == 0 && (st.st_mode & 077) != 0)
    g_warning ("PSK file %s is readable by group or others (mode %03o); it should be 0600",
               path, (guint) (st.st_mode & 0777));

  memcpy (psk, contents, G5120_PSK_LEN);
  OPENSSL_cleanse (contents, len);
  return TRUE;
}

/* ---- Server -------------------------------------------------------------- */

static unsigned int
psk_server_cb (SSL           *ssl,
               const char    *identity,
               unsigned char *psk,
               unsigned int   max_psk_len)
{
  G5120Tls *tls = SSL_get_app_data (ssl);

  /* s_server, which completed the live handshakes (Runs 18, 20), warns on an
   * unexpected identity and carries on. So does this. */
  if (g_strcmp0 (identity, G5120_PSK_IDENTITY) != 0)
    g_warning ("TLS: the EC asked for PSK identity '%s', expected '%s'",
               identity ? identity : "(null)", G5120_PSK_IDENTITY);

  if (max_psk_len < G5120_PSK_LEN)
    return 0;

  memcpy (psk, tls->psk, G5120_PSK_LEN);
  return G5120_PSK_LEN;
}

static void
set_ssl_error (GError **error, gint code, const char *what)
{
  char buf[256] = "no OpenSSL error queued";
  unsigned long e = ERR_get_error ();

  if (e != 0)
    ERR_error_string_n (e, buf, sizeof (buf));
  ERR_clear_error ();

  g_set_error (error, G5120_TLS_ERROR, code, "%s: %s", what, buf);
}

/* Setter success does not establish that the effective policy permits this
 * suite. Exercise selection on a disposable SSL from the same configured
 * context, using the EC's extension-free ClientHello shape and synthetic
 * random bytes. This cannot emit USB traffic or consume the actual handshake. */
static gboolean
preflight_policy (G5120Tls *tls, GError **error)
{
  guint8 hello[52] = { 0x16, 0x03, 0x03, 0x00, 0x2f, 0x01, 0x00, 0x00, 0x2b,
                       0x03, 0x03 };
  SSL *probe = SSL_new (tls->ctx);
  BIO *in = NULL, *out = NULL;
  const SSL_CIPHER *cipher;
  gboolean permitted;
  int ret, ssl_error;

  if (probe == NULL)
    {
      set_ssl_error (error, G5120_TLS_ERROR_SETUP, "creating TLS policy probe");
      return FALSE;
    }
  in = BIO_new (BIO_s_mem ());
  out = BIO_new (BIO_s_mem ());
  if (in == NULL || out == NULL)
    {
      BIO_free (in);
      BIO_free (out);
      SSL_free (probe);
      set_ssl_error (error, G5120_TLS_ERROR_SETUP, "creating TLS policy probe BIOs");
      return FALSE;
    }

  hello[45] = 4;      /* cipher list: 0x00ae and renegotiation SCSV */
  hello[47] = 0xae;
  hello[49] = 0xff;
  hello[50] = 1;      /* one compression method: null */
  BIO_set_mem_eof_return (in, -1);
  SSL_set_bio (probe, in, out);
  SSL_set_app_data (probe, tls);
  SSL_set_accept_state (probe);
  if (BIO_write (in, hello, sizeof (hello)) != sizeof (hello))
    {
      SSL_free (probe);
      set_ssl_error (error, G5120_TLS_ERROR_SETUP, "feeding TLS policy probe");
      return FALSE;
    }

  ERR_clear_error ();
  ret = SSL_do_handshake (probe);
  ssl_error = SSL_get_error (probe, ret);
  cipher = SSL_get_pending_cipher (probe);
  permitted = ssl_error == SSL_ERROR_WANT_READ && cipher != NULL &&
              SSL_CIPHER_get_protocol_id (cipher) == 0x00ae &&
              SSL_version (probe) == TLS1_2_VERSION;
  if (!permitted)
    set_ssl_error (error, G5120_TLS_ERROR_POLICY,
                   "effective local TLS policy does not permit the device's "
                   G5120_TLS_CIPHER " (0x00ae)");
  SSL_free (probe);
  ERR_clear_error ();
  return permitted;
}

G5120Tls *
g5120_tls_new (const guint8 psk[G5120_PSK_LEN], GError **error)
{
  g_autoptr(G5120Tls) tls = g_new0 (G5120Tls, 1);

  memcpy (tls->psk, psk, G5120_PSK_LEN);
  tls->out = g_byte_array_new ();

  tls->ctx = SSL_CTX_new (TLS_server_method ());
  if (tls->ctx == NULL)
    {
      set_ssl_error (error, G5120_TLS_ERROR_SETUP, "SSL_CTX_new");
      return NULL;
    }

  /* Respect the original system-configured protocol and cipher restrictions
   * before narrowing them for the device. Pinning first could override a
   * configured TLS 1.3 minimum or re-enable an explicitly excluded suite. */
  SSL_CTX_set_psk_server_callback (tls->ctx, psk_server_cb);
  if (!preflight_policy (tls, error))
    return NULL;

  /* The EC offers TLS 1.2 and exactly one suite, 0x00ae (plus the
   * renegotiation SCSV), with no extensions at all. */
  if (!SSL_CTX_set_min_proto_version (tls->ctx, TLS1_2_VERSION) ||
      !SSL_CTX_set_max_proto_version (tls->ctx, TLS1_2_VERSION))
    {
      set_ssl_error (error, G5120_TLS_ERROR_SETUP, "pinning TLS 1.2");
      return NULL;
    }

  if (!SSL_CTX_set_cipher_list (tls->ctx, G5120_TLS_CIPHER))
    {
      set_ssl_error (error, G5120_TLS_ERROR_POLICY,
                     "local TLS policy does not offer " G5120_TLS_CIPHER " (0x00ae)");
      return NULL;
    }

  /* No identity hint. A hint makes an OpenSSL server send a
   * ServerKeyExchange, and the vendor's flight has none: ServerHello is
   * followed directly by ServerHelloDone. */
  if (!preflight_policy (tls, error))
    return NULL;

  tls->ssl = SSL_new (tls->ctx);
  if (tls->ssl == NULL)
    {
      set_ssl_error (error, G5120_TLS_ERROR_SETUP, "SSL_new");
      return NULL;
    }
  SSL_set_app_data (tls->ssl, tls);

  tls->rbio = BIO_new (BIO_s_mem ());
  tls->wbio = BIO_new (BIO_s_mem ());
  if (tls->rbio == NULL || tls->wbio == NULL)
    {
      g_clear_pointer (&tls->rbio, BIO_free);
      g_clear_pointer (&tls->wbio, BIO_free);
      set_ssl_error (error, G5120_TLS_ERROR_SETUP, "BIO_new");
      return NULL;
    }
  /* An empty memory BIO reports "retry", not EOF. */
  BIO_set_mem_eof_return (tls->rbio, -1);
  SSL_set_bio (tls->ssl, tls->rbio, tls->wbio);  /* ssl owns both now */
  SSL_set_accept_state (tls->ssl);

  return g_steal_pointer (&tls);
}

void
g5120_tls_free (G5120Tls *tls)
{
  if (tls == NULL)
    return;

  g_clear_pointer (&tls->ssl, SSL_free);  /* frees the BIOs */
  g_clear_pointer (&tls->ctx, SSL_CTX_free);
  OPENSSL_cleanse (tls->psk, sizeof (tls->psk));
  if (tls->out)
    {
      OPENSSL_cleanse (tls->out->data, tls->out->len);
      g_byte_array_unref (tls->out);
    }
  g_free (tls);
}

/* Moves whatever the server wrote into tls->out. */
static void
collect_output (G5120Tls *tls)
{
  guint8 buf[4096];
  int n;

  while ((n = BIO_read (tls->wbio, buf, sizeof (buf))) > 0)
    g_byte_array_append (tls->out, buf, n);
}

/* Drops everything queued for the EC and reports the first alert in it, if
 * any. The Go bridge does the same: nothing gathered ahead of an alert is
 * worth sending, and the alert itself is not forwarded either.
 *
 * OPEN QUESTION: whether a fatal alert would take the EC out of the stuck
 * mid-handshake state (docs/protocol.md, "Recovering the EC", item 4) is
 * untested. Until it is, the driver sends nothing it has not seen work. */
static gboolean
discard_output_find_alert (G5120Tls *tls, guint8 *level, guint8 *desc)
{
  gboolean found = FALSE;
  gsize off = 0;

  while (off < tls->out->len)
    {
      gsize rlen = g5120_tls_record_len (tls->out->data + off, tls->out->len - off);

      if (rlen == 0)
        break;
      if (!found && tls->out->data[off] == G5120_TLS_ALERT &&
          rlen == G5120_TLS_RECORD_HEADER_LEN + 2)
        {
          *level = tls->out->data[off + 5];
          *desc = tls->out->data[off + 6];
          found = TRUE;
        }
      off += rlen;
    }

  OPENSSL_cleanse (tls->out->data, tls->out->len);
  g_byte_array_set_size (tls->out, 0);
  return found;
}

gboolean
g5120_tls_feed (G5120Tls *tls, const guint8 *data, gsize len, GError **error)
{
  gsize off = 0;

  /* OpenSSL receives exactly the original stream, including partial records.
   * Inspection below stores only the header and two possible alert bytes. */
  while (off < len)
    {
      int chunk = (int) MIN (len - off, G_MAXINT);

      if (BIO_write (tls->rbio, data + off, chunk) != chunk)
        {
          set_ssl_error (error, G5120_TLS_ERROR_FAILED, "buffering EC bytes");
          return FALSE;
        }
      off += chunk;
    }

  off = 0;
  while (off < len)
    {
      if (tls->input_header_len < G5120_TLS_RECORD_HEADER_LEN)
        {
          gsize n = MIN (len - off, G5120_TLS_RECORD_HEADER_LEN - tls->input_header_len);

          memcpy (tls->input_header + tls->input_header_len, data + off, n);
          tls->input_header_len += n;
          off += n;
          if (tls->input_header_len < G5120_TLS_RECORD_HEADER_LEN)
            break;
          tls->input_body_len = (tls->input_header[3] << 8) | tls->input_header[4];
          if (tls->input_header[0] < G5120_TLS_CHANGE_CIPHER_SPEC ||
              tls->input_header[0] > G5120_TLS_APPLICATION_DATA ||
              tls->input_header[1] != 3 || tls->input_header[2] < 1 ||
              tls->input_header[2] > 3 || tls->input_body_len == 0 ||
              tls->input_body_len > G5120_TLS_MAX_BODY_LEN)
            {
              g_set_error (error, G5120_TLS_ERROR, G5120_TLS_ERROR_FAILED,
                           "the EC sent an invalid TLS record header");
              return FALSE;
            }
          tls->input_remaining = tls->input_body_len;
        }

      {
        gsize n = MIN (len - off, tls->input_remaining);
        gsize body_off = tls->input_body_len - tls->input_remaining;

        if (tls->input_header[0] == G5120_TLS_ALERT && body_off < 2)
          memcpy (tls->input_alert + body_off, data + off, MIN (n, 2 - body_off));
        off += n;
        tls->input_remaining -= n;
      }
      if (tls->input_remaining != 0)
        continue;

      tls->input_header_len = 0;
      tls->from_ec++;
      g_debug ("TLS: EC -> host: %s record, %" G_GSIZE_FORMAT " bytes",
               g5120_tls_type_name (tls->input_header[0]),
               G5120_TLS_RECORD_HEADER_LEN + tls->input_body_len);
      if (tls->input_header[0] == G5120_TLS_ALERT && !tls->input_encrypted)
        {
          if (tls->input_body_len == 2)
            {
              guint8 desc = tls->input_alert[1];

              g_set_error (error, G5120_TLS_ERROR,
                           alert_means_key_mismatch (desc) ?
                           G5120_TLS_ERROR_PSK_MISMATCH : G5120_TLS_ERROR_ALERT,
                           "the EC sent a %s alert: %s (%u)%s",
                           tls->input_alert[0] == 2 ? "fatal" : "warning",
                           alert_name (desc), desc,
                           alert_means_key_mismatch (desc) ?
                           " — likely different PSKs or corrupted TLS data" : "");
            }
          else
            g_set_error (error, G5120_TLS_ERROR, G5120_TLS_ERROR_ALERT,
                         "the EC sent a malformed plaintext alert");
          return FALSE;
        }
      if (tls->input_header[0] == G5120_TLS_CHANGE_CIPHER_SPEC)
        tls->input_encrypted = TRUE;
    }
  return TRUE;
}

static void
set_failure (G5120Tls *tls, GError **error, const char *what)
{
  guint8 level = 0, desc = 0;

  if (discard_output_find_alert (tls, &level, &desc))
    {
      ERR_clear_error ();
      g_set_error (error, G5120_TLS_ERROR,
                   alert_means_key_mismatch (desc) ?
                   G5120_TLS_ERROR_PSK_MISMATCH : G5120_TLS_ERROR_FAILED,
                   "%s: the host side raised %s (%u)%s; the alert was not sent to the EC",
                   what, alert_name (desc), desc,
                   alert_means_key_mismatch (desc) ?
                   " — likely different PSKs or corrupted TLS data" : "");
      return;
    }

  /* Post-handshake alerts are encrypted, so their bytes cannot be inspected
   * above. Preserve the likely key/corruption classification from OpenSSL's
   * authenticated record/Finished checks, never generic handshake_failure.
   * Scan the queue: OpenSSL 3 can put a provider error first and a generic
   * record-layer failure last, with the useful bad-MAC reason between them. */
  {
    unsigned long e, diagnostic = 0;
    gboolean key_mismatch = FALSE;
    char buf[256] = "no OpenSSL error queued";

    while ((e = ERR_get_error ()) != 0)
      {
        if (diagnostic == 0)
          diagnostic = e;
        if (ERR_GET_LIB (e) != ERR_LIB_SSL)
          continue;
        switch (ERR_GET_REASON (e))
          {
          case SSL_R_DECRYPTION_FAILED:
          case SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC:
          case SSL_R_DIGEST_CHECK_FAILED:
          case SSL_R_SSLV3_ALERT_BAD_RECORD_MAC:
          case SSL_R_TLSV1_ALERT_DECRYPTION_FAILED:
          case SSL_R_TLSV1_ALERT_DECRYPT_ERROR:
            key_mismatch = TRUE;
            diagnostic = e;
            break;

          default:
            break;
          }
      }
    if (diagnostic != 0)
      ERR_error_string_n (diagnostic, buf, sizeof (buf));
    g_set_error (error, G5120_TLS_ERROR,
                 key_mismatch ? G5120_TLS_ERROR_PSK_MISMATCH : G5120_TLS_ERROR_FAILED,
                 "%s: %s%s", what, buf,
                 key_mismatch ? " — likely different PSKs or corrupted TLS data" : "");
  }
}

gboolean
g5120_tls_handshake (G5120Tls *tls, gboolean *done, GError **error)
{
  int ret, err;

  *done = FALSE;

  ERR_clear_error ();
  ret = SSL_do_handshake (tls->ssl);
  err = SSL_get_error (tls->ssl, ret);
  collect_output (tls);

  if (ret == 1)
    {
      *done = TRUE;
      return TRUE;
    }

  if (err == SSL_ERROR_WANT_READ)
    return TRUE;

  set_failure (tls, error, "TLS handshake failed");
  return FALSE;
}

GBytes *
g5120_tls_pop_record (G5120Tls *tls)
{
  gsize rlen;
  GBytes *rec;

  collect_output (tls);

  while ((rlen = g5120_tls_record_len (tls->out->data, tls->out->len)) != 0)
    {
      guint8 type = tls->out->data[0];

      if (type == G5120_TLS_ALERT)
        {
          /* Never reached in practice: failures discard their output first.
           * Belt and braces, so no path can put an alert on the wire. */
          g_warning ("TLS: dropping an alert record the host side generated");
          g_byte_array_remove_range (tls->out, 0, rlen);
          continue;
        }

      rec = g_bytes_new (tls->out->data, rlen);
      g_byte_array_remove_range (tls->out, 0, rlen);
      tls->to_ec++;
      g_debug ("TLS: host -> EC: %s record, %" G_GSIZE_FORMAT " bytes",
               g5120_tls_type_name (type), rlen);
      return rec;
    }

  return NULL;
}

gssize
g5120_tls_read (G5120Tls *tls, guint8 *buf, gsize len, GError **error)
{
  int ret, err;

  ERR_clear_error ();
  ret = SSL_read (tls->ssl, buf, (int) MIN (len, G_MAXINT));
  err = SSL_get_error (tls->ssl, ret);
  collect_output (tls);
  if (ret > 0)
    return ret;
  if (err == SSL_ERROR_WANT_READ)
    return 0;

  if (err == SSL_ERROR_ZERO_RETURN)
    {
      discard_output_find_alert (tls, &(guint8) { 0 }, &(guint8) { 0 });
      g_set_error (error, G5120_TLS_ERROR, G5120_TLS_ERROR_CLOSED,
                   "the EC closed the TLS session (close_notify)");
      return -1;
    }

  set_failure (tls, error, "decrypting application data failed");
  return -1;
}

void
g5120_tls_counts (G5120Tls *tls, guint *from_ec, guint *to_ec)
{
  *from_ec = tls->from_ec;
  *to_ec = tls->to_ec;
}
