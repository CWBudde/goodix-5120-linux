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
 * The Go reference drives an `openssl s_server -nocert -psk <hex>` subprocess
 * (internal/tlspsk) and bridges it to the device (internal/session). Here the
 * same server runs in-process on memory BIOs, which removes the part that
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
};

/* TLS alert descriptions (RFC 5246 7.2) that mean the two ends derived
 * different keys. With a PSK suite and no certificates, that means the PSKs
 * differ. An INTERPRETATION: no alert ever says "wrong PSK". */
static gboolean
alert_means_key_mismatch (guint8 desc)
{
  switch (desc)
    {
    case 20:  /* bad_record_mac */
    case 40:  /* handshake_failure */
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
      /* Some distributions raise the default security level past legacy CBC
       * PSK suites; the Go reference has the same escape hatch
       * (tlspsk.Config.Cipher). */
      ERR_clear_error ();
      if (!SSL_CTX_set_cipher_list (tls->ctx, G5120_TLS_CIPHER ":@SECLEVEL=0"))
        {
          set_ssl_error (error, G5120_TLS_ERROR_SETUP,
                         "this OpenSSL does not offer " G5120_TLS_CIPHER " (0x00ae)");
          return NULL;
        }
      g_warning ("TLS: " G5120_TLS_CIPHER " needed @SECLEVEL=0 on this OpenSSL");
    }

  /* No identity hint. A hint makes an OpenSSL server send a
   * ServerKeyExchange, and the vendor's flight has none: ServerHello is
   * followed directly by ServerHelloDone. */
  SSL_CTX_set_psk_server_callback (tls->ctx, psk_server_cb);

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

  /* Inspect (type and length only), then forward verbatim: the Finished MACs
   * cover the transcript, so the bytes must reach the server unchanged. */
  while (off < len)
    {
      gsize rlen = g5120_tls_record_len (data + off, len - off);
      guint8 type;

      if (rlen == 0)
        {
          g_debug ("TLS: EC -> host: %" G_GSIZE_FORMAT " trailing byte(s) that are not a "
                   "whole record; forwarding anyway, the server reassembles", len - off);
          break;
        }

      type = data[off];
      g_debug ("TLS: EC -> host: %s record, %" G_GSIZE_FORMAT " bytes",
               g5120_tls_type_name (type), rlen);

      if (type == G5120_TLS_ALERT)
        {
          if (rlen == G5120_TLS_RECORD_HEADER_LEN + 2)
            {
              guint8 desc = data[off + 6];

              g_set_error (error, G5120_TLS_ERROR,
                           alert_means_key_mismatch (desc) ?
                           G5120_TLS_ERROR_PSK_MISMATCH : G5120_TLS_ERROR_ALERT,
                           "the EC sent a %s alert: %s (%u)%s",
                           data[off + 5] == 2 ? "fatal" : "warning",
                           alert_name (desc), desc,
                           alert_means_key_mismatch (desc) ?
                           " — the EC and this host do not share the same PSK" : "");
            }
          else
            {
              g_set_error (error, G5120_TLS_ERROR, G5120_TLS_ERROR_ALERT,
                           "the EC sent an encrypted %" G_GSIZE_FORMAT "-byte alert",
                           rlen - G5120_TLS_RECORD_HEADER_LEN);
            }
          return FALSE;
        }

      tls->from_ec++;
      off += rlen;
    }

  if (len > 0 && BIO_write (tls->rbio, data, len) != (int) len)
    {
      set_ssl_error (error, G5120_TLS_ERROR_FAILED, "buffering EC bytes");
      return FALSE;
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
                   " — the EC and this host do not share the same PSK" : "");
      return;
    }

  set_ssl_error (error, G5120_TLS_ERROR_FAILED, what);
}

gboolean
g5120_tls_handshake (G5120Tls *tls, gboolean *done, GError **error)
{
  int ret, err;

  *done = FALSE;

  ret = SSL_do_handshake (tls->ssl);
  collect_output (tls);

  if (ret == 1)
    {
      *done = TRUE;
      return TRUE;
    }

  err = SSL_get_error (tls->ssl, ret);
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

  ret = SSL_read (tls->ssl, buf, (int) MIN (len, G_MAXINT));
  collect_output (tls);
  if (ret > 0)
    return ret;

  err = SSL_get_error (tls->ssl, ret);
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
