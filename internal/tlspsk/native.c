#include "native.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <string.h>

#if OPENSSL_VERSION_MAJOR < 3
#error "Goodix TLS requires OpenSSL 3"
#endif

#define LIMIT 65536
#define POLICY -2
#define MISMATCH -3
#define OVERFLOW -4
#define CLOSED -5

struct g5120_endpoint {
  SSL_CTX *ctx;
  SSL *ssl;
  unsigned char psk[32];
};

static unsigned int
server_psk(SSL *ssl, const char *identity, unsigned char *psk, unsigned int max)
{
  g5120_endpoint *e = SSL_get_app_data(ssl);
  if (!identity || strcmp(identity, "Client_identity") || max < 32)
    return 0;
  memcpy(psk, e->psk, 32);
  return 32;
}

static unsigned int
client_psk(SSL *ssl, const char *hint, char *identity, unsigned int max_identity,
           unsigned char *psk, unsigned int max_psk)
{
  g5120_endpoint *e = SSL_get_app_data(ssl);
  (void) hint;
  if (max_identity < sizeof("Client_identity") || max_psk < 32)
    return 0;
  memcpy(identity, "Client_identity", sizeof("Client_identity"));
  memcpy(psk, e->psk, 32);
  return 32;
}

static SSL *
new_ssl(SSL_CTX *ctx, int client)
{
  SSL *ssl = SSL_new(ctx);
  BIO *in = BIO_new(BIO_s_mem());
  BIO *out = BIO_new(BIO_s_mem());
  if (!ssl || !in || !out) {
    SSL_free(ssl);
    BIO_free(in);
    BIO_free(out);
    return NULL;
  }
  BIO_set_mem_eof_return(in, -1);
  SSL_set_bio(ssl, in, out);
  if (client)
    SSL_set_connect_state(ssl);
  else
    SSL_set_accept_state(ssl);
  return ssl;
}

/* Extension-free, empty-session-id device-shaped TLS 1.2 ClientHello:
 * only 0x00ae and the renegotiation SCSV, null compression. No real secrets. */
static int
check_policy(SSL_CTX *ctx)
{
  static const unsigned char hello[] = {
    0x16,0x03,0x03,0x00,0x2f,0x01,0x00,0x00,0x2b,0x03,0x03,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0x00,0x00,0x04,0x00,0xae,0x00,0xff,0x01,0x00
  };
  SSL *ssl = new_ssl(ctx, 0);
  int ok = 0;
  if (!ssl)
    return POLICY;
  ERR_clear_error();
  if (BIO_write(SSL_get_rbio(ssl), hello, sizeof(hello)) == sizeof(hello)) {
    int ret = SSL_do_handshake(ssl);
    int err = SSL_get_error(ssl, ret);
    unsigned char record[512];
    int n = BIO_read(SSL_get_wbio(ssl), record, sizeof(record));
    /* Confirm server selection, not mere cipher-list setter success. */
    ok = err == SSL_ERROR_WANT_READ && n >= 47 &&
      record[0] == SSL3_RT_HANDSHAKE && record[5] == SSL3_MT_SERVER_HELLO &&
      record[9] == 0x03 && record[10] == 0x03 &&
      n >= 47 + record[43] && record[44 + record[43]] == 0x00 &&
      record[45 + record[43]] == 0xae;
  }
  SSL_free(ssl);
  ERR_clear_error();
  return ok ? 0 : POLICY;
}

g5120_endpoint *
g5120_new(const unsigned char *psk, int client, int *error)
{
  g5120_endpoint *e = OPENSSL_zalloc(sizeof(*e));
  *error = -1;
  if (!e)
    return NULL;
  memcpy(e->psk, psk, sizeof(e->psk));
  e->ctx = SSL_CTX_new(TLS_method());
  if (!e->ctx)
    goto fail;
  SSL_CTX_set_psk_server_callback(e->ctx, server_psk);
  SSL_CTX_set_psk_client_callback(e->ctx, client_psk);
  /* First test the unmodified effective system context. Pinning protocol and
   * cipher below may only narrow policy, never enable an excluded capability. */
  *error = check_policy(e->ctx);
  if (*error)
    goto fail;
  if (!SSL_CTX_set_min_proto_version(e->ctx, TLS1_2_VERSION) ||
      !SSL_CTX_set_max_proto_version(e->ctx, TLS1_2_VERSION) ||
      !SSL_CTX_set_cipher_list(e->ctx, "PSK-AES128-CBC-SHA256")) {
    *error = POLICY;
    goto fail;
  }
  SSL_CTX_set_options(e->ctx, SSL_OP_NO_TICKET | SSL_OP_NO_EXTENDED_MASTER_SECRET |
                     SSL_OP_NO_ENCRYPT_THEN_MAC);
  /* No identity hint and no security-level override. */
  *error = check_policy(e->ctx);
  if (*error)
    goto fail;
  e->ssl = new_ssl(e->ctx, client);
  if (!e->ssl) {
    *error = -1;
    goto fail;
  }
  SSL_set_app_data(e->ssl, e);
  return e;
fail:
  g5120_free(e);
  ERR_clear_error();
  return NULL;
}

void g5120_free(g5120_endpoint *e)
{
  if (!e)
    return;
  SSL_free(e->ssl);
  SSL_CTX_free(e->ctx);
  OPENSSL_clear_free(e, sizeof(*e));
}

static int
ssl_result(g5120_endpoint *e, int ret)
{
  int err = SSL_get_error(e->ssl, ret);
  int result = -1;
  if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
    return 0;
  if (err == SSL_ERROR_ZERO_RETURN)
    return CLOSED;
  unsigned long code;
  while ((code = ERR_get_error())) {
    int reason = ERR_GET_REASON(code);
    if (reason == SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC ||
        reason == SSL_R_PSK_IDENTITY_NOT_FOUND ||
        /* SSL_R_TLSV1_ALERT_UNKNOWN_PSK_IDENTITY; OpenSSL 3.0 lacks the name. */
        reason == SSL_AD_REASON_OFFSET + TLS1_AD_UNKNOWN_PSK_IDENTITY ||
        reason == SSL_R_SSLV3_ALERT_BAD_RECORD_MAC ||
        reason == SSL_R_TLSV1_ALERT_DECRYPT_ERROR)
      result = MISMATCH;
    if (reason == SSL_R_NO_SHARED_CIPHER || reason == SSL_R_NO_CIPHERS_AVAILABLE ||
        reason == SSL_R_UNSUPPORTED_PROTOCOL)
      result = POLICY;
  }
  return result;
}

int g5120_feed(g5120_endpoint *e, const unsigned char *p, size_t n)
{
  if (n > LIMIT || BIO_ctrl_pending(SSL_get_rbio(e->ssl)) > LIMIT - n)
    return OVERFLOW;
  return BIO_write(SSL_get_rbio(e->ssl), p, (int)n) == (int)n ? 0 : -1;
}

int g5120_step(g5120_endpoint *e, unsigned char *p, size_t n)
{
  ERR_clear_error();
  if (!SSL_is_init_finished(e->ssl)) {
    int ret = SSL_do_handshake(e->ssl);
    if (ret != 1)
      return ssl_result(e, ret);
  }
  int ret = SSL_read(e->ssl, p, (int)n);
  return ret > 0 ? ret : ssl_result(e, ret);
}

int g5120_write(g5120_endpoint *e, const unsigned char *p, size_t n)
{
  ERR_clear_error();
  int ret = SSL_write(e->ssl, p, (int)n);
  return ret > 0 ? ret : ssl_result(e, ret);
}

int g5120_drain(g5120_endpoint *e, unsigned char *p, size_t n)
{
  if (BIO_ctrl_pending(SSL_get_wbio(e->ssl)) > LIMIT)
    return OVERFLOW;
  int ret = BIO_read(SSL_get_wbio(e->ssl), p, (int)n);
  return ret > 0 ? ret : 0;
}

int g5120_ready(g5120_endpoint *e) { return SSL_is_init_finished(e->ssl); }
int g5120_preflight(void)
{
  unsigned char psk[32] = {0};
  int err = 0;
  g5120_endpoint *e = g5120_new(psk, 0, &err);
  int ok = e != NULL;
  g5120_free(e);
  return ok ? 0 : err;
}
const char *g5120_version(void) { return OpenSSL_version(OPENSSL_VERSION); }
