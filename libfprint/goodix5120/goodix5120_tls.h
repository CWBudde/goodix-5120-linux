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
 * After 0xd0 the EC is the TLS *client* and the host is the *server*: TLS 1.2,
 * suite 0x00ae TLS_PSK_WITH_AES_128_CBC_SHA256, PSK identity
 * "Client_identity", no ServerKeyExchange (no identity hint). This module is
 * the server half with no I/O of its own: the driver feeds it the bytes of
 * every 0xb0 pack the EC sends and sends every record it produces in its own
 * 0xb0 pack. GLib and OpenSSL only; no libfprint types.
 */

#pragma once

#include <glib.h>

G_BEGIN_DECLS

#define G5120_PSK_LEN 32
#define G5120_PSK_IDENTITY "Client_identity"
#define G5120_TLS_CIPHER "PSK-AES128-CBC-SHA256"

#define G5120_TLS_ERROR (g5120_tls_error_quark ())
typedef enum {
  G5120_TLS_ERROR_SETUP,          /* OpenSSL context could not be built */
  G5120_TLS_ERROR_PSK_FILE,       /* PSK file missing or malformed */
  G5120_TLS_ERROR_ALERT,          /* the EC sent an alert */
  G5120_TLS_ERROR_PSK_MISMATCH,   /* bad MAC/decryption suggests different keys */
  G5120_TLS_ERROR_FAILED,         /* the handshake failed on our side */
  G5120_TLS_ERROR_CLOSED,         /* the EC closed the session */
  G5120_TLS_ERROR_POLICY,         /* effective local policy rejects the device suite */
} G5120TlsError;

GQuark g5120_tls_error_quark (void);

typedef struct _G5120Tls G5120Tls;

/* Reads a raw 32-byte PSK (not hex) from @path — the form goodix-dpapi -out
 * writes. Warns (via g_warning) if the file is readable by group or others. */
gboolean g5120_psk_load (const char *path,
                         guint8      psk[G5120_PSK_LEN],
                         GError    **error);

/* Probes the effective context policy offline with a synthetic device-shaped
 * ClientHello before returning a usable server. Never lowers security policy. */
G5120Tls *g5120_tls_new (const guint8 psk[G5120_PSK_LEN],
                         GError     **error);
void      g5120_tls_free (G5120Tls *tls);

/* Hands the server EC bytes verbatim, preserving record boundaries across
 * arbitrary feeds. Counts only complete records. A complete plaintext alert is
 * reported here; encrypted alerts are interpreted by OpenSSL. */
gboolean g5120_tls_feed (G5120Tls     *tls,
                         const guint8 *data,
                         gsize         len,
                         GError      **error);

/* Advances the handshake as far as the fed bytes allow. Returns TRUE and sets
 * @done when the server has verified the EC's Finished and written its own
 * ChangeCipherSpec + Finished: in TLS 1.2 that is only possible if both ends
 * hold the same PSK. Returns FALSE with @error on failure. */
gboolean g5120_tls_handshake (G5120Tls *tls,
                              gboolean *done,
                              GError  **error);

/* Pops the next whole record the server wants sent to the EC, or returns NULL
 * if there is none. Each record goes to the EC in its own 0xb0 pack, as the
 * vendor driver sends them. Alert records the server generates are NOT
 * returned (see the .c file); they turn into an error from
 * g5120_tls_handshake() instead. */
GBytes *g5120_tls_pop_record (G5120Tls *tls);

/* Whether another whole record is queued for the EC, without popping it. */
gboolean g5120_tls_has_record (G5120Tls *tls);

/* A received TLS record is incomplete; read its suffix before more output. */
gboolean g5120_tls_has_partial_input (G5120Tls *tls);

/* Reads decrypted application data into @buf. Returns the number of bytes
 * read, 0 if nothing is available yet, or -1 with @error set. */
gssize g5120_tls_read (G5120Tls *tls,
                       guint8   *buf,
                       gsize     len,
                       GError  **error);

/* Records forwarded each way, for a log line. */
void g5120_tls_counts (G5120Tls *tls,
                       guint    *from_ec,
                       guint    *to_ec);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (G5120Tls, g5120_tls_free)

G_END_DECLS
