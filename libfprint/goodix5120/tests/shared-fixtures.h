/* Test-only reader for the independent corpus shared with Go. */
#pragma once
#include <glib.h>
#include "goodix5120_proto.h"

GKeyFile *fixture_parse (const gchar *data, GError **error);
GKeyFile *fixture_load (void);
GByteArray *fixture_hex (GKeyFile *corpus, const char *section, const char *key);
guint fixture_uint (GKeyFile *corpus, const char *section, const char *key);
gint *fixture_ints (GKeyFile *corpus, const char *section, const char *key, gsize *len);
guint8 fixture_cmd (GKeyFile *corpus, const char *section, const char *key);
G5120Reply fixture_reply (GKeyFile *corpus, const char *section);
