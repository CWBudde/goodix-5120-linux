#include <string.h>
#include "shared-fixtures.h"

static gboolean
valid_number (const char *s)
{
  if (!*s)
    return FALSE;
  for (gsize i = 0; s[i]; i++)
    if (!g_ascii_isdigit (s[i]))
      return FALSE;
  return g_ascii_strtoull (s, NULL, 10) <= 65535;
}

GKeyFile *
fixture_parse (const gchar *data, GError **error)
{
  g_autoptr(GKeyFile) c = g_key_file_new ();
  g_autoptr(GHashTable) seen = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  g_auto(GStrv) lines = g_strsplit (data, "\n", -1);
  g_auto(GStrv) groups = NULL;
  const char *section = NULL;
  const char *problem = "invalid corpus syntax";
  gsize n_groups;

  /* GKeyFile alone silently accepts duplicate groups/keys. Check the source
   * before allowing GLib to merge them into one reference. */
  for (guint i = 0; lines[i]; i++)
    {
      gchar *line = g_strstrip (lines[i]);
      g_autofree gchar *identity = NULL;
      gchar *equals;
      gsize n = strlen (line);
      if (!n || line[0] == '#')
        continue;
      if (line[0] == '[' && line[n - 1] == ']')
        {
          line[n - 1] = 0;
          section = line + 1;
          identity = g_strconcat ("section:", section, NULL);
        }
      else
        {
          if (!section || !(equals = strchr (line, '=')))
            goto invalid;
          *equals = 0;
          identity = g_strconcat ("key:", section, ":", g_strstrip (line), NULL);
        }
      if (g_hash_table_contains (seen, identity))
        { problem = "duplicate corpus section or key"; goto invalid; }
      g_hash_table_add (seen, g_steal_pointer (&identity));
    }
  if (!g_key_file_load_from_data (c, data, strlen (data), G_KEY_FILE_NONE, error))
    return NULL;
  groups = g_key_file_get_groups (c, &n_groups);
  if (!n_groups)
    { problem = "empty corpus"; goto invalid; }
  for (gsize i = 0; i < n_groups; i++)
    {
      const char *name = groups[i], *spec;
      g_auto(GStrv) fields = NULL;
      g_auto(GStrv) keys = NULL;
      gsize n_keys;
      if (g_str_has_prefix (name, "init.") || !strcmp (name, "health") || g_str_has_prefix (name, "loop."))
        spec = "cmd:h payload:h reply:r data:h secret:n";
      else if (g_str_has_prefix (name, "arm."))
        spec = "cmd:h thresholds:h timestamp:n payload:h";
      else if (g_str_has_prefix (name, "event."))
        spec = "cmd:h payload:h kind:n zones:l";
      else if (g_str_has_prefix (name, "pair."))
        spec = "cmd:h event:h kind:n zones:l arm_cmd:h delta:n timestamp:n thresholds:h payload:h";
      else if (!strcmp (name, "image"))
        spec = "width:n height:n packed_len:n wrapped_len:n header:h trailer:h pattern:h samples:l gray:h repetitions:n rejected_lengths:l";
      else
        { problem = "unknown corpus section"; goto invalid; }
      fields = g_strsplit (spec, " ", -1);
      keys = g_key_file_get_keys (c, name, &n_keys, NULL);
      if (n_keys != g_strv_length (fields))
        { problem = "incomplete or unknown corpus fields"; goto invalid; }
      for (guint j = 0; fields[j]; j++)
        {
          gchar *colon = strchr (fields[j], ':');
          gchar type = colon[1];
          g_autofree gchar *value = NULL;
          *colon = 0;
          value = g_key_file_get_string (c, name, fields[j], NULL);
          if (!value)
            { problem = "missing corpus field"; goto invalid; }
          problem = "invalid corpus value";
          if (type == 'h')
            {
              gsize len = strlen (value);
              if (len % 2 || (!len && strcmp (fields[j], "data")))
                goto invalid;
              for (gsize k = 0; k < len; k++)
                if (!g_ascii_isxdigit (value[k]))
                  goto invalid;
              if ((!strcmp (fields[j], "cmd") || !strcmp (fields[j], "arm_cmd")) && len != 2)
                goto invalid;
              if (!strcmp (fields[j], "thresholds") && len != 12)
                goto invalid;
            }
          else if (type == 'r')
            {
              if (strcmp (value, "none") && strcmp (value, "ack") && strcmp (value, "data") &&
                  strcmp (value, "ack-data") && strcmp (value, "tls") && strcmp (value, "ack-tls"))
                goto invalid;
            }
          else if (type == 'n')
            {
              if (!valid_number (value))
                goto invalid;
              guint64 n = g_ascii_strtoull (value, NULL, 10);
              if ((!strcmp (fields[j], "secret") && n > 1) ||
                  (!strcmp (fields[j], "kind") && n > 4) || (!strcmp (fields[j], "delta") && n > 255))
                goto invalid;
            }
          else
            {
              g_auto(GStrv) numbers = NULL;
              gsize len = strlen (value);
              if (!len || value[len - 1] != ';')
                goto invalid;
              value[len - 1] = 0;
              numbers = g_strsplit (value, ";", -1);
              if (!strcmp (fields[j], "zones") && g_strv_length (numbers) != 6)
                goto invalid;
              for (guint k = 0; numbers[k]; k++)
                if (!valid_number (numbers[k]))
                  goto invalid;
            }
        }
    }
  return g_steal_pointer (&c);
invalid:
  g_set_error_literal (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_PARSE, problem);
  return NULL;
}

GKeyFile *
fixture_load (void)
{
  g_autofree gchar *data = NULL;
  g_autoptr(GError) error = NULL;
  GKeyFile *c;
  g_assert_true (g_file_get_contents (G5120_SHARED_FIXTURE_DIR "/protocol.ini", &data, NULL, &error));
  g_assert_no_error (error);
  c = fixture_parse (data, &error);
  g_assert_no_error (error);
  g_assert_nonnull (c);
  const char *prefixes[] = { "init.", "health", "loop.", "arm.", "event.", "pair.", "image" };
  const guint expected[] = { 14, 1, 3, 3, 10, 21, 1 };
  g_auto(GStrv) groups = g_key_file_get_groups (c, NULL);
  for (guint i = 0; i < G_N_ELEMENTS (prefixes); i++)
    {
      guint n = 0;
      for (guint j = 0; groups[j]; j++)
        if (g_str_has_prefix (groups[j], prefixes[i]))
          n++;
      g_assert_cmpuint (n, ==, expected[i]);
    }
  return c;
}

GByteArray *
fixture_hex (GKeyFile *c, const char *section, const char *key)
{
  g_autoptr(GError) error = NULL;
  g_autofree gchar *s = g_key_file_get_string (c, section, key, &error);
  GByteArray *out = g_byte_array_new ();
  g_assert_no_error (error);
  g_assert_cmpuint (strlen (s) % 2, ==, 0);
  for (gsize i = 0; s[i]; i += 2)
    {
      gint a = g_ascii_xdigit_value (s[i]), b = g_ascii_xdigit_value (s[i + 1]);
      guint8 byte;
      g_assert_cmpint (a, >=, 0);
      g_assert_cmpint (b, >=, 0);
      byte = (a << 4) | b;
      g_byte_array_append (out, &byte, 1);
    }
  return out;
}

guint
fixture_uint (GKeyFile *c, const char *section, const char *key)
{
  g_autoptr(GError) error = NULL;
  gint value = g_key_file_get_integer (c, section, key, &error);
  g_assert_no_error (error);
  g_assert_cmpint (value, >=, 0);
  g_assert_cmpint (value, <=, 65535);
  return value;
}

gint *
fixture_ints (GKeyFile *c, const char *section, const char *key, gsize *len)
{
  g_autoptr(GError) error = NULL;
  gint *values = g_key_file_get_integer_list (c, section, key, len, &error);
  g_assert_no_error (error);
  return values;
}

guint8
fixture_cmd (GKeyFile *c, const char *section, const char *key)
{
  g_autoptr(GByteArray) bytes = fixture_hex (c, section, key);
  g_assert_cmpuint (bytes->len, ==, 1);
  return bytes->data[0];
}

G5120Reply
fixture_reply (GKeyFile *c, const char *section)
{
  const char *names[] = { "none", "ack", "data", "ack-data", "tls", "ack-tls" };
  const G5120Reply values[] = { G5120_REPLY_NONE, G5120_REPLY_ACK, G5120_REPLY_DATA,
    G5120_REPLY_ACK | G5120_REPLY_DATA, G5120_REPLY_TLS, G5120_REPLY_ACK | G5120_REPLY_TLS };
  g_autofree gchar *s = g_key_file_get_string (c, section, "reply", NULL);
  for (guint i = 0; i < G_N_ELEMENTS (names); i++)
    if (g_strcmp0 (s, names[i]) == 0)
      return values[i];
  g_error ("unknown fixture reply mode");
}
