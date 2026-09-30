/* Both implementations independently consume this reference; expectations never
 * come from either implementation's builders or decoders. */
#include <string.h>
#include "shared-fixtures.h"

static GKeyFile *corpus;

static void
check_step (const char *section, const G5120Step *step)
{
  g_autoptr(GByteArray) payload = fixture_hex (corpus, section, "payload");
  g_assert_cmphex (step->cmd, ==, fixture_cmd (corpus, section, "cmd"));
  g_assert_cmpmem (step->payload, step->payload_len, payload->data, payload->len);
  g_assert_cmpuint (step->reply, ==, fixture_reply (corpus, section));
  g_assert_cmpuint (step->secret_reply, ==, fixture_uint (corpus, section, "secret"));
}

static void
test_init (void)
{
  gsize n;
  const G5120Step *steps = g5120_vendor_init_pre_tls (&n);
  g_assert_cmpuint (n, ==, 11);
  for (guint i = 0; i < n; i++)
    {
      g_autofree gchar *section = g_strdup_printf ("init.%02u", i);
      check_step (section, &steps[i]);
    }
  check_step ("init.11", g5120_step_request_tls ());
  check_step ("init.12", g5120_step_tls_established ());
  check_step ("init.13", g5120_step_mcu_state ());
  check_step ("health", g5120_step_health_check ());
  check_step ("loop.image", g5120_step_get_image ());
}

/* The Go catalogue's starting down arm and observed up arm also have C
 * counterparts: the fixed down baseline and a derived zone-uncovered up arm. */
static void
test_loop_catalogue (void)
{
  g_autoptr(GByteArray) want_down = fixture_hex (corpus, "loop.down", "payload");
  g_autoptr(GByteArray) want_up = fixture_hex (corpus, "loop.up", "payload");
  g_autoptr(GByteArray) event = fixture_hex (corpus, "pair.observed-5", "event");
  guint8 thr[6], arm[16];
  G5120FdtEvent ev;
  gsize len = g5120_fdt_encode_arm (0x32, g5120_fdt_initial_down_thresholds,
                                   fixture_uint (corpus, "arm.down", "timestamp"), arm);
  g_assert_cmpmem (arm, len, want_down->data, want_down->len);
  g_assert_true (g5120_fdt_decode_event (0x32, event->data, event->len, &ev, NULL));
  g5120_fdt_up_thresholds (ev.zones, ev.touchflags, G5120_FDT_DELTA_THIS_DEVICE, thr);
  len = g5120_fdt_encode_arm (0x34, thr, 0, arm);
  g_assert_cmpmem (arm, len, want_up->data, want_up->len);
}

static void
test_arm (gconstpointer data)
{
  const char *section = data;
  g_autoptr(GByteArray) thresholds = fixture_hex (corpus, section, "thresholds");
  g_autoptr(GByteArray) want = fixture_hex (corpus, section, "payload");
  guint8 out[16];
  guint8 cmd = fixture_cmd (corpus, section, "cmd");
  gsize len = g5120_fdt_encode_arm (cmd, thresholds->data, fixture_uint (corpus, section, "timestamp"), out);
  g_assert_cmpmem (out, len, want->data, want->len);
  g_assert_true (g5120_check_send (cmd, len, NULL));
  if (cmd == 0x32)
    g_assert_cmpmem (g5120_fdt_initial_down_thresholds, 6, thresholds->data, thresholds->len);
}

static G5120FdtEvent
check_event (const char *section, const char *key)
{
  g_autoptr(GByteArray) raw = fixture_hex (corpus, section, key);
  g_autoptr(GError) error = NULL;
  gsize n;
  g_autofree gint *zones = fixture_ints (corpus, section, "zones", &n);
  G5120FdtEvent ev;
  g_assert_cmpuint (raw->len, ==, 16);
  g_assert_true (g5120_fdt_decode_event (fixture_cmd (corpus, section, "cmd"), raw->data, raw->len, &ev, &error));
  g_assert_no_error (error);
  g_assert_cmpuint (ev.kind, ==, fixture_uint (corpus, section, "kind"));
  g_assert_cmpmem (ev.header, 4, raw->data, 4);
  g_assert_cmpuint (ev.touchflags, ==, raw->data[2]);
  g_assert_cmpuint (n, ==, 6);
  for (guint i = 0; i < n; i++)
    g_assert_cmpuint (ev.zones[i], ==, zones[i]);
  return ev;
}

static void
test_event (gconstpointer data)
{
  check_event (data, "payload");
}

static void
test_pair (gconstpointer data)
{
  const char *section = data;
  G5120FdtEvent ev = check_event (section, "event");
  g_autoptr(GByteArray) want_thr = fixture_hex (corpus, section, "thresholds");
  g_autoptr(GByteArray) want_arm = fixture_hex (corpus, section, "payload");
  guint8 cmd = fixture_cmd (corpus, section, "arm_cmd"), thr[6], arm[16];
  gsize len;
  if (cmd == 0x32)
    g5120_fdt_down_thresholds (ev.zones, thr);
  else
    g5120_fdt_up_thresholds (ev.zones, ev.touchflags, fixture_uint (corpus, section, "delta"), thr);
  g_assert_cmpmem (thr, 6, want_thr->data, want_thr->len);
  len = g5120_fdt_encode_arm (cmd, thr, fixture_uint (corpus, section, "timestamp"), arm);
  g_assert_cmpmem (arm, len, want_arm->data, want_arm->len);
  g_assert_true (g5120_check_send (cmd, len, NULL));
}

static void
test_image (gconstpointer data)
{
  gboolean wrapped = GPOINTER_TO_UINT (data), got_wrapped;
  g_autoptr(GByteArray) pattern = fixture_hex (corpus, "image", "pattern");
  g_autoptr(GByteArray) header = fixture_hex (corpus, "image", "header");
  g_autoptr(GByteArray) trailer = fixture_hex (corpus, "image", "trailer");
  g_autoptr(GByteArray) want_gray = fixture_hex (corpus, "image", "gray");
  g_autoptr(GByteArray) plain = g_byte_array_new ();
  g_autoptr(GError) error = NULL;
  gsize n_want;
  g_autofree gint *want_samples = fixture_ints (corpus, "image", "samples", &n_want);
  guint w = fixture_uint (corpus, "image", "width"), h = fixture_uint (corpus, "image", "height");
  guint packed_len = fixture_uint (corpus, "image", "packed_len");
  guint offset = wrapped ? header->len : 0;
  g_autofree guint16 *samples = g_new (guint16, w * h);
  g_autofree guint8 *gray = g_new (guint8, w * h);
  const guint8 *raw;
  g_assert_cmpuint (w, ==, G5120_IMG_WIDTH);
  g_assert_cmpuint (h, ==, G5120_IMG_HEIGHT);
  g_assert_cmpuint (packed_len, ==, G5120_IMG_PACKED_LEN);
  g_assert_cmpuint (header->len, ==, G5120_IMG_HEADER_LEN);
  g_assert_cmpuint (trailer->len, ==, G5120_IMG_TRAILER_LEN);
  g_assert_cmpuint (fixture_uint (corpus, "image", "wrapped_len"), ==, G5120_IMG_WRAPPED_LEN);
  g_assert_cmpuint (n_want, ==, 4);
  g_assert_cmpuint (want_gray->len, ==, 4);
  if (wrapped)
    g_byte_array_append (plain, header->data, header->len);
  for (guint i = 0; i < fixture_uint (corpus, "image", "repetitions"); i++)
    g_byte_array_append (plain, pattern->data, pattern->len);
  if (wrapped)
    g_byte_array_append (plain, trailer->data, trailer->len);
  g_assert_cmpuint (plain->len, ==, wrapped ? G5120_IMG_WRAPPED_LEN : G5120_IMG_PACKED_LEN);
  raw = g5120_frame_samples (plain->data, plain->len, &got_wrapped, &error);
  g_assert_no_error (error);
  g_assert_true (raw == plain->data + offset);
  g_assert_cmpint (got_wrapped, ==, wrapped);
  for (guint i = 0; i < packed_len; i++)
    g_assert_cmpuint (raw[i], ==, pattern->data[i % pattern->len]);
  g_assert_true (g5120_decode_12bit (raw, packed_len, samples, w * h, &error));
  g_assert_no_error (error);
  g5120_samples_to_gray8 (samples, w * h, gray);
  for (guint i = 0; i < w * h; i++)
    {
      g_assert_cmpuint (samples[i], ==, want_samples[i % n_want]);
      g_assert_cmpuint (gray[i], ==, want_gray->data[i % want_gray->len]);
    }
}

static void
test_image_rejected (void)
{
  gsize n;
  g_autofree gint *lengths = fixture_ints (corpus, "image", "rejected_lengths", &n);
  g_autofree guint8 *plain = g_malloc0 (65536);
  gboolean wrapped;
  for (gsize i = 0; i < n; i++)
    {
      g_autoptr(GError) error = NULL;
      g_assert_null (g5120_frame_samples (plain, lengths[i], &wrapped, &error));
      g_assert_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_IMAGE);
    }
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_autoptr(GKeyFile) owned = fixture_load ();
  g_auto(GStrv) groups = g_key_file_get_groups (owned, NULL);
  corpus = owned;
  g_test_add_func ("/goodix5120/shared/init", test_init);
  g_test_add_func ("/goodix5120/shared/loop-catalogue", test_loop_catalogue);
  for (guint i = 0; groups[i]; i++)
    {
      g_autofree gchar *path = g_strdup_printf ("/goodix5120/shared/%s", groups[i]);
      if (g_str_has_prefix (groups[i], "arm."))
        g_test_add_data_func (path, groups[i], test_arm);
      else if (g_str_has_prefix (groups[i], "event."))
        g_test_add_data_func (path, groups[i], test_event);
      else if (g_str_has_prefix (groups[i], "pair."))
        g_test_add_data_func (path, groups[i], test_pair);
    }
  g_test_add_data_func ("/goodix5120/shared/image/bare", GUINT_TO_POINTER (0), test_image);
  g_test_add_data_func ("/goodix5120/shared/image/wrapped", GUINT_TO_POINTER (1), test_image);
  g_test_add_func ("/goodix5120/shared/image/reject-lengths", test_image_rejected);
  return g_test_run ();
}
