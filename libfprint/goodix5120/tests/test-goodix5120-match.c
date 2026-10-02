/*
 * The stored template format (goodix5120_match.c) against the fake view backend:
 * round trip, best-score selection and refusal of every malformed shape.
 * Real SIGFM is exercised by test-goodix5120-sigfm.
 */
#include <string.h>
#include "fake-matcher.h"
#include "goodix5120_match.h"

#define W 192
#define H 240

static G5120View *
view_of (guint8 seed)
{
  g_autofree guint8 *pixels = g_malloc (W * H);
  G5120View *view;
  memset (pixels, seed, W * H);
  view = g5120_view_extract (pixels, W, H, NULL);
  g_assert_nonnull (view);
  return view;
}

static GPtrArray *
views_of (guint n)
{
  GPtrArray *views = g_ptr_array_new_with_free_func ((GDestroyNotify) g5120_view_free);
  for (guint i = 0; i < n; i++)
    g_ptr_array_add (views, view_of (i));
  return views;
}

static GVariant *
template_of (guint n)
{
  g_autoptr(GPtrArray) views = views_of (n);
  return g_variant_ref_sink (g5120_template_new (views, W, H));
}

static void
test_round_trip (void)
{
  g_autoptr(GVariant) value = template_of (15);
  g_autoptr(GError) error = NULL;
  g_autoptr(GPtrArray) views = NULL;
  g_autoptr(G5120View) probe = view_of (7);
  g_autoptr(G5120View) stranger = view_of (200);
  guint index = 99;

  g_assert_true (g_variant_is_of_type (value, G5120_TEMPLATE_TYPE));
  /* Serialised and read back from bytes, as libfprint stores it. */
  g_autoptr(GBytes) bytes = g_variant_get_data_as_bytes (value);
  g_autoptr(GVariant) loaded = g_variant_ref_sink (g_variant_new_from_bytes (G5120_TEMPLATE_TYPE, bytes, FALSE));
  views = g5120_template_parse (loaded, W, H, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (views->len, ==, 15);
  g_assert_cmpint (g5120_template_best_score (views, probe, &index), ==, FAKE_MATCH_SCORE);
  g_assert_cmpuint (index, ==, 7);
  g_assert_cmpint (g5120_template_best_score (views, stranger, NULL), ==, 0);
}

static void
assert_refused (GVariant *value, const char *fragment)
{
  g_autoptr(GError) error = NULL;
  g_autoptr(GVariant) owned = value ? g_variant_ref_sink (value) : NULL;
  GPtrArray *views = g5120_template_parse (owned, W, H, &error);
  g_assert_null (views);
  g_assert_error (error, G5120_MATCH_ERROR, G5120_MATCH_ERROR_TEMPLATE);
  if (!strstr (error->message, fragment))
    g_error ("'%s' does not mention '%s'", error->message, fragment);
}

/* A template with one view replaced by (points, n_bytes descriptor bytes). */
static GVariant *
template_with_view (guint n_points, gsize n_bytes, guint16 x)
{
  GVariantBuilder points;
  g_autofree guint8 *bytes = g_malloc0 (n_bytes + 1);
  g_variant_builder_init (&points, G_VARIANT_TYPE ("a(qq)"));
  for (guint i = 0; i < n_points; i++)
    g_variant_builder_add (&points, "(qq)", i == 0 ? x : (guint16) 1, (guint16) 1);
  GVariant *view = g_variant_new ("(a(qq)@ay)", &points,
                                  g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, bytes, n_bytes, 1));
  return g_variant_new ("(yqq@a" G5120_VIEW_TYPE_STRING ")", G5120_TEMPLATE_VERSION, W, H,
                        g_variant_new_array (G5120_VIEW_TYPE, &view, 1));
}

static void
test_refusals (void)
{
  g_autoptr(GVariant) good = template_of (3);
  g_autoptr(GVariant) list = NULL;
  guint8 version;
  guint16 w, h;

  g_variant_get (good, "(yqq@a" G5120_VIEW_TYPE_STRING ")", &version, &w, &h, &list);
  assert_refused (NULL, "no print data");
  assert_refused (g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, "abc", 3, 1), "type ay");
  assert_refused (g_variant_new ("(yqq@a" G5120_VIEW_TYPE_STRING ")", version + 1, w, h, list), "format version 2");
  assert_refused (g_variant_new ("(yqq@a" G5120_VIEW_TYPE_STRING ")", version, 64, 80, list), "extracted at 64x80");
  assert_refused (g_variant_new ("(yqq@a" G5120_VIEW_TYPE_STRING ")", version, w, h,
                                 g_variant_new_array (G5120_VIEW_TYPE, NULL, 0)), "0 views");
  assert_refused (template_with_view (G5120_MATCH_MIN_KEYPOINTS - 1,
                                      (G5120_MATCH_MIN_KEYPOINTS - 1) * G5120_MATCH_DESCRIPTOR, 1), "24 keypoints");
  assert_refused (template_with_view (G5120_MATCH_MAX_KEYPOINTS + 1,
                                      (G5120_MATCH_MAX_KEYPOINTS + 1) * G5120_MATCH_DESCRIPTOR, 1), "2049 keypoints");
  assert_refused (template_with_view (30, 30 * G5120_MATCH_DESCRIPTOR - 1, 1), "3839 descriptor bytes");
  assert_refused (template_with_view (30, 30 * G5120_MATCH_DESCRIPTOR + 1, 1), "3841 descriptor bytes");
  assert_refused (template_with_view (30, 30 * G5120_MATCH_DESCRIPTOR, W), "outside the 192x240 image");

  /* Too many views. */
  GVariantBuilder many;
  g_variant_builder_init (&many, G_VARIANT_TYPE ("a" G5120_VIEW_TYPE_STRING));
  g_autoptr(GVariant) first = g_variant_get_child_value (list, 0);
  for (guint i = 0; i <= G5120_MATCH_MAX_VIEWS; i++)
    g_variant_builder_add_value (&many, first);
  assert_refused (g_variant_new ("(yqq@a" G5120_VIEW_TYPE_STRING ")", version, w, h, g_variant_builder_end (&many)),
                  "65 views");
}

/* Bytes from a file that are not in normal form are refused, not repaired. */
static void
test_non_normal (void)
{
  g_autoptr(GVariant) good = template_of (1);
  gsize size = g_variant_get_size (good);
  g_autofree guint8 *data = g_malloc (size);
  g_variant_store (good, data);
  /* The last byte of a (yqq a(...)) is a framing offset for the array; garbling
   * it makes GVariant read a non-normal value, which it repairs on access. */
  data[size - 1] ^= 0x7f;
  g_autoptr(GBytes) bytes = g_bytes_new (data, size);
  GVariant *loaded = g_variant_new_from_bytes (G5120_TEMPLATE_TYPE, bytes, FALSE);
  if (g_variant_is_normal_form (loaded))
    {
      g_variant_unref (g_variant_ref_sink (loaded));
      g_test_skip ("garbled framing still in normal form");
      return;
    }
  assert_refused (loaded, "normal form");
}

static void
test_best_score (void)
{
  g_autoptr(GPtrArray) views = views_of (4);
  g_autoptr(G5120View) probe = view_of (3);
  guint index = 0;
  g_assert_cmpint (g5120_template_best_score (views, probe, &index), ==, FAKE_MATCH_SCORE);
  g_assert_cmpuint (index, ==, 3);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/goodix5120/match/round-trip", test_round_trip);
  g_test_add_func ("/goodix5120/match/refusals", test_refusals);
  g_test_add_func ("/goodix5120/match/non-normal-form", test_non_normal);
  g_test_add_func ("/goodix5120/match/best-score", test_best_score);
  return g_test_run ();
}
