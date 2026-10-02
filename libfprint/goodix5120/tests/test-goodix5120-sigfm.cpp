/*
 * The real SIGFM backend (goodix5120_sigfm.cpp over the vendored sigfm/):
 * extraction, the template round trip and that it changes no score.
 * Synthetic ridge patterns only; needs OpenCV, so it is built only when
 * OpenCV is found. These do not measure matching accuracy (Runs 38-40 did).
 */
#include <cmath>
#include <vector>

#include "goodix5120_match.h"

namespace {

constexpr guint W = 192, H = 240;

/* A whorl-like ridge pattern with a period of 27 px (9 px at 64 x 80), plus
 * fixed pseudo-random noise: smooth synthetic ridges give SIFT too few corners. */
std::vector<guint8>
whorl (double cx, double cy, double twist, double shift)
{
  std::vector<guint8> img (W * H);
  g_autoptr(GRand) rand = g_rand_new_with_seed (5120);

  for (guint y = 0; y < H; y++)
    for (guint x = 0; x < W; x++)
      {
        double dx = x + shift - W * cx, dy = y - H * cy;
        double r = std::sqrt (dx * dx + dy * dy) + 9.0 * std::sin (std::atan2 (dy, dx) * twist) +
                   4.0 * std::sin (x * 0.05) * std::cos (y * 0.07);
        double v = 128.0 + 90.0 * std::sin (2.0 * G_PI * r / 27.0) + g_rand_double_range (rand, -30.0, 30.0);

        img[y * W + x] = (guint8) CLAMP (v, 0.0, 255.0);
      }
  return img;
}

G5120View *
extract (const std::vector<guint8> &img)
{
  g_autoptr(GError) error = nullptr;
  G5120View *view = g5120_view_extract (img.data (), W, H, &error);

  g_assert_no_error (error);
  g_assert_nonnull (view);
  return view;
}

void
test_extract (void)
{
  g_autoptr(G5120View) view = extract (whorl (0.45, 0.55, 3.0, 0.0));
  std::vector<guint8> flat (W * H, 128);
  g_autoptr(G5120View) none = extract (flat);

  g_test_message ("whorl: %u keypoints", g5120_view_keypoints (view));
  g_assert_cmpuint (g5120_view_keypoints (view), >=, G5120_MATCH_MIN_KEYPOINTS);
  g_assert_cmpuint (g5120_view_keypoints (none), <, G5120_MATCH_MIN_KEYPOINTS);
  /* Identical images: every keypoint matches its twin. */
  g_assert_cmpint (g5120_view_score (view, view), >=, G5120_MATCH_THRESHOLD);
}

/* Storing views must not change a single score: SIGFM reads keypoints only as
 * rounded integer points, and SIFT's descriptors are whole numbers 0..255. */
void
test_round_trip_scores (void)
{
  g_autoptr(GPtrArray) views = g_ptr_array_new_with_free_func ((GDestroyNotify) g5120_view_free);
  g_autoptr(GPtrArray) loaded = nullptr;
  g_autoptr(GError) error = nullptr;
  std::vector<G5120View *> probes;

  for (int i = 0; i < 4; i++)
    g_ptr_array_add (views, extract (whorl (0.45, 0.55, 3.0, i * 5.0)));
  for (int i = 0; i < 4; i++)
    probes.push_back (extract (whorl (i < 2 ? 0.45 : 0.6, i < 2 ? 0.55 : 0.4, i < 2 ? 3.0 : 5.0, i * 3.0 + 1.0)));

  g_autoptr(GVariant) tmpl = g_variant_ref_sink (g5120_template_new (views, W, H));
  g_autoptr(GBytes) bytes = g_variant_get_data_as_bytes (tmpl);
  g_autoptr(GVariant) stored = g_variant_ref_sink (g_variant_new_from_bytes (G5120_TEMPLATE_TYPE, bytes, FALSE));
  loaded = g5120_template_parse (stored, W, H, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (loaded->len, ==, views->len);
  g_test_message ("template: %zu bytes", g_bytes_get_size (bytes));

  for (guint v = 0; v < views->len; v++)
    {
      auto *a = static_cast<G5120View *> (g_ptr_array_index (views, v));
      auto *b = static_cast<G5120View *> (g_ptr_array_index (loaded, v));

      g_assert_cmpuint (g5120_view_keypoints (a), ==, g5120_view_keypoints (b));
      for (G5120View *probe : probes)
        {
          gint before = g5120_view_score (probe, a);
          gint after = g5120_view_score (probe, b);

          g_test_message ("view %u: %d / %d", v, before, after);
          g_assert_cmpint (before, ==, after);
        }
    }
  for (G5120View *probe : probes)
    g5120_view_free (probe);
}

} // namespace

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, nullptr);
  g_test_add_func ("/goodix5120/sigfm/extract", test_extract);
  g_test_add_func ("/goodix5120/sigfm/round-trip-scores", test_round_trip_scores);
  return g_test_run ();
}
