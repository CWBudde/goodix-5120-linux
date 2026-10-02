/*
 * Owner-only diagnostic: does SIGFM separate two fingers on this sensor?
 *
 * Run 37 measured at most 5 NBIS minutiae per frame, so Bozorth3 (which needs
 * 10) cannot match. This tool captures K frames of finger A and K frames of
 * finger B through the unchanged goodix5120 driver in one open, extracts SIGFM
 * features (the goodixtls fork's SIFT-based matcher, compiled from its pinned
 * source, not from this repository), and prints keypoint counts and match
 * scores for the driver's x3 image and for a 64 x 80 reduction of it.
 *
 * Prints numbers only. No pixels, features or templates are written anywhere;
 * everything stays in memory and is freed on exit. It opens hardware, so only
 * the owner runs it (docs/c-driver-enroll-verify.md).
 *
 * libfprint's capture action discards a frame in which NBIS finds no minutiae,
 * so such touches are repeated; the kept frames are biased towards images with
 * at least one minutia.
 */

#include <glib-unix.h>
#include <libfprint/fprint.h>

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "sigfm.hpp"

namespace {

constexpr int SRC_W = 64;
constexpr int SRC_H = 80;
constexpr int DRV_ENL = 3;
constexpr int FORK_THRESHOLD = 24; /* goodix511 in the goodixtls fork */
constexpr int FORK_MIN_KEYPOINTS = 25; /* fork's fp-image.c retry limit */

struct Variant {
  const char                 *name;
  std::vector<SigfmImgInfo *> a, b;
};

std::vector<guint8>
reduce_x3 (const guint8 *x3)
{
  std::vector<guint8> x1 (SRC_W * SRC_H);

  for (int y = 0; y < SRC_H; y++)
    for (int x = 0; x < SRC_W; x++)
      {
        unsigned sum = 0;

        for (int dy = 0; dy < DRV_ENL; dy++)
          for (int dx = 0; dx < DRV_ENL; dx++)
            sum += x3[(y * DRV_ENL + dy) * SRC_W * DRV_ENL + x * DRV_ENL + dx];
        x1[y * SRC_W + x] = (sum + 4) / 9;
      }
  return x1;
}

void
add_frame (Variant &v1, Variant &v3, bool finger_a, const guint8 *x3)
{
  std::vector<guint8> x1 = reduce_x3 (x3);
  SigfmImgInfo *i1 = sigfm_extract (x1.data (), SRC_W, SRC_H);
  SigfmImgInfo *i3 = sigfm_extract (x3, SRC_W * DRV_ENL, SRC_H * DRV_ENL);

  (finger_a ? v1.a : v1.b).push_back (i1);
  (finger_a ? v3.a : v3.b).push_back (i3);
  printf ("  keypoints: x1=%d x3=%d\n", sigfm_keypoints_count (i1), sigfm_keypoints_count (i3));
}

void
print_stats (const char *label, std::vector<int> s)
{
  if (s.empty ())
    {
      printf ("  %-26s (none)\n", label);
      return;
    }
  std::sort (s.begin (), s.end ());
  printf ("  %-26s n=%zu min=%d median=%d max=%d  [", label, s.size (), s.front (),
          s[s.size () / 2], s.back ());
  for (size_t i = 0; i < s.size (); i++)
    printf ("%s%d", i ? " " : "", s[i]);
  printf ("]\n");
}

/* Scores as libfprint's fork uses them: probe = "frame", template = "enrolled";
 * a verify succeeds when any template view scores >= the threshold. */
void
report (const Variant &v)
{
  std::vector<int> gen_pairs, imp_pairs, gen_loo, imp_all, kp;
  size_t k = v.a.size ();

  for (SigfmImgInfo *i : v.a)
    kp.push_back (sigfm_keypoints_count (i));
  for (SigfmImgInfo *i : v.b)
    kp.push_back (sigfm_keypoints_count (i));

  for (size_t i = 0; i < k; i++)
    {
      int best = 0;

      for (size_t j = 0; j < k; j++)
        if (i != j)
          {
            int s = sigfm_match_score (v.a[i], v.a[j]);

            gen_pairs.push_back (s);
            best = std::max (best, s);
          }
      gen_loo.push_back (best);
    }
  for (SigfmImgInfo *probe : v.b)
    {
      int best = 0;

      for (SigfmImgInfo *tmpl : v.a)
        {
          int s = sigfm_match_score (probe, tmpl);

          imp_pairs.push_back (s);
          best = std::max (best, s);
        }
      imp_all.push_back (best);
    }

  printf ("%s:\n", v.name);
  print_stats ("keypoints (all frames)", kp);
  print_stats ("genuine pairs A->A", gen_pairs);
  print_stats ("impostor pairs B->A", imp_pairs);
  print_stats ("genuine verify (best)", gen_loo);
  print_stats ("impostor verify (best)", imp_all);

  int accepted = 0, false_accepts = 0, low_kp = 0;

  for (int s : gen_loo)
    accepted += s >= FORK_THRESHOLD;
  for (int s : imp_all)
    false_accepts += s >= FORK_THRESHOLD;
  for (int n : kp)
    low_kp += n < FORK_MIN_KEYPOINTS;
  printf ("  at the fork's threshold %d: genuine accepted %d/%zu, impostor accepted %d/%zu;"
          " frames under %d keypoints: %d/%zu\n",
          FORK_THRESHOLD, accepted, gen_loo.size (), false_accepts, imp_all.size (),
          FORK_MIN_KEYPOINTS, low_kp, kp.size ());
}

void
free_variant (Variant &v)
{
  for (SigfmImgInfo *i : v.a)
    sigfm_free_info (i);
  for (SigfmImgInfo *i : v.b)
    sigfm_free_info (i);
  v.a.clear ();
  v.b.clear ();
}

/* A synthetic whorl-like pattern, optionally shifted, as the driver's x3 image. */
std::vector<guint8>
synthetic (double cx, double cy, double twist, double shift)
{
  int w = SRC_W * DRV_ENL, h = SRC_H * DRV_ENL;
  std::vector<guint8> img (w * h);

  for (int y = 0; y < h; y++)
    for (int x = 0; x < w; x++)
      {
        double dx = x + shift - w * cx, dy = y - h * cy;
        double r = std::sqrt (dx * dx + dy * dy) + 9.0 * std::sin (std::atan2 (dy, dx) * twist) +
                   4.0 * std::sin (x * 0.05) * std::cos (y * 0.07);

        img[y * w + x] = (guint8) (128.0 + 100.0 * std::sin (2.0 * G_PI * r / (9.0 * DRV_ENL)));
      }
  return img;
}

int
selftest ()
{
  Variant v1{ "x1 (64x80)", {}, {} }, v3{ "x3 (driver)", {}, {} };

  for (int i = 0; i < 3; i++)
    {
      std::vector<guint8> a = synthetic (0.45, 0.55, 3.0, i * 4.0);
      std::vector<guint8> b = synthetic (0.60, 0.40, 5.0, i * 4.0);

      printf ("synthetic A%d", i + 1);
      add_frame (v1, v3, true, a.data ());
      printf ("synthetic B%d", i + 1);
      add_frame (v1, v3, false, b.data ());
    }
  report (v1);
  report (v3);
  free_variant (v1);
  free_variant (v3);
  return EXIT_SUCCESS;
}

gboolean
on_sigint (gpointer user_data)
{
  g_cancellable_cancel (G_CANCELLABLE (user_data));
  return G_SOURCE_CONTINUE;
}

} // namespace

int
main (int argc, char **argv)
{
  if (argc > 1 && std::strcmp (argv[1], "--selftest") == 0)
    return selftest ();

  int k = argc > 1 ? std::atoi (argv[1]) : 6;

  if (k < 2 || k > 15)
    {
      fprintf (stderr, "usage: %s [frames per finger 2..15, default 6 | --selftest]\n", argv[0]);
      return EXIT_FAILURE;
    }
  setvbuf (stdout, nullptr, _IOLBF, 0);

  GCancellable *cancel = g_cancellable_new ();
  g_unix_signal_add (SIGINT, on_sigint, cancel);

  FpContext *ctx = fp_context_new ();
  GPtrArray *devices = fp_context_get_devices (ctx);
  GError *error = nullptr;
  int rc = EXIT_SUCCESS;

  if (!devices || devices->len != 1)
    {
      fprintf (stderr, "expected exactly one supported device, found %u\n", devices ? devices->len : 0);
      g_object_unref (ctx);
      return EXIT_FAILURE;
    }
  FpDevice *dev = FP_DEVICE (g_ptr_array_index (devices, 0));

  if (!fp_device_open_sync (dev, cancel, &error))
    {
      fprintf (stderr, "open failed: %s\n", error->message);
      g_error_free (error);
      g_object_unref (ctx);
      return EXIT_FAILURE;
    }

  Variant v1{ "x1 (64x80, box-reduced from the driver's image)", {}, {} };
  Variant v3{ "x3 (the driver's 192x240 image)", {}, {} };

  for (int phase = 0; phase < 2 && rc == EXIT_SUCCESS; phase++)
    {
      bool finger_a = phase == 0;
      int kept = 0, attempts = 0;

      printf ("\n=== finger %s: %d touches. %s ===\n", finger_a ? "A" : "B", k,
              finger_a ? "Use the finger you would enroll; vary the placement slightly."
                       : "Use a DIFFERENT finger.");
      while (kept < k && attempts < 3 * k && !g_cancellable_is_cancelled (cancel))
        {
          GError *cerr = nullptr;

          attempts++;
          printf ("finger %s, frame %d/%d: touch at 'arming 0x32', lift at 'arming 0x34'\n",
                  finger_a ? "A" : "B", kept + 1, k);
          FpImage *img = fp_device_capture_sync (dev, TRUE, cancel, &cerr);

          if (!img)
            {
              if (g_error_matches (cerr, FP_DEVICE_RETRY, FP_DEVICE_RETRY_GENERAL))
                {
                  printf ("  discarded by libfprint (no NBIS minutiae); touch again\n");
                  g_error_free (cerr);
                  continue;
                }
              fprintf (stderr, "capture failed: %s\n", cerr->message);
              g_error_free (cerr);
              rc = EXIT_FAILURE;
              break;
            }

          gsize len;
          const guint8 *x3 = fp_image_get_data (img, &len);

          if (fp_image_get_width (img) != SRC_W * DRV_ENL || fp_image_get_height (img) != SRC_H * DRV_ENL ||
              len != (gsize) (SRC_W * DRV_ENL * SRC_H * DRV_ENL))
            {
              fprintf (stderr, "unexpected image geometry %ux%u\n", fp_image_get_width (img),
                       fp_image_get_height (img));
              g_object_unref (img);
              rc = EXIT_FAILURE;
              break;
            }
          add_frame (v1, v3, finger_a, x3);
          g_object_unref (img);
          kept++;
        }
      if (kept < k && rc == EXIT_SUCCESS)
        {
          fprintf (stderr, "stopped with %d/%d frames of finger %s\n", kept, k, finger_a ? "A" : "B");
          rc = EXIT_FAILURE;
        }
    }

  if (rc == EXIT_SUCCESS)
    {
      printf ("\n=== SIGFM scores (higher = more similar; the fork accepts at >= %d) ===\n", FORK_THRESHOLD);
      report (v1);
      report (v3);
    }
  free_variant (v1);
  free_variant (v3);

  if (!fp_device_close_sync (dev, nullptr, &error))
    {
      fprintf (stderr, "close failed: %s\n", error->message);
      g_error_free (error);
      rc = EXIT_FAILURE;
    }
  g_object_unref (ctx);
  g_object_unref (cancel);
  return rc;
}
