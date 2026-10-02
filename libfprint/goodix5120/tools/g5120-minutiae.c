/*
 * Owner-only diagnostic: how many NBIS minutiae does each frame yield?
 *
 * Captures N frames through the goodix5120 driver (one open, one TLS session)
 * and prints, per frame, the minutiae count libfprint's own pipeline found on
 * the driver's x3 image, then re-runs the same NBIS detection on rescaled
 * copies (x1..x5) and on the colour-inverted x3 image. Bozorth3 scores 0
 * whenever either print has fewer than 10 minutiae (Run 36).
 *
 * Prints counts only. No pixels, no templates, no files: images never leave
 * memory. It opens hardware, so only the owner runs it, per
 * docs/c-driver-enroll-verify.md.
 *
 * Uses public libfprint API only. Rescaled images are written through the
 * buffer fp_image_get_data() returns, which fp_image_new() allocated.
 */

#include <glib-unix.h>
#include <libfprint/fprint.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SRC_W   64
#define SRC_H   80
#define DRV_ENL 3

typedef struct
{
  gboolean done;
  gboolean ok;
  GError  *error;
} Wait;

static void
on_detected (GObject *src, GAsyncResult *res, gpointer user_data)
{
  Wait *w = user_data;

  w->ok = fp_image_detect_minutiae_finish (FP_IMAGE (src), res, &w->error);
  w->done = TRUE;
}

/* Count after detection; 0 when NBIS found none, -1 on any other failure. */
static gint
detect_count (FpImage *img)
{
  Wait w = { 0 };
  GPtrArray *m;

  fp_image_detect_minutiae (img, NULL, on_detected, &w);
  while (!w.done)
    g_main_context_iteration (NULL, TRUE);

  if (!w.ok)
    {
      gboolean none = w.error && strstr (w.error->message, "No minutiae") != NULL;

      g_clear_error (&w.error);
      return none ? 0 : -1;
    }
  m = fp_image_get_minutiae (img);
  return m ? (gint) m->len : 0;
}

static FpImage *
image_from (const guint8 *pix, gint w, gint h)
{
  FpImage *img = fp_image_new (w, h);
  gsize len;
  guint8 *dst = (guint8 *) fp_image_get_data (img, &len);

  g_assert (len == (gsize) (w * h));
  memcpy (dst, pix, len);
  return img;
}

/* The driver's x3 image back to 64 x 80 by 3 x 3 box averaging. */
static void
reduce_x3 (const guint8 *x3, guint8 *x1)
{
  for (gint y = 0; y < SRC_H; y++)
    for (gint x = 0; x < SRC_W; x++)
      {
        guint sum = 0;

        for (gint dy = 0; dy < DRV_ENL; dy++)
          for (gint dx = 0; dx < DRV_ENL; dx++)
            sum += x3[(y * DRV_ENL + dy) * SRC_W * DRV_ENL + x * DRV_ENL + dx];
        x1[y * SRC_W + x] = (sum + 4) / 9;
      }
}

/* Bilinear enlargement of the 64 x 80 frame by k (pixel-centre aligned). */
static void
enlarge (const guint8 *x1, guint8 *out, gint k)
{
  gint w = SRC_W * k, h = SRC_H * k;

  for (gint y = 0; y < h; y++)
    {
      double sy = CLAMP ((y + 0.5) / k - 0.5, 0.0, SRC_H - 1.0);
      gint y0 = (gint) sy, y1 = MIN (y0 + 1, SRC_H - 1);
      double fy = sy - y0;

      for (gint x = 0; x < w; x++)
        {
          double sx = CLAMP ((x + 0.5) / k - 0.5, 0.0, SRC_W - 1.0);
          gint x0 = (gint) sx, x1i = MIN (x0 + 1, SRC_W - 1);
          double fx = sx - x0;
          double top = x1[y0 * SRC_W + x0] * (1 - fx) + x1[y0 * SRC_W + x1i] * fx;
          double bot = x1[y1 * SRC_W + x0] * (1 - fx) + x1[y1 * SRC_W + x1i] * fx;

          out[y * w + x] = (guint8) (top * (1 - fy) + bot * fy + 0.5);
        }
    }
}

static gint
count_pixels (const guint8 *pix, gint w, gint h)
{
  g_autoptr(FpImage) img = image_from (pix, w, h);
  return detect_count (img);
}

static void
print_count (const char *label, gint n)
{
  if (n < 0)
    printf (" %s=err", label);
  else
    printf (" %s=%d", label, n);
}

/* One output line for a frame, given the driver's x3 pixels and its count. */
static void
analyse (gint i, const guint8 *x3, gint n_drv)
{
  gsize len = SRC_W * DRV_ENL * SRC_H * DRV_ENL;
  g_autofree guint8 *x1 = g_malloc (SRC_W * SRC_H);
  g_autofree guint8 *inv = g_malloc (len);
  g_autofree guint8 *big = NULL;

  reduce_x3 (x3, x1);
  for (gsize p = 0; p < len; p++)
    inv[p] = 0xff - x3[p];

  printf ("frame %d:", i);
  print_count ("driver", n_drv);
  print_count ("x1", count_pixels (x1, SRC_W, SRC_H));
  for (gint k = 2; k <= 5; k++)
    {
      char label[4];

      big = g_realloc (big, SRC_W * k * SRC_H * k);
      enlarge (x1, big, k);
      g_snprintf (label, sizeof label, "x%d", k);
      print_count (label, count_pixels (big, SRC_W * k, SRC_H * k));
    }
  print_count ("inv", count_pixels (inv, SRC_W * DRV_ENL, SRC_H * DRV_ENL));
  printf ("\n");
}

/* Offline check of the analysis path: a synthetic whorl with a ridge period of
 * about 9 px at 64 x 80, built at x3 like the driver's output. Opens nothing. */
static int
selftest (void)
{
  gsize len = SRC_W * DRV_ENL * SRC_H * DRV_ENL;
  g_autofree guint8 *x3 = g_malloc (len);
  g_autoptr(FpImage) img = NULL;
  gint w = SRC_W * DRV_ENL, h = SRC_H * DRV_ENL;

  for (gint y = 0; y < h; y++)
    for (gint x = 0; x < w; x++)
      {
        double dx = x - w * 0.45, dy = y - h * 0.55;
        double r = sqrt (dx * dx + dy * dy) + 6.0 * sin (atan2 (dy, dx) * 3.0);

        x3[y * w + x] = (guint8) (128.0 + 100.0 * sin (2.0 * G_PI * r / (9.0 * DRV_ENL)));
      }
  img = image_from (x3, w, h);
  analyse (0, x3, detect_count (img));
  return EXIT_SUCCESS;
}

static gboolean
on_sigint (gpointer user_data)
{
  g_cancellable_cancel (G_CANCELLABLE (user_data));
  return G_SOURCE_CONTINUE;
}

int
main (int argc, char **argv)
{
  g_autoptr(FpContext) ctx = NULL;
  g_autoptr(GCancellable) cancel = g_cancellable_new ();
  g_autoptr(GError) error = NULL;
  GPtrArray *devices;
  FpDevice *dev;
  gint frames;
  gint scored = 0, at_least_10 = 0;

  if (argc > 1 && strcmp (argv[1], "--selftest") == 0)
    return selftest ();
  frames = argc > 1 ? atoi (argv[1]) : 10;
  if (frames < 1 || frames > 50)
    {
      fprintf (stderr, "usage: %s [frames 1..50, default 10 | --selftest]\n", argv[0]);
      return EXIT_FAILURE;
    }
  setvbuf (stdout, NULL, _IOLBF, 0);
  g_unix_signal_add (SIGINT, on_sigint, cancel);

  ctx = fp_context_new ();
  devices = fp_context_get_devices (ctx);
  if (!devices || devices->len != 1)
    {
      fprintf (stderr, "expected exactly one supported device, found %u\n", devices ? devices->len : 0);
      return EXIT_FAILURE;
    }
  dev = g_ptr_array_index (devices, 0);
  if (!fp_device_open_sync (dev, cancel, &error))
    {
      fprintf (stderr, "open failed: %s\n", error->message);
      return EXIT_FAILURE;
    }

  printf ("Counts per frame: driver = libfprint's own pass on the driver's x3 image;\n"
          "x1..x5 = this tool's rescale of the same frame; inv = x3 colours inverted.\n"
          "Bozorth3 needs >= 10 on both prints to score at all.\n");

  for (gint i = 1; i <= frames && !g_cancellable_is_cancelled (cancel); i++)
    {
      g_autoptr(FpImage) img = NULL;
      g_autoptr(GError) cerr = NULL;
      const guint8 *x3;
      gsize len;
      gint n_drv;

      printf ("frame %d/%d: place the finger, lift when asked by the log (arming 0x34)\n", i, frames);
      img = fp_device_capture_sync (dev, TRUE, cancel, &cerr);
      if (!img)
        {
          if (g_error_matches (cerr, FP_DEVICE_RETRY, FP_DEVICE_RETRY_GENERAL))
            {
              printf ("frame %d: driver=0 (no minutiae; libfprint discards the image, nothing to rescale)\n", i);
              scored++;
              continue;
            }
          fprintf (stderr, "frame %d: capture failed: %s\n", i, cerr->message);
          break;
        }

      x3 = fp_image_get_data (img, &len);
      if (fp_image_get_width (img) != SRC_W * DRV_ENL ||
          fp_image_get_height (img) != SRC_H * DRV_ENL ||
          len != (gsize) (SRC_W * DRV_ENL * SRC_H * DRV_ENL))
        {
          fprintf (stderr, "frame %d: unexpected image geometry %ux%u\n", i,
                   fp_image_get_width (img), fp_image_get_height (img));
          break;
        }
      n_drv = fp_image_get_minutiae (img) ? (gint) fp_image_get_minutiae (img)->len : 0;
      scored++;
      if (n_drv >= 10)
        at_least_10++;
      analyse (i, x3, n_drv);
    }

  printf ("summary: %d frame(s) processed, %d with >= 10 minutiae on the driver's image\n",
          scored, at_least_10);

  g_clear_error (&error);
  if (!fp_device_close_sync (dev, NULL, &error))
    {
      fprintf (stderr, "close failed: %s\n", error->message);
      return EXIT_FAILURE;
    }
  return EXIT_SUCCESS;
}
