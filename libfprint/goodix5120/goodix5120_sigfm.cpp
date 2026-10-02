/*
 * Goodix 27c6:5120 driver for libfprint: SIGFM views
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
 */

/*
 * The matcher backend of goodix5120_match.h over the vendored, unmodified
 * SIGFM (sigfm/). Extraction and scoring are SIGFM's own functions; this file
 * only converts a view to and from the template's GVariant, which needs the
 * SigfmImgInfo layout, and keeps C++ exceptions out of the C driver.
 */

#include "goodix5120_match.h"

#include <cmath>
#include <exception>
#include <memory>
#include <vector>

#include "sigfm/img-info.hpp"
#include "sigfm/sigfm.hpp"

struct _G5120View
{
  SigfmImgInfo *info;
};

static G5120View *
view_wrap (SigfmImgInfo *info)
{
  G5120View *view = g_new0 (G5120View, 1);

  view->info = info;
  return view;
}

void
g5120_view_free (G5120View *view)
{
  if (view == nullptr)
    return;
  sigfm_free_info (view->info);
  g_free (view);
}

/* The template stores what SIGFM scores, exactly: CV_32F descriptors of 128
 * whole numbers 0..255 each, and keypoints as integer points inside the image. */
static bool
info_storable (const SigfmImgInfo *info, guint width, guint height, GError **error)
{
  const cv::Mat &d = info->descriptors;
  size_t n = info->keypoints.size ();

  if (n == 0)
    return true;
  if (d.type () != CV_32F || d.cols != G5120_MATCH_DESCRIPTOR || (size_t) d.rows != n)
    {
      g_set_error (error, G5120_MATCH_ERROR, G5120_MATCH_ERROR_EXTRACT,
                   "SIGFM returned %d x %d descriptors of type %d for %zu keypoints",
                   d.rows, d.cols, d.type (), n);
      return false;
    }
  for (int r = 0; r < d.rows; r++)
    for (int c = 0; c < d.cols; c++)
      {
        float v = d.at<float> (r, c);

        if (!(v >= 0.0f && v <= 255.0f) || v != std::floor (v))
          {
            g_set_error (error, G5120_MATCH_ERROR, G5120_MATCH_ERROR_EXTRACT,
                         "SIFT descriptor value %g is not a whole number 0..255", (double) v);
            return false;
          }
      }
  for (const cv::KeyPoint &k : info->keypoints)
    {
      cv::Point2i p = k.pt;

      if (p.x < 0 || p.y < 0 || (guint) p.x >= width || (guint) p.y >= height)
        {
          g_set_error (error, G5120_MATCH_ERROR, G5120_MATCH_ERROR_EXTRACT,
                       "SIFT keypoint (%d, %d) lies outside the %ux%u image", p.x, p.y, width, height);
          return false;
        }
    }
  return true;
}

G5120View *
g5120_view_extract (const guint8 *pixels, guint width, guint height, GError **error)
{
  g_return_val_if_fail (pixels != nullptr && width > 0 && height > 0, nullptr);
  g_return_val_if_fail (width <= G_MAXUINT16 && height <= G_MAXUINT16, nullptr);

  try
    {
      SigfmImgInfo *info = sigfm_extract (pixels, (int) width, (int) height);

      if (!info_storable (info, width, height, error))
        {
          sigfm_free_info (info);
          return nullptr;
        }
      return view_wrap (info);
    }
  catch (const std::exception &e)
    {
      g_set_error (error, G5120_MATCH_ERROR, G5120_MATCH_ERROR_EXTRACT, "SIGFM extraction failed: %s", e.what ());
      return nullptr;
    }
  catch (...)
    {
      g_set_error_literal (error, G5120_MATCH_ERROR, G5120_MATCH_ERROR_EXTRACT, "SIGFM extraction failed");
      return nullptr;
    }
}

guint
g5120_view_keypoints (const G5120View *view)
{
  return view->info->keypoints.size ();
}

gint
g5120_view_score (const G5120View *probe, const G5120View *enrolled)
{
  /* sigfm_match_score catches its own exceptions and returns -1; it takes
   * non-const pointers but does not modify either. */
  try
    {
      return sigfm_match_score (probe->info, enrolled->info);
    }
  catch (...)
    {
      return -1;
    }
}

GVariant *
g5120_view_to_variant (const G5120View *view)
{
  const SigfmImgInfo *info = view->info;
  size_t n = info->keypoints.size ();
  GVariantBuilder points;
  std::vector<guint8> bytes (n * G5120_MATCH_DESCRIPTOR);

  g_variant_builder_init (&points, G_VARIANT_TYPE ("a(qq)"));
  for (size_t i = 0; i < n; i++)
    {
      cv::Point2i p = info->keypoints[i].pt; /* the rounding SIGFM's match uses */

      g_variant_builder_add (&points, "(qq)", (guint16) p.x, (guint16) p.y);
      for (int c = 0; c < G5120_MATCH_DESCRIPTOR; c++)
        bytes[i * G5120_MATCH_DESCRIPTOR + c] = (guint8) info->descriptors.at<float> ((int) i, c);
    }
  return g_variant_new ("(a(qq)@ay)", &points,
                        g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, bytes.data (), bytes.size (), 1));
}

G5120View *
g5120_view_from_variant (GVariant *value, GError **error)
{
  g_return_val_if_fail (g_variant_is_of_type (value, G5120_VIEW_TYPE), nullptr);

  g_autoptr(GVariant) points = g_variant_get_child_value (value, 0);
  g_autoptr(GVariant) descriptors = g_variant_get_child_value (value, 1);
  gsize n = g_variant_n_children (points);
  gsize len = 0;
  const guint8 *bytes = (const guint8 *) g_variant_get_fixed_array (descriptors, &len, 1);

  if (n == 0 || n > G5120_MATCH_MAX_KEYPOINTS || len != n * G5120_MATCH_DESCRIPTOR)
    {
      g_set_error (error, G5120_MATCH_ERROR, G5120_MATCH_ERROR_TEMPLATE,
                   "Not a goodix5120 template: view of %" G_GSIZE_FORMAT " keypoints with %" G_GSIZE_FORMAT
                   " descriptor bytes", n, len);
      return nullptr;
    }

  try
    {
      auto info = std::make_unique<SigfmImgInfo> ();

      info->keypoints.reserve (n);
      info->descriptors.create ((int) n, G5120_MATCH_DESCRIPTOR, CV_32F);
      for (gsize i = 0; i < n; i++)
        {
          guint16 x, y;

          g_variant_get_child (points, i, "(qq)", &x, &y);
          info->keypoints.emplace_back (cv::Point2f (x, y), 1.0f);
          for (int c = 0; c < G5120_MATCH_DESCRIPTOR; c++)
            info->descriptors.at<float> ((int) i, c) = bytes[i * G5120_MATCH_DESCRIPTOR + c];
        }
      return view_wrap (info.release ());
    }
  catch (const std::exception &e)
    {
      g_set_error (error, G5120_MATCH_ERROR, G5120_MATCH_ERROR_TEMPLATE, "Rebuilding a view failed: %s", e.what ());
      return nullptr;
    }
}
