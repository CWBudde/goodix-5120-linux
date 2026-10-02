/*
 * Goodix 27c6:5120 driver for libfprint: the stored template
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

#include "goodix5120_match.h"

G_DEFINE_QUARK (g5120-match-error-quark, g5120_match_error)

GVariant *
g5120_template_new (GPtrArray *views, guint width, guint height)
{
  GVariantBuilder builder;

  g_return_val_if_fail (views != NULL, NULL);
  g_return_val_if_fail (views->len > 0 && views->len <= G5120_MATCH_MAX_VIEWS, NULL);
  g_return_val_if_fail (width <= G_MAXUINT16 && height <= G_MAXUINT16, NULL);

  g_variant_builder_init (&builder, G_VARIANT_TYPE ("a" G5120_VIEW_TYPE_STRING));
  for (guint i = 0; i < views->len; i++)
    g_variant_builder_add_value (&builder, g5120_view_to_variant (g_ptr_array_index (views, i)));

  return g_variant_new ("(yqq@a" G5120_VIEW_TYPE_STRING ")", G5120_TEMPLATE_VERSION,
                        (guint16) width, (guint16) height, g_variant_builder_end (&builder));
}

static GError *
template_error (const char *format, ...) G_GNUC_PRINTF (1, 2);

static GError *
template_error (const char *format, ...)
{
  g_autofree gchar *message = NULL;
  va_list args;

  va_start (args, format);
  message = g_strdup_vprintf (format, args);
  va_end (args);
  return g_error_new (G5120_MATCH_ERROR, G5120_MATCH_ERROR_TEMPLATE, "Not a goodix5120 template: %s", message);
}

/* Shape checks on one view, before the backend rebuilds anything from it. */
static gboolean
view_shape_ok (GVariant *view, guint width, guint height, guint index, GError **error)
{
  g_autoptr(GVariant) points = g_variant_get_child_value (view, 0);
  g_autoptr(GVariant) descriptors = g_variant_get_child_value (view, 1);
  gsize n = g_variant_n_children (points);
  gsize bytes = g_variant_get_size (descriptors);

  if (n < G5120_MATCH_MIN_KEYPOINTS || n > G5120_MATCH_MAX_KEYPOINTS)
    {
      g_propagate_error (error, template_error ("view %u has %" G_GSIZE_FORMAT " keypoints, outside %u..%u",
                                                index, n, G5120_MATCH_MIN_KEYPOINTS,
                                                G5120_MATCH_MAX_KEYPOINTS));
      return FALSE;
    }
  if (bytes != n * G5120_MATCH_DESCRIPTOR)
    {
      g_propagate_error (error, template_error ("view %u has %" G_GSIZE_FORMAT " descriptor bytes for %"
                                                G_GSIZE_FORMAT " keypoints", index, bytes, n));
      return FALSE;
    }
  for (gsize i = 0; i < n; i++)
    {
      guint16 x, y;

      g_variant_get_child (points, i, "(qq)", &x, &y);
      if (x >= width || y >= height)
        {
          g_propagate_error (error, template_error ("view %u keypoint %" G_GSIZE_FORMAT
                                                    " lies outside the %ux%u image", index, i, width, height));
          return FALSE;
        }
    }
  return TRUE;
}

GPtrArray *
g5120_template_parse (GVariant *value, guint width, guint height, GError **error)
{
  g_autoptr(GVariant) list = NULL;
  g_autoptr(GPtrArray) views = NULL;
  guint8 version;
  guint16 w, h;
  gsize n;

  if (value == NULL)
    {
      g_propagate_error (error, template_error ("no print data"));
      return NULL;
    }
  if (!g_variant_is_of_type (value, G5120_TEMPLATE_TYPE))
    {
      g_propagate_error (error, template_error ("type %s, expected %s",
                                                g_variant_get_type_string (value), G5120_TEMPLATE_TYPE_STRING));
      return NULL;
    }
  /* Stored data comes from a file. GVariant reads malformed serialised data
   * as default values instead of failing, so such data is refused here. */
  if (!g_variant_is_normal_form (value))
    {
      g_propagate_error (error, template_error ("serialised data is not in normal form"));
      return NULL;
    }

  g_variant_get (value, "(yqq@a" G5120_VIEW_TYPE_STRING ")", &version, &w, &h, &list);
  if (version != G5120_TEMPLATE_VERSION)
    {
      g_propagate_error (error, template_error ("format version %u, expected %u", version, G5120_TEMPLATE_VERSION));
      return NULL;
    }
  if (w != width || h != height)
    {
      g_propagate_error (error, template_error ("extracted at %ux%u, this driver uses %ux%u", w, h, width, height));
      return NULL;
    }
  n = g_variant_n_children (list);
  if (n == 0 || n > G5120_MATCH_MAX_VIEWS)
    {
      g_propagate_error (error, template_error ("%" G_GSIZE_FORMAT " views, outside 1..%u", n,
                                                G5120_MATCH_MAX_VIEWS));
      return NULL;
    }

  views = g_ptr_array_new_full (n, (GDestroyNotify) g5120_view_free);
  for (gsize i = 0; i < n; i++)
    {
      g_autoptr(GVariant) view = g_variant_get_child_value (list, i);
      G5120View *rebuilt;

      if (!view_shape_ok (view, width, height, i, error))
        return NULL;
      rebuilt = g5120_view_from_variant (view, error);
      if (rebuilt == NULL)
        return NULL;
      g_ptr_array_add (views, rebuilt);
    }
  return g_steal_pointer (&views);
}

gint
g5120_template_best_score (GPtrArray *views, const G5120View *probe, guint *best_view)
{
  gint best = -1;
  guint index = 0;

  g_return_val_if_fail (views != NULL && probe != NULL, -1);

  for (guint i = 0; i < views->len; i++)
    {
      gint score = g5120_view_score (probe, g_ptr_array_index (views, i));

      if (score > best)
        {
          best = score;
          index = i;
        }
    }
  if (best_view)
    *best_view = index;
  return best;
}
