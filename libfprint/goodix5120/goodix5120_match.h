/*
 * Goodix 27c6:5120 driver for libfprint: SIGFM matching and the stored template
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
 * NBIS finds at most 5 minutiae on this 64 x 80 sensor (Run 37) and Bozorth3
 * needs 10, so the driver matches with SIGFM (sigfm/README.md), which Runs
 * 38-40 measured here: with 14 enrolled views, 14/15 genuine attempts scored
 * at least 3526 at 64 x 80 and 6643 at the driver's 192 x 240, while no
 * attempt with another finger scored above 9 and 2.
 *
 * Two layers. A view is the SIGFM features of one image
 * (goodix5120_sigfm.cpp; the offline driver tests link a fake). A template
 * is the print data libfprint stores, a GVariant of views
 * (goodix5120_match.c), validated in full before any view is rebuilt from it.
 *
 * Plain GLib, no libfprint: errors are in G5120_MATCH_ERROR and the driver
 * maps them to libfprint's.
 */

#pragma once

#include <glib.h>

G_BEGIN_DECLS

/* The goodixtls fork's goodix511 values (a 64 x 80 sensor as well). Run 40
 * had genuine scores >= 3526 and other-finger scores <= 9 at the same size. */
#define G5120_MATCH_THRESHOLD     24
#define G5120_MATCH_MIN_KEYPOINTS 25   /* fewer: ask for another touch */

/* Bounds for stored data. Runs 38/39 had 92-169 keypoints per frame at 192 x 240. */
#define G5120_MATCH_MAX_KEYPOINTS 2048
#define G5120_MATCH_MAX_VIEWS     64
#define G5120_MATCH_DESCRIPTOR    128  /* bytes per SIFT descriptor */

typedef enum {
  G5120_MATCH_ERROR_EXTRACT,      /* the matcher failed on an image */
  G5120_MATCH_ERROR_TEMPLATE,     /* stored data is not a valid template */
} G5120MatchError;

#define G5120_MATCH_ERROR (g5120_match_error_quark ())
GQuark g5120_match_error_quark (void);

/* ---- Views: one image's features (the matcher backend) ------------------- */

typedef struct _G5120View G5120View;

/* (keypoint positions rounded to pixels, descriptors one byte per value).
 * SIGFM uses keypoint positions only as integer points, and OpenCV's SIFT
 * descriptors are whole numbers 0..255, so this loses nothing it scores. */
#define G5120_VIEW_TYPE_STRING "(a(qq)ay)"
#define G5120_VIEW_TYPE        G_VARIANT_TYPE (G5120_VIEW_TYPE_STRING)

G5120View *g5120_view_extract (const guint8 *pixels,
                               guint         width,
                               guint         height,
                               GError      **error);
guint      g5120_view_keypoints (const G5120View *view);
/* SIGFM's score of @probe against @enrolled: higher is more similar, 0 never
 * matches, negative is a matcher failure. */
gint       g5120_view_score (const G5120View *probe,
                             const G5120View *enrolled);
/* A new floating G5120_VIEW_TYPE value. */
GVariant  *g5120_view_to_variant (const G5120View *view);
/* @value has passed g5120_template_parse()'s checks. */
G5120View *g5120_view_from_variant (GVariant *value,
                                    GError  **error);
void       g5120_view_free (G5120View *view);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (G5120View, g5120_view_free)

/* ---- Templates: the stored print data ------------------------------------ */

/* (format version, image width, image height, views). The size is the
 * image the views were extracted from; a template extracted at another size
 * is refused rather than scored against. */
#define G5120_TEMPLATE_VERSION     1
#define G5120_TEMPLATE_TYPE_STRING "(yqqa" G5120_VIEW_TYPE_STRING ")"
#define G5120_TEMPLATE_TYPE        G_VARIANT_TYPE (G5120_TEMPLATE_TYPE_STRING)

/* A new floating template from @views (G5120View *, 1..MAX_VIEWS). */
GVariant  *g5120_template_new (GPtrArray *views,
                               guint      width,
                               guint      height);
/* The views of @value as a new GPtrArray of G5120View * that frees them,
 * or NULL with @error set. */
GPtrArray *g5120_template_parse (GVariant *value,
                                 guint     width,
                                 guint     height,
                                 GError  **error);
/* The highest score of @probe against any of @views; negative only if every
 * comparison failed. *@best_view gets its index when non-NULL. */
gint       g5120_template_best_score (GPtrArray       *views,
                                      const G5120View *probe,
                                      guint           *best_view);

G_END_DECLS
