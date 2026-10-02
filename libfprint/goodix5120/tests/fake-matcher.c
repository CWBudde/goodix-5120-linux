/* Test-only SIGFM view backend; see fake-matcher.h. */
#include <string.h>
#include "fake-matcher.h"
#include "goodix5120_match.h"

FakeMatcher fake_matcher;

struct _G5120View {
  guint32 digest;
  guint keypoints;
};

void
fake_matcher_reset (void)
{
  g_free (fake_matcher.pixels);
  memset (&fake_matcher, 0, sizeof (fake_matcher));
}

G5120View *
g5120_view_extract (const guint8 *pixels, guint width, guint height, GError **error)
{
  G5120View *view;
  guint32 digest = 2166136261u; /* FNV-1a */

  fake_matcher.extractions++;
  g_free (fake_matcher.pixels);
  fake_matcher.pixels = g_memdup2 (pixels, width * height);
  fake_matcher.width = width;
  fake_matcher.height = height;
  if (fake_matcher.fail_extract)
    {
      fake_matcher.fail_extract--;
      g_set_error_literal (error, G5120_MATCH_ERROR, G5120_MATCH_ERROR_EXTRACT, "synthetic extraction failure");
      return NULL;
    }
  for (guint i = 0; i < width * height; i++)
    digest = (digest ^ pixels[i]) * 16777619u;
  view = g_new0 (G5120View, 1);
  view->digest = digest;
  view->keypoints = FAKE_MATCH_KEYPOINTS;
  if (fake_matcher.low_keypoints)
    {
      fake_matcher.low_keypoints--;
      view->keypoints = 10;
    }
  return view;
}

guint g5120_view_keypoints (const G5120View *view) { return view->keypoints; }

gint
g5120_view_score (const G5120View *probe, const G5120View *enrolled)
{
  return probe->digest == enrolled->digest ? FAKE_MATCH_SCORE : 0;
}

/* Valid G5120_VIEW_TYPE data: keypoints at in-image positions, the digest in
 * the first descriptor's first four bytes. */
GVariant *
g5120_view_to_variant (const G5120View *view)
{
  GVariantBuilder points;
  g_autofree guint8 *bytes = g_malloc0 (view->keypoints * G5120_MATCH_DESCRIPTOR);

  g_variant_builder_init (&points, G_VARIANT_TYPE ("a(qq)"));
  for (guint i = 0; i < view->keypoints; i++)
    g_variant_builder_add (&points, "(qq)", (guint16) i, (guint16) i);
  memcpy (bytes, &view->digest, sizeof (view->digest));
  return g_variant_new ("(a(qq)@ay)", &points,
                        g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, bytes,
                                                   view->keypoints * G5120_MATCH_DESCRIPTOR, 1));
}

G5120View *
g5120_view_from_variant (GVariant *value, GError **error)
{
  g_autoptr(GVariant) points = g_variant_get_child_value (value, 0);
  g_autoptr(GVariant) descriptors = g_variant_get_child_value (value, 1);
  gsize len;
  const guint8 *bytes = g_variant_get_fixed_array (descriptors, &len, 1);
  G5120View *view;

  (void) error;
  /* g5120_template_parse() has checked the shape already. */
  g_assert_cmpuint (len, ==, g_variant_n_children (points) * G5120_MATCH_DESCRIPTOR);
  view = g_new0 (G5120View, 1);
  view->keypoints = g_variant_n_children (points);
  memcpy (&view->digest, bytes, sizeof (view->digest));
  return view;
}

void
g5120_view_free (G5120View *view)
{
  g_free (view);
}
