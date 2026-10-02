/* Test-only stand-in for the SIGFM view backend (goodix5120_sigfm.cpp), so the
 * driver tests need no OpenCV. The template code (goodix5120_match.c) is real. */
#pragma once
#include <glib.h>

/* A view is a digest of the image: identical images score FAKE_MATCH_SCORE,
 * any other pair 0. Real SIGFM is exercised by test-goodix5120-sigfm. */
#define FAKE_MATCH_SCORE     1000
#define FAKE_MATCH_KEYPOINTS 100

typedef struct {
  guint extractions;
  guint low_keypoints;   /* the next N extractions find 10 keypoints */
  guint fail_extract;    /* the next N extractions fail */
  guint width, height;   /* of the last extracted image */
  guint8 *pixels;        /* a copy of it, so tests can check what was matched */
} FakeMatcher;

extern FakeMatcher fake_matcher;
void fake_matcher_reset (void);
