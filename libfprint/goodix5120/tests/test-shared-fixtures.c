#include "shared-fixtures.h"

static void
test_broken_corpus (void)
{
  const char *cases[] = {
    "", "cmd=a8\n", "[health]\ncmd=a8\n[health]\ncmd=a8\n",
    "[health]\ncmd=a8\ncmd=96\n", "[health]\ncmd\n", "[health]\ncmd=a8\n",
    "[arm.down]\ncmd=32\nthresholds=123\ntimestamp=0\npayload=00\n",
    "[arm.down]\ncmd=32\nthresholds=zz\ntimestamp=0\npayload=00\n",
    "[arm.down]\ncmd=32\nthresholds=010203040506\ntimestamp=oops\npayload=00\n",
    "[unknown]\nx=1\n",
  };
  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      g_autoptr(GError) error = NULL;
      g_autoptr(GKeyFile) c = fixture_parse (cases[i], &error);
      g_assert_null (c);
      g_assert_nonnull (error);
    }
}

static void
test_complete_corpus (void)
{
  g_autoptr(GKeyFile) c = fixture_load ();
  g_autoptr(GByteArray) config = fixture_hex (c, "init.10", "payload");
  g_assert_cmpuint (config->len, ==, 224);
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);
  g_test_add_func ("/goodix5120/fixtures/reject-broken", test_broken_corpus);
  g_test_add_func ("/goodix5120/fixtures/complete", test_complete_corpus);
  return g_test_run ();
}
