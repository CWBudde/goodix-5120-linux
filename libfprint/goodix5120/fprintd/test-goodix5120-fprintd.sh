#!/bin/sh
# Offline tests for goodix5120-fprintd.sh: which bundle install picks, and the
# drop-in it writes. Runs the installer's read-only subcommands (which-bundle,
# dropin) against fake repositories and unit files under a temporary
# directory. Needs no root and changes nothing on the system.
set -eu

src=$(cd "$(dirname "$0")" && pwd)/goodix5120-fprintd.sh
tmp=$(mktemp -d "${TMPDIR:-/tmp}/goodix5120-installer-test.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
fails=0

pass() { echo "ok   $1"; }
fail() {
  echo "FAIL $1" >&2
  fails=$((fails + 1))
}

# expect NAME WANT GOT
expect() {
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1: want '$2', got '$3'"; fi
}

# fake_repo NAME: a repository layout with the installer at its usual place.
fake_repo() {
  mkdir -p "$tmp/$1/libfprint/goodix5120/fprintd" "$tmp/$1/dist"
  cp "$src" "$tmp/$1/libfprint/goodix5120/fprintd/"
}

# fake_bundle DIR STAMP: a finished bundle whose SHA256SUMS has mtime STAMP
# (touch -t [[CC]YY]MMDDhhmm[.ss]).
fake_bundle() {
  mkdir -p "$1/libfprint"
  : >"$1/libfprint/libfprint-2.so.2.0.0"
  basename "$1" | sed 's/^goodix5120-//' >"$1/VERSION"
  : >"$1/SHA256SUMS"
  touch -t "$2" "$1/SHA256SUMS"
}

which_bundle() {
  sh "$tmp/$1/libfprint/goodix5120/fprintd/goodix5120-fprintd.sh" which-bundle 2>/dev/null
}

# --- bundle selection

# The case that went wrong: c8e7570 sorts last, 6bfc625 was built last.
fake_repo alpha
fake_bundle "$tmp/alpha/dist/goodix5120-38f52b2" 202610021841.53
fake_bundle "$tmp/alpha/dist/goodix5120-6bfc625" 202610021953.33
fake_bundle "$tmp/alpha/dist/goodix5120-77fd41f" 202610021723.23
fake_bundle "$tmp/alpha/dist/goodix5120-7ada9a7" 202610021805.30
fake_bundle "$tmp/alpha/dist/goodix5120-c8e7570" 202610021930.42
expect "newest, not last in glob order" "$tmp/alpha/dist/goodix5120-6bfc625" "$(BUNDLE='' which_bundle alpha)"

# Only seconds apart, newest last in glob order.
fake_repo seconds
fake_bundle "$tmp/seconds/dist/goodix5120-aaaaaaa" 202610021953.33
fake_bundle "$tmp/seconds/dist/goodix5120-bbbbbbb" 202610021953.34
expect "newest by one second" "$tmp/seconds/dist/goodix5120-bbbbbbb" "$(BUNDLE='' which_bundle seconds)"

# A newer directory without SHA256SUMS is an unfinished build; a newer file is
# no bundle.
fake_repo partial
fake_bundle "$tmp/partial/dist/goodix5120-1111111" 202610021000
mkdir -p "$tmp/partial/dist/goodix5120-2222222/libfprint"
touch -t 202610021100 "$tmp/partial/dist/goodix5120-2222222"
: >"$tmp/partial/dist/goodix5120-3333333.tar.gz"
touch -t 202610021200 "$tmp/partial/dist/goodix5120-3333333.tar.gz"
expect "skips unfinished builds and files" "$tmp/partial/dist/goodix5120-1111111" "$(BUNDLE='' which_bundle partial)"

# The bundle directory's own mtime does not count, only its SHA256SUMS.
fake_repo dirtime
fake_bundle "$tmp/dirtime/dist/goodix5120-old" 202610020900
fake_bundle "$tmp/dirtime/dist/goodix5120-new" 202610021900
touch -t 202610030000 "$tmp/dirtime/dist/goodix5120-old"
expect "ignores the directory mtime" "$tmp/dirtime/dist/goodix5120-new" "$(BUNDLE='' which_bundle dirtime)"

# BUNDLE= wins over dist/.
expect "BUNDLE= overrides" "/some/where" "$(BUNDLE=/some/where which_bundle alpha)"

# Run from an extracted bundle, the script uses that bundle even if a dist/
# sits three levels up.
mkdir -p "$tmp/extracted/a/b"
fake_bundle "$tmp/extracted/dist/goodix5120-zzzzzzz" 202610022359
fake_bundle "$tmp/extracted/a/b/goodix5120-0000000" 202610020000
cp "$src" "$tmp/extracted/a/b/goodix5120-0000000/"
expect "extracted bundle uses itself" "$tmp/extracted/a/b/goodix5120-0000000" \
  "$(BUNDLE='' sh "$tmp/extracted/a/b/goodix5120-0000000/goodix5120-fprintd.sh" which-bundle)"

# No bundle at all: which-bundle fails.
fake_repo empty
if BUNDLE='' which_bundle empty >/dev/null; then fail "empty dist/ fails"; else pass "empty dist/ fails"; fi

# --- the drop-in

# fake_unit NAME EXECSTART-LINES...: a unit file, plus a fake fprintd that knows --no-timeout.
mkdir -p "$tmp/bin"
printf 'Usage: fprintd\n  -t, --no-timeout  Do not exit after unused for a while\n' >"$tmp/bin/fprintd"
printf 'Usage: fprintd\n' >"$tmp/bin/fprintd-old"
fake_unit() {
  u=$tmp/$1.service
  shift
  printf '[Service]\nType=dbus\nBusName=net.reactivated.Fprint\n' >"$u"
  for l in "$@"; do printf '%s\n' "$l" >>"$u"; done
  printf 'ProtectSystem=strict\n' >>"$u"
}
dropin() { sh "$src" dropin "$tmp/$1.service"; }
execstart() { dropin "$1" | grep '^ExecStart=' | tr '\n' '|'; }

fake_unit stock "ExecStart=$tmp/bin/fprintd"
expect "replaces ExecStart with --no-timeout" "ExecStart=|ExecStart=$tmp/bin/fprintd --no-timeout|" "$(execstart stock)"
if dropin stock | grep -q '^Environment=LD_LIBRARY_PATH=/opt/goodix5120/lib$' &&
  dropin stock | grep -q '^UnsetEnvironment=FP_DEBUG_TRANSFER$'; then
  pass "keeps the environment lines"
else
  fail "keeps the environment lines"
fi

fake_unit args "ExecStart=$tmp/bin/fprintd --g-fatal-warnings"
expect "keeps existing arguments" "ExecStart=|ExecStart=$tmp/bin/fprintd --g-fatal-warnings --no-timeout|" "$(execstart args)"

fake_unit already "ExecStart=$tmp/bin/fprintd --no-timeout"
expect "already without timeout: ExecStart left alone" "" "$(execstart already)"

fake_unit oldbin "ExecStart=$tmp/bin/fprintd-old"
expect "binary without the flag: ExecStart left alone" "" "$(execstart oldbin)"

fake_unit missing "ExecStart=$tmp/bin/nonexistent"
expect "missing binary: ExecStart left alone" "" "$(execstart missing)"

fake_unit prefixed "ExecStart=-$tmp/bin/fprintd"
expect "prefixed ExecStart: left alone" "" "$(execstart prefixed)"

fake_unit two "ExecStart=$tmp/bin/fprintd" "ExecStart=$tmp/bin/fprintd"
expect "two ExecStart lines: left alone" "" "$(execstart two)"

fake_unit none
expect "no ExecStart: left alone" "" "$(execstart none)"

expect "no unit file: left alone" "" "$(execstart does-not-exist)"

if [ "$fails" -gt 0 ]; then
  echo "$fails failed" >&2
  exit 1
fi
echo "all passed"
