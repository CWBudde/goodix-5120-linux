#!/bin/sh
# Builds the goodix5120 bundle: pinned libfprint with this driver compiled in,
# plus the fprintd installer, the sources and SHA256SUMS.
#
#   SRC=/src LIBFPRINT_SRC=/libfprint OUT=/out VERSION=v0.1.0 sh build-bundle.sh
#
# Runs inside the image from this directory's Dockerfile (`just bundle`, or the
# build-bundle CI workflow). Needs no network: LIBFPRINT_SRC is a libfprint
# checkout at the pinned revision, and neither it nor SRC is written to.
# It runs the driver's offline tests first and refuses a driver that draws
# compiler warnings. Nothing here opens a device.
set -eu

pinned=6f9479c3d55f847c1b3769f28ceb99227f9858cf
src=${SRC:-/src}
upstream=${LIBFPRINT_SRC:-/libfprint}
out=${OUT:-/out}
version=${VERSION:-dev}
driver=$src/libfprint/goodix5120
work=$(mktemp -d)

rev=$(git -C "$upstream" rev-parse HEAD)
[ "$rev" = "$pinned" ] || {
  echo "libfprint is at $rev, want $pinned" >&2
  exit 1
}

echo "== offline tests"
for t in tests tests-asan; do
  opts=
  [ "$t" = tests ] || opts=-Db_sanitize=address,undefined
  meson setup "$work/$t" "$driver" $opts >/dev/null
  meson compile -C "$work/$t" >/dev/null
  rc=0
  ASAN_OPTIONS=detect_leaks=1 meson test -C "$work/$t" --print-errorlogs >"$work/$t.log" 2>&1 || rc=$?
  grep -E '^ *[0-9]+/[0-9]+ |^(Ok|Fail):' "$work/$t.log"
  [ "$rc" = 0 ] || {
    cat "$work/$t.log" >&2
    exit 1
  }
done

echo "== libfprint $pinned with goodix5120"
git -C "$upstream" archive --format=tar --prefix=libfprint/ HEAD | tar -C "$work" -xf -
tree=$work/libfprint
(cd "$tree" && patch -p1 --quiet <"$driver/libfprint-register.patch")
d=$tree/libfprint/drivers/goodix5120
mkdir -p "$d/sigfm"
cp "$driver"/goodix5120*.[ch] "$driver"/goodix5120_sigfm.cpp "$d/"
cp "$driver"/sigfm/sigfm.cpp "$driver"/sigfm/*.hpp "$driver"/sigfm/COPYING "$driver"/sigfm/REVISION "$d/sigfm/"
meson setup "$work/build" "$tree" -Ddrivers=goodix5120 -Dintrospection=false -Ddoc=false \
  -Dudev_rules=disabled -Dudev_hwdb=disabled -Dinstalled-tests=false -Dgtk-examples=false >/dev/null
meson compile -C "$work/build" >"$work/driver-build.log" 2>&1 || {
  tail -50 "$work/driver-build.log" >&2
  exit 1
}
# The vendored sigfm.cpp draws warnings from OpenCV's headers; the driver's own files must draw none.
if grep -E 'drivers/goodix5120/goodix5120[^/:]*:[0-9]+:[0-9]+: warning' "$work/driver-build.log"; then
  echo "the driver draws compiler warnings" >&2
  exit 1
fi

echo "== bundle"
b=$work/build
rm -rf "${out:?}"/*
mkdir -p "$out/examples" "$out/libfprint" "$out/source"
for e in enroll verify identify img-capture; do
  cp "$b/examples/$e" "$out/examples/"
  # shellcheck disable=SC2016 # $ORIGIN is for the dynamic loader, not the shell
  patchelf --set-rpath '$ORIGIN/../libfprint' "$out/examples/$e"
done
for library in "$b"/libfprint/libfprint-2.so*; do
  [ -d "$library" ] || cp -a "$library" "$out/libfprint/"
done
cp "$b/libfprint/fprint-list-supported-devices" "$out/libfprint/"
# shellcheck disable=SC2016
patchelf --set-rpath '$ORIGIN' "$out/libfprint/fprint-list-supported-devices"
"$out/libfprint/fprint-list-supported-devices" >"$out/device-table.txt"
grep -q '27c6:5120' "$out/device-table.txt"

cp "$driver/fprintd/goodix5120-fprintd.sh" "$driver/fprintd/goodix5120-fprintd.pam-config" "$out/"
# LGPL: the sources of the modified library travel with it.
mkdir -p "$out/source/goodix5120"
cp -r "$driver"/goodix5120*.[ch] "$driver"/goodix5120_sigfm.cpp "$driver"/sigfm "$driver"/libfprint-register.patch \
  "$driver"/README.md "$out/source/goodix5120/"
echo "$pinned" >"$out/source/libfprint-revision.txt"
echo "https://gitlab.freedesktop.org/libfprint/libfprint" >>"$out/source/libfprint-revision.txt"

echo "$version" >"$out/VERSION"
pkg-config --modversion glib-2.0 gusb libusb-1.0 openssl pixman-1 opencv4 >"$out/dependencies.txt"
c++ --version | head -1 >"$out/toolchain.txt"
cp "$work/driver-build.log" "$out/"
(cd "$out" && find . -type f | LC_ALL=C sort | xargs sha256sum >"$work/SHA256SUMS")
mv "$work/SHA256SUMS" "$out/SHA256SUMS"
rm -rf "$work"
echo "bundle $version: $out"
