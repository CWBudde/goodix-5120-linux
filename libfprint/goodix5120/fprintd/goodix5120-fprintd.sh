#!/bin/sh
# Points the system fprintd at this driver's libfprint build, reversibly.
#
#   sudo ./goodix5120-fprintd.sh install [PSK_FILE]   # from an extracted release bundle
#   sudo ./goodix5120-fprintd.sh uninstall
#
# It also runs from the repository (libfprint/goodix5120/fprintd/), where it
# installs the bundle in dist/ that `just bundle` built; BUNDLE= overrides.
# The PSK comes from PSK_FILE, else PSK=, else the repo's captures/; a
# re-install keeps an existing /etc/goodix5120/psk.bin if none is given.
#
# No package is replaced. install copies the bundle's libfprint-2.so to
# /opt/goodix5120/lib, the PSK to /etc/goodix5120/psk.bin (root, 0600), and
# adds a fprintd.service drop-in that loads that library. The installed
# fprintd 1.94.5 needs 47 libfprint symbols; all are in the pinned build.
# uninstall removes the library and the drop-in; the PSK and prints enrolled
# under fprintd (/var/lib/fprint) stay. Owner only: restarting fprintd lets
# it enumerate the reader. Agents do not run this.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
if [ -n "${BUNDLE:-}" ]; then
  bundle=$BUNDLE
elif [ -f "$here/libfprint/libfprint-2.so.2.0.0" ]; then
  bundle=$here
else
  # The last bundle `just bundle` left in dist/, in glob order.
  bundle=
  for d in "$repo"/dist/goodix5120-*; do
    [ -d "$d" ] && bundle=$d
  done
fi
psk=${2:-${PSK:-}}
[ -n "$psk" ] || [ ! -f "$repo/captures/goodix-psk.bin" ] || psk=$repo/captures/goodix-psk.bin
lib=/opt/goodix5120/lib
conf=/etc/systemd/system/fprintd.service.d/goodix5120.conf

[ "$(id -u)" = 0 ] || {
  echo "run with sudo" >&2
  exit 1
}

case ${1:-} in
install)
  [ -n "$bundle" ] && [ -f "$bundle/libfprint/libfprint-2.so.2.0.0" ] || {
    echo "no bundle at ${bundle:-dist/}" >&2
    exit 1
  }
  if [ -n "$psk" ]; then
    [ "$(stat -c %s "$psk")" = 32 ] || {
      echo "$psk is not a 32-byte PSK" >&2
      exit 1
    }
  elif [ ! -f /etc/goodix5120/psk.bin ]; then
    echo "no PSK: give the 32-byte key file, e.g. $0 install psk.bin" >&2
    exit 1
  fi
  (cd "$bundle" && sha256sum --quiet -c SHA256SUMS)
  install -d -m 755 "$lib"
  install -m 644 "$bundle/libfprint/libfprint-2.so.2.0.0" "$lib/"
  ln -sf libfprint-2.so.2.0.0 "$lib/libfprint-2.so.2"
  install -d -m 700 /etc/goodix5120
  [ -z "$psk" ] || install -m 600 "$psk" /etc/goodix5120/psk.bin
  install -d -m 755 "$(dirname "$conf")"
  cat >"$conf" <<'EOF'
# goodix5120: fprintd with the 27c6:5120 driver build (goodix5120-fprintd.sh)
[Service]
Environment=LD_LIBRARY_PATH=/opt/goodix5120/lib
Environment=GOODIX5120_PSK_FILE=/etc/goodix5120/psk.bin
Environment=FP_DRIVERS_ALLOWLIST=goodix5120
# Milestones only (no keys, pixels or templates); see the driver README.
Environment=G_MESSAGES_DEBUG=libfprint-goodix5120
UnsetEnvironment=FP_DEBUG_TRANSFER
EOF
  ;;
uninstall)
  rm -f "$conf"
  rmdir --ignore-fail-on-non-empty "$(dirname "$conf")" 2>/dev/null || true
  rm -rf /opt/goodix5120
  ;;
*)
  echo "usage: sudo $0 install [PSK_FILE] | uninstall" >&2
  exit 2
  ;;
esac

systemctl daemon-reload
systemctl stop fprintd.service 2>/dev/null || true # D-Bus starts it again on first use
echo "fprintd ${1}ed; it loads the new setup on next use"
