#!/bin/sh
# Points the system fprintd at this driver's libfprint build, reversibly.
#
#   sudo ./goodix5120-fprintd.sh install [PSK_FILE]   # from an extracted release bundle
#   sudo ./goodix5120-fprintd.sh uninstall
#   ./goodix5120-fprintd.sh which-bundle              # the bundle install would use (no root, no changes)
#   ./goodix5120-fprintd.sh dropin [UNIT_FILE]        # the drop-in install would write (no root, no changes)
#
# It also runs from the repository (libfprint/goodix5120/fprintd/), where it
# installs the newest bundle in dist/ that `just bundle` built (by the
# modification time of its SHA256SUMS, the file the build writes last);
# BUNDLE= overrides. The PSK comes from PSK_FILE, else PSK=, else the repo's
# captures/; a re-install keeps an existing /etc/goodix5120/psk.bin if none
# is given.
#
# No package is replaced. install copies the bundle's libfprint-2.so to
# /opt/goodix5120/lib, the PSK to /etc/goodix5120/psk.bin (root, 0600), and
# adds a fprintd.service drop-in that loads that library and runs fprintd
# with --no-timeout, so it does not exit after 30 s idle and each prompt does
# not pay for its start again. The installed fprintd 1.94.5 needs 47 libfprint
# symbols; all are in the pinned build.
# uninstall removes the library and the drop-in; the PSK and prints enrolled
# under fprintd (/var/lib/fprint) stay. Owner only: restarting fprintd lets
# it enumerate the reader. Agents do not run this.
#
# If fingerprint login is enabled in PAM (pam-auth-update's fprintd profile),
# install swaps that profile for goodix5120-fprintd: pam_fprintd with three
# tries, skipped for gdm-password. GNOME's unlock screen runs gdm-password and
# gdm-fingerprint side by side; with pam_fprintd in both they race for the
# reader, and when gdm-password wins, its prompt is blocked until pam_fprintd
# times out (seen after a resume). Fedora's gdm-password has no pam_fprintd
# either. uninstall swaps the stock profile back.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)

# newest_bundle DIR prints the goodix5120-* bundle in DIR whose SHA256SUMS is
# newest. Not glob order: the names end in a commit hash, so that order is
# alphabetical, not by age. A directory without SHA256SUMS (an unfinished
# build) is skipped. find -newer compares the full timestamps.
newest_bundle() {
  newest=
  for d in "$1"/goodix5120-*; do
    [ -f "$d/SHA256SUMS" ] || continue
    if [ -z "$newest" ] || [ -n "$(find "$d/SHA256SUMS" -newer "$newest/SHA256SUMS")" ]; then
      newest=$d
    fi
  done
  printf '%s\n' "$newest"
}

# noidle_execstart UNIT_FILE prints the lines that replace the unit's
# ExecStart with the same command plus --no-timeout. It prints nothing, and
# fprintd keeps its idle exit, unless the unit has exactly one plain
# ExecStart=/absolute/path line and that binary knows the flag. The stock
# unit file is read, not `systemctl show`, which would include this drop-in.
noidle_execstart() {
  [ -f "$1" ] || return 0
  [ "$(grep -c '^ExecStart=' "$1")" = 1 ] || return 0
  cmd=$(sed -n 's/^ExecStart=//p' "$1")
  case $cmd in
  /*) ;;
  *) return 0 ;; # a prefix such as - or @, or no path
  esac
  case " $cmd " in
  *" --no-timeout "* | *" -t "*) return 0 ;;
  esac
  bin=${cmd%% *}
  if [ ! -f "$bin" ] || ! grep -q 'no-timeout' "$bin"; then
    return 0
  fi
  printf '%s\n' "# No idle exit: each prompt would otherwise start fprintd again." "ExecStart=" "ExecStart=$cmd --no-timeout"
}

# fprintd_unit prints the path of fprintd.service's unit file, if any.
fprintd_unit() {
  systemctl show --property=FragmentPath --value fprintd.service 2>/dev/null || true
}

# dropin UNIT_FILE prints the fprintd.service drop-in.
dropin() {
  cat <<'EOF'
# goodix5120: fprintd with the 27c6:5120 driver build (goodix5120-fprintd.sh)
[Service]
Environment=LD_LIBRARY_PATH=/opt/goodix5120/lib
Environment=GOODIX5120_PSK_FILE=/etc/goodix5120/psk.bin
Environment=FP_DRIVERS_ALLOWLIST=goodix5120
# Milestones only (no keys, pixels or templates); see the driver README.
Environment=G_MESSAGES_DEBUG=libfprint-goodix5120
UnsetEnvironment=FP_DEBUG_TRANSFER
EOF
  noidle_execstart "$1"
}

if [ -n "${BUNDLE:-}" ]; then
  bundle=$BUNDLE
elif [ -f "$here/libfprint/libfprint-2.so.2.0.0" ]; then
  bundle=$here
else
  bundle=$(newest_bundle "$repo/dist")
fi
psk=${2:-${PSK:-}}
[ -n "$psk" ] || [ ! -f "$repo/captures/goodix-psk.bin" ] || psk=$repo/captures/goodix-psk.bin
lib=/opt/goodix5120/lib
conf=/etc/systemd/system/fprintd.service.d/goodix5120.conf
pamprof=/usr/share/pam-configs/goodix5120-fprintd

# Read-only subcommands: they change nothing, so they run without root.
case ${1:-} in
which-bundle)
  [ -n "$bundle" ] || {
    echo "no bundle in $repo/dist" >&2
    exit 1
  }
  printf '%s\n' "$bundle"
  exit 0
  ;;
dropin)
  dropin "${2:-$(fprintd_unit)}"
  exit 0
  ;;
esac

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
  echo "bundle: $bundle (VERSION $(cat "$bundle/VERSION" 2>/dev/null || echo unknown))"
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
  install -m 644 "$here/goodix5120-fprintd.pam-config" "$pamprof"
  if grep -q 'pam_fprintd\.so' /etc/pam.d/common-auth; then
    pam-auth-update --disable fprintd --enable goodix5120-fprintd
    echo "PAM: fingerprint everywhere except gdm-password (gdm-fingerprint covers the GNOME screens), three tries"
  fi
  unit=$(fprintd_unit)
  dropin "$unit" >"$conf"
  if grep -q '^ExecStart=/' "$conf"; then
    echo "fprintd: $(grep '^ExecStart=/' "$conf" | cut -d= -f2-)"
  else
    echo "note: fprintd keeps its idle exit (no plain ExecStart with --no-timeout in ${unit:-fprintd.service})" >&2
  fi
  ;;
uninstall)
  if [ -f "$pamprof" ]; then
    if grep -q 'service = gdm-password' /etc/pam.d/common-auth; then
      pam-auth-update --remove goodix5120-fprintd --enable fprintd
    else
      pam-auth-update --remove goodix5120-fprintd
    fi
    rm -f "$pamprof"
  fi
  rm -f "$conf"
  rmdir --ignore-fail-on-non-empty "$(dirname "$conf")" 2>/dev/null || true
  rm -rf /opt/goodix5120
  ;;
*)
  echo "usage: sudo $0 install [PSK_FILE] | uninstall; $0 which-bundle | dropin [UNIT_FILE]" >&2
  exit 2
  ;;
esac

systemctl daemon-reload
systemctl stop fprintd.service 2>/dev/null || true # D-Bus starts it again on first use
echo "fprintd ${1}ed; it loads the new setup on next use"
