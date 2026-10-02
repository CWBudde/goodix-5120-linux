# SIGFM (vendored, unmodified)

SIGFM is the SIFT-based fingerprint matcher of the community `goodixtls` libfprint fork
(<https://github.com/goodix-fp-linux-dev/libfprint>, branch `sigfm`, commit in `REVISION`). It is
LGPL-2.1-or-later (`COPYING`), the same licence as libfprint and this driver, and needs OpenCV 4 (SIFT is in the
main `features2d` module since OpenCV 4.4).

These four files are byte-identical to that commit. Runs 38–40 (`docs/protocol.md`) measured this exact code on
this sensor, so do not edit them. Driver-side glue goes in `../goodix5120_sigfm.cpp`.

| File | SHA-256 |
|---|---|
| `sigfm.cpp` | `600cef8290d722928853a6467a85eb52965d1e926a66cc845100359841850807` |
| `sigfm.hpp` | `22a1c107d2c63343b8d08537b9d421eecea606a1f76ba3fd3b22fdb05ba8ccd9` |
| `img-info.hpp` | `ee8db1e003da6312176b560152071fcbbf75304f0a07c8cffabe2cf1d003adc0` |
| `binary.hpp` | `8a352ae6979ec6a713ac5abc2cf4d98a479cd64915fccd9983ff30358c993186` |

Known quirks, kept on purpose because the measured scores depend on them:

- `match::operator<` compares only `p1.y`, so the `std::set` that de-duplicates matches keeps one match per
  probe row.
- `sigfm_deserialize_binary` does not bound its reads. The driver never calls it: templates use the driver's
  own validated GVariant format (`../goodix5120_match.h`).
