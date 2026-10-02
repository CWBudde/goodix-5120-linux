# Standalone helper and actual-driver lifecycle tests for goodix5120.
#
# This is NOT how the driver is built into libfprint (see README.md and
# libfprint-register.patch); it exists so the framing, the send gate, the FDT
# threshold rules, image decode, TLS server, template format and driver state
# machines can be tested offline, without libfprint and without any device:
#
#   meson setup build-c libfprint/goodix5120 && meson test -C build-c -v
#
# Nothing here opens USB. The lifecycle target compiles goodix5120.c against
# a test-only adapter and a fake SIGFM backend; no GUsb/libusb implementation
# is linked. The real SIGFM backend is tested too when OpenCV 4 is installed.
project('goodix5120-tests', 'c',
  default_options: ['c_std=gnu99', 'warning_level=2', 'werror=true'])

glib_dep = dependency('glib-2.0', version: '>= 2.68')
openssl_dep = dependency('openssl', version: '>= 3.0')
gio_dep = dependency('gio-2.0', version: '>= 2.68')

fixture_dir = join_paths(meson.current_source_dir(), '..', '..', 'internal', 'testfixtures', 'testdata')
fixture_args = ['-DG5120_SHARED_FIXTURE_DIR="' + fixture_dir + '"']
fixture_lib = static_library('g5120fixtures', 'tests/shared-fixtures.c',
  include_directories: include_directories('.'),
  c_args: fixture_args, dependencies: glib_dep)

test('goodix5120-fixtures',
  executable('test-shared-fixtures', 'tests/test-shared-fixtures.c',
    include_directories: include_directories('.'),
    dependencies: glib_dep, link_with: fixture_lib),
  protocol: 'tap', args: ['--tap'])

proto_lib = static_library('g5120proto', 'goodix5120_proto.c',
  dependencies: glib_dep)
tls_lib = static_library('g5120tls', 'goodix5120_tls.c',
  dependencies: [glib_dep, openssl_dep], link_with: proto_lib)

test('goodix5120-shared-protocol',
  executable('test-shared-protocol', 'tests/test-shared-protocol.c',
    include_directories: include_directories('.'),
    dependencies: glib_dep, link_with: [proto_lib, fixture_lib]),
  protocol: 'tap', args: ['--tap'])

test('goodix5120-proto',
  executable('test-goodix5120-proto', 'tests/test-goodix5120-proto.c',
    include_directories: include_directories('.'),
    dependencies: glib_dep, link_with: [proto_lib, fixture_lib]),
  protocol: 'tap', args: ['--tap'])

test('goodix5120-tls',
  executable('test-goodix5120-tls', 'tests/test-goodix5120-tls.c',
    include_directories: include_directories('.'),
    dependencies: [glib_dep, openssl_dep], link_with: [tls_lib, proto_lib]),
  protocol: 'tap', args: ['--tap'])

# Suppress only unused callback arguments, as libfprint's own build does.
test('goodix5120-driver',
  executable('test-goodix5120-driver',
    ['goodix5120.c', 'goodix5120_match.c', 'tests/test-goodix5120-driver.c',
     'tests/fake-libfprint/fake-libfprint.c', 'tests/fake-matcher.c'],
    include_directories: [include_directories('tests/fake-libfprint'), include_directories('.')],
    c_args: ['-Wno-unused-parameter'],
    dependencies: [gio_dep, openssl_dep], link_with: [tls_lib, proto_lib, fixture_lib]),
  protocol: 'tap', args: ['--tap'])

match_lib = static_library('g5120match', 'goodix5120_match.c', dependencies: glib_dep)
fake_matcher_lib = static_library('g5120fakematcher', 'tests/fake-matcher.c',
  include_directories: include_directories('.'), dependencies: glib_dep)

test('goodix5120-match',
  executable('test-goodix5120-match', 'tests/test-goodix5120-match.c',
    include_directories: include_directories('.'),
    dependencies: glib_dep, link_with: [match_lib, fake_matcher_lib]),
  protocol: 'tap', args: ['--tap'])

# The real backend: vendored SIGFM (sigfm/README.md) over OpenCV's SIFT.
opencv_dep = dependency('opencv4', required: false, include_type: 'system')
if opencv_dep.found() and add_languages('cpp', required: false, native: false)
  # The vendored files stay byte-identical, so their warnings are not ours to fix.
  vendored_lib = static_library('sigfmvendored', 'sigfm/sigfm.cpp',
    cpp_args: ['-std=c++17'], override_options: ['werror=false', 'warning_level=0'],
    dependencies: opencv_dep)
  sigfm_lib = static_library('g5120sigfm', 'goodix5120_sigfm.cpp',
    cpp_args: ['-std=c++17'], dependencies: [glib_dep, opencv_dep], link_with: vendored_lib)
  test('goodix5120-sigfm',
    executable('test-goodix5120-sigfm', 'tests/test-goodix5120-sigfm.cpp',
      include_directories: include_directories('.'), cpp_args: ['-std=c++17'],
      dependencies: [glib_dep, opencv_dep], link_with: [match_lib, sigfm_lib]),
    protocol: 'tap', args: ['--tap'], timeout: 120)
endif
