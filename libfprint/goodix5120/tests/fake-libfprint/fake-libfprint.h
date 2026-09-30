#pragma once
#include "drivers_api.h"

typedef void (*FakeStateHook) (FpDevice *, const char *, int, gpointer);
typedef void (*FakeWriteHook) (const guint8 *, gsize, gpointer);
typedef struct {
  guint opens, closes, activations, deactivations, session_errors;
  guint fingers_on, fingers_off, images;
  guint target_images;
  GError *error;
  FpImage *last_image;
  gboolean automatic, processing_done, processing_ready, finger_off, defer_processing;
  FpiImageDeviceState state;
} FakeNotifications;

struct _FakeUsb {
  FpDevice *device;
  FpiUsbTransfer *pending;
  FpiUsbTransferCallback callback;
  gpointer user_data;
  GCancellable *cancel;
  guint timeout;
  guint completions;
  GQueue replies;
  GPtrArray *writes;
  guint claims, releases, claim_flags, release_flags;
  gboolean claimed, claim_fails;
  guint machines;
  FakeNotifications notify;
  FakeStateHook state_hook;
  FakeWriteHook write_hook;
  gpointer hook_data;
};

void fake_attach (FakeUsb *, FpDevice *);
void fake_clear (FakeUsb *);
void fake_change_state (FakeUsb *, FpiImageDeviceState);
void fake_deactivate (FakeUsb *);
void fake_processing_complete (FakeUsb *);
void fake_queue_bytes (FakeUsb *, const guint8 *, gsize);
void fake_queue_error (FakeUsb *, GQuark, gint);
void fake_drop_replies (FakeUsb *);
/* Complete at most one submitted transfer, asynchronously relative to submit. */
gboolean fake_usb_step (FakeUsb *);
void fake_usb_complete (FakeUsb *, const guint8 *, gsize, GError *);
