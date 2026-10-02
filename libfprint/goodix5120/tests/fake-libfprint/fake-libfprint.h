#pragma once
#include "drivers_api.h"

typedef void (*FakeStateHook) (FpDevice *, const char *, int, gpointer);
typedef void (*FakeWriteHook) (const guint8 *, gsize, gpointer);
typedef struct {
  guint opens, closes;
  guint completions;      /* enroll/verify/identify/capture completions, success or error */
  guint action_errors;    /* of those, completions with an error (cancellation included) */
  guint needed, fingers_on, fingers_off;  /* finger-status changes */
  guint progress, retries;                /* enroll progress reports; reports with a retry error */
  gint stage;                             /* stages completed at the last progress report */
  guint images;                           /* capture completions with an image */
  gboolean reported;                      /* verify/identify result reported */
  FpiMatchResult result;                  /* verify */
  FpPrint *match;                         /* identify (borrowed from the gallery) */
  GError *error;                          /* last error passed to a completion */
  GError *retry;                          /* last retry error passed to a report */
  FpPrint *enrolled;                      /* enroll result */
  FpImage *last_image;                    /* capture result */
} FakeNotifications;

struct _FakeUsb {
  FpDevice *device;
  FpiUsbTransfer *pending;
  FpiUsbTransferCallback callback;
  gpointer user_data;
  GCancellable *cancel;
  guint timeout;
  gint64 next_transfer_delay; /* one-shot allocation/scheduling delay */
  guint completions;
  GQueue replies;
  GPtrArray *writes;
  guint claims, releases, claim_flags, release_flags;
  gboolean claimed, claim_fails;
  gboolean kernel_bound, kernel_detached;
  gboolean release_fails, attach_fails;
  guint machines, machines_started;
  FakeNotifications notify;
  FakeStateHook state_hook;
  FakeWriteHook write_hook;
  gpointer hook_data;
  /* The current action, as libfprint's core holds it. */
  FpiDeviceAction action;
  GCancellable *action_cancel;
  FpPrint *action_print;
  GPtrArray *action_gallery;
  gboolean wait_for_finger;
};

void fake_attach (FakeUsb *, FpDevice *);
void fake_clear (FakeUsb *);
/* Start an action through the driver's class vfunc, as libfprint's core does. */
void fake_open (FakeUsb *);
void fake_close (FakeUsb *);
void fake_enroll (FakeUsb *, FpPrint *);
void fake_verify (FakeUsb *, FpPrint *);
void fake_identify (FakeUsb *, GPtrArray *);
void fake_capture (FakeUsb *, gboolean wait_for_finger);
/* Cancel the action's cancellable and call the driver's cancel vfunc. */
void fake_cancel (FakeUsb *);
void fake_queue_bytes (FakeUsb *, const guint8 *, gsize);
void fake_queue_error (FakeUsb *, GQuark, gint);
void fake_drop_replies (FakeUsb *);
/* Complete at most one submitted transfer, asynchronously relative to submit. */
gboolean fake_usb_step (FakeUsb *);
void fake_usb_complete (FakeUsb *, const guint8 *, gsize, GError *);
void fake_advance_time (gint64);
