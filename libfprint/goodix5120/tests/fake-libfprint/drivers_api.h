#pragma once
#include "fpi-image-device.h"
#include "fpi-ssm.h"

/* Keep diagnostics nonfatal in tests, including deliberately malformed replies. */
#define fp_dbg(...) g_debug (__VA_ARGS__)
#define fp_info(...) g_debug (__VA_ARGS__)
#define fp_warn(...) g_debug (__VA_ARGS__)
#define FPI_USB_ENDPOINT_IN 0x80
#define FPI_USB_ENDPOINT_OUT 0

typedef enum {
  G_USB_DEVICE_ERROR_TIMED_OUT,
  G_USB_DEVICE_ERROR_NO_DEVICE,
  G_USB_DEVICE_ERROR_FAILED,
} FakeUsbError;
#define G_USB_DEVICE_ERROR (g_quark_from_static_string ("fake-usb-error"))
#define G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER (1 << 0)

typedef struct _FpiUsbTransfer {
  FpDevice *device;
  FpiSsm *ssm;
  gboolean short_is_error;
  guint8 *buffer;
  gssize length, actual_length;
  guint8 endpoint;
  GDestroyNotify free_buffer;
} FpiUsbTransfer;
typedef void (*FpiUsbTransferCallback) (FpiUsbTransfer *, FpDevice *, gpointer, GError *);

FpiUsbTransfer *fpi_usb_transfer_new (FpDevice *);
void fpi_usb_transfer_fill_bulk (FpiUsbTransfer *, guint8, gsize);
void fpi_usb_transfer_fill_bulk_full (FpiUsbTransfer *, guint8, guint8 *, gsize, GDestroyNotify);
void fpi_usb_transfer_submit (FpiUsbTransfer *, guint, GCancellable *, FpiUsbTransferCallback, gpointer);
void fpi_ssm_usb_transfer_cb (FpiUsbTransfer *, FpDevice *, gpointer, GError *);
gboolean g_usb_device_claim_interface (FakeUsb *, guint, guint, GError **);
gboolean g_usb_device_release_interface (FakeUsb *, guint, guint, GError **);

/* Only the standalone test compilation uses virtual time. */
gint64 fake_monotonic_time (void);
#define g_get_monotonic_time fake_monotonic_time
