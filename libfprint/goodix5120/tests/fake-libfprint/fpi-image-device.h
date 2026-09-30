/* Test-only subset of libfprint's internal driver API; never linked into a driver. */
#pragma once

#include <gio/gio.h>

typedef struct _FakeUsb FakeUsb;
typedef struct { guint16 vid, pid; } FpIdEntry;
typedef enum { FP_DEVICE_TYPE_USB } FpDeviceType;
typedef enum { FP_SCAN_TYPE_PRESS } FpScanType;
typedef enum {
  FP_DEVICE_ERROR_GENERAL,
  FP_DEVICE_ERROR_NOT_SUPPORTED,
  FP_DEVICE_ERROR_PROTO,
} FpDeviceError;

#define FP_TYPE_DEVICE (fp_device_get_type ())
G_DECLARE_DERIVABLE_TYPE (FpDevice, fp_device, FP, DEVICE, GObject)
struct _FpDeviceClass {
  GObjectClass parent_class;
  const char *id, *full_name;
  FpDeviceType type;
  const FpIdEntry *id_table;
  FpScanType scan_type;
};

typedef enum {
  FPI_IMAGE_DEVICE_STATE_INACTIVE,
  FPI_IMAGE_DEVICE_STATE_ACTIVATING,
  FPI_IMAGE_DEVICE_STATE_DEACTIVATING,
  FPI_IMAGE_DEVICE_STATE_IDLE,
  FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON,
  FPI_IMAGE_DEVICE_STATE_CAPTURE,
  FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_OFF,
} FpiImageDeviceState;

#define FP_TYPE_IMAGE_DEVICE (fp_image_device_get_type ())
G_DECLARE_DERIVABLE_TYPE (FpImageDevice, fp_image_device, FP, IMAGE_DEVICE, FpDevice)
struct _FpImageDeviceClass {
  FpDeviceClass parent_class;
  gint bz3_threshold, img_width, img_height;
  void (*img_open) (FpImageDevice *);
  void (*img_close) (FpImageDevice *);
  void (*activate) (FpImageDevice *);
  void (*change_state) (FpImageDevice *, FpiImageDeviceState);
  void (*deactivate) (FpImageDevice *);
};

typedef struct _FpImage {
  GObject parent;
  guint width, height;
  guint8 *data;
} FpImage;
typedef GObjectClass FpImageClass;
GType fp_image_get_type (void);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (FpImage, g_object_unref)

FpImage *fp_image_new (gint width, gint height);
FpImage *fpi_image_resize (FpImage *, guint, guint);
GError *fpi_device_error_new_msg (FpDeviceError, const char *, ...) G_GNUC_PRINTF (2, 3);
FakeUsb *fpi_device_get_usb_device (FpDevice *);
void fpi_image_device_open_complete (FpImageDevice *, GError *);
void fpi_image_device_close_complete (FpImageDevice *, GError *);
void fpi_image_device_activate_complete (FpImageDevice *, GError *);
void fpi_image_device_deactivate_complete (FpImageDevice *, GError *);
void fpi_image_device_session_error (FpImageDevice *, GError *);
void fpi_image_device_report_finger_status (FpImageDevice *, gboolean);
void fpi_image_device_image_captured (FpImageDevice *, FpImage *);
