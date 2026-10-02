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
  FP_DEVICE_ERROR_NOT_OPEN,
  FP_DEVICE_ERROR_ALREADY_OPEN,
  FP_DEVICE_ERROR_BUSY,
  FP_DEVICE_ERROR_PROTO,
  FP_DEVICE_ERROR_DATA_INVALID,
} FpDeviceError;
typedef enum {
  FP_DEVICE_RETRY_GENERAL,
  FP_DEVICE_RETRY_TOO_SHORT,
  FP_DEVICE_RETRY_CENTER_FINGER,
  FP_DEVICE_RETRY_REMOVE_FINGER,
} FpDeviceRetry;
#define FP_DEVICE_ERROR (g_quark_from_static_string ("fake-device-error"))
#define FP_DEVICE_RETRY (g_quark_from_static_string ("fake-device-retry"))
typedef enum {
  FP_FINGER_STATUS_NONE = 0,
  FP_FINGER_STATUS_NEEDED = 1 << 0,
  FP_FINGER_STATUS_PRESENT = 1 << 1,
} FpFingerStatusFlags;
typedef enum {
  FPI_DEVICE_ACTION_NONE,
  FPI_DEVICE_ACTION_PROBE,
  FPI_DEVICE_ACTION_OPEN,
  FPI_DEVICE_ACTION_CLOSE,
  FPI_DEVICE_ACTION_ENROLL,
  FPI_DEVICE_ACTION_VERIFY,
  FPI_DEVICE_ACTION_IDENTIFY,
  FPI_DEVICE_ACTION_CAPTURE,
  FPI_DEVICE_ACTION_LIST,
  FPI_DEVICE_ACTION_DELETE,
  FPI_DEVICE_ACTION_CLEAR_STORAGE,
} FpiDeviceAction;
typedef enum {
  FPI_MATCH_ERROR = -1,
  FPI_MATCH_FAIL,
  FPI_MATCH_SUCCESS,
} FpiMatchResult;
typedef enum {
  FPI_PRINT_UNDEFINED,
  FPI_PRINT_RAW,
  FPI_PRINT_NBIS,
} FpiPrintType;
typedef enum {
  FP_DEVICE_FEATURE_NONE = 0,
  FP_DEVICE_FEATURE_CAPTURE = 1 << 0,
  FP_DEVICE_FEATURE_IDENTIFY = 1 << 1,
  FP_DEVICE_FEATURE_VERIFY = 1 << 2,
  FP_DEVICE_FEATURE_ALWAYS_ON = 1 << 3,
} FpDeviceFeature;

#define FP_TYPE_DEVICE (fp_device_get_type ())
G_DECLARE_DERIVABLE_TYPE (FpDevice, fp_device, FP, DEVICE, GObject)
struct _FpDeviceClass {
  GObjectClass parent_class;
  const char *id, *full_name;
  FpDeviceType type;
  const FpIdEntry *id_table;
  FpScanType scan_type;
  gint nr_enroll_stages;
  gint32 temp_hot_seconds;
  FpDeviceFeature features;
  void (*open) (FpDevice *);
  void (*close) (FpDevice *);
  void (*enroll) (FpDevice *);
  void (*verify) (FpDevice *);
  void (*identify) (FpDevice *);
  void (*capture) (FpDevice *);
  void (*cancel) (FpDevice *);
};

typedef struct _FpImage {
  GObject parent;
  guint width, height;
  guint8 *data;
} FpImage;
typedef GObjectClass FpImageClass;
GType fp_image_get_type (void);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (FpImage, g_object_unref)

/* Only the parts the driver uses: a type and the "fpi-data" property. */
typedef struct _FpPrint {
  GObject parent;
  FpiPrintType type;
  GVariant *data;
} FpPrint;
typedef GObjectClass FpPrintClass;
GType fp_print_get_type (void);
G_DEFINE_AUTOPTR_CLEANUP_FUNC (FpPrint, g_object_unref)
void fpi_print_set_type (FpPrint *, FpiPrintType);

FpImage *fp_image_new (gint width, gint height);
FpImage *fpi_image_resize (FpImage *, guint, guint);
GError *fpi_device_error_new (FpDeviceError);
GError *fpi_device_error_new_msg (FpDeviceError, const char *, ...) G_GNUC_PRINTF (2, 3);
GError *fpi_device_retry_new_msg (FpDeviceRetry, const char *, ...) G_GNUC_PRINTF (2, 3);
FakeUsb *fpi_device_get_usb_device (FpDevice *);
void fpi_device_class_auto_initialize_features (FpDeviceClass *);
FpiDeviceAction fpi_device_get_current_action (FpDevice *);
void fpi_device_get_enroll_data (FpDevice *, FpPrint **);
void fpi_device_get_verify_data (FpDevice *, FpPrint **);
void fpi_device_get_identify_data (FpDevice *, GPtrArray **);
void fpi_device_get_capture_data (FpDevice *, gboolean *);
void fpi_device_action_error (FpDevice *, GError *);
void fpi_device_open_complete (FpDevice *, GError *);
void fpi_device_close_complete (FpDevice *, GError *);
void fpi_device_enroll_progress (FpDevice *, gint, FpPrint *, GError *);
void fpi_device_enroll_complete (FpDevice *, FpPrint *, GError *);
void fpi_device_verify_report (FpDevice *, FpiMatchResult, FpPrint *, GError *);
void fpi_device_verify_complete (FpDevice *, GError *);
void fpi_device_identify_report (FpDevice *, FpPrint *, FpPrint *, GError *);
void fpi_device_identify_complete (FpDevice *, GError *);
void fpi_device_capture_complete (FpDevice *, FpImage *, GError *);
gboolean fpi_device_report_finger_status_changes (FpDevice *, FpFingerStatusFlags, FpFingerStatusFlags);
