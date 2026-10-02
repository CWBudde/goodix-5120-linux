/*
 * Test-only libfprint boundary adapter, based on the used API semantics in
 * libfprint 6f9479c3d55f847c1b3769f28ceb99227f9858cf.
 * SSM and action callbacks are synchronous and reentrant. USB completion is explicitly
 * stepped after submission; there is exactly one outstanding transfer.
 */
#include "fake-libfprint.h"
#include <stdarg.h>
#include <string.h>

G_DEFINE_TYPE (FpDevice, fp_device, G_TYPE_OBJECT)
G_DEFINE_TYPE (FpImage, fp_image, G_TYPE_OBJECT)
G_DEFINE_TYPE (FpPrint, fp_print, G_TYPE_OBJECT)

static gint64 virtual_time;

static void fp_device_init (FpDevice *dev) { (void) dev; }
static void fp_device_class_init (FpDeviceClass *klass) { (void) klass; }
static void fp_image_init (FpImage *image) { (void) image; }
static void fp_print_init (FpPrint *print) { (void) print; }

static void
image_finalize (GObject *object)
{
  FpImage *image = (FpImage *) object;
  memset (image->data, 0, image->width * image->height);
  g_free (image->data);
  G_OBJECT_CLASS (fp_image_parent_class)->finalize (object);
}

static void
fp_image_class_init (FpImageClass *klass)
{
  klass->finalize = image_finalize;
}

enum { PRINT_PROP_0, PRINT_PROP_DATA };

static void
print_set_property (GObject *object, guint id, const GValue *value, GParamSpec *pspec)
{
  FpPrint *print = (FpPrint *) object;
  g_assert_cmpuint (id, ==, PRINT_PROP_DATA);
  (void) pspec;
  g_clear_pointer (&print->data, g_variant_unref);
  print->data = g_value_dup_variant (value);
}

static void
print_get_property (GObject *object, guint id, GValue *value, GParamSpec *pspec)
{
  FpPrint *print = (FpPrint *) object;
  g_assert_cmpuint (id, ==, PRINT_PROP_DATA);
  (void) pspec;
  g_value_set_variant (value, print->data);
}

static void
print_finalize (GObject *object)
{
  g_clear_pointer (&((FpPrint *) object)->data, g_variant_unref);
  G_OBJECT_CLASS (fp_print_parent_class)->finalize (object);
}

static void
fp_print_class_init (FpPrintClass *klass)
{
  klass->set_property = print_set_property;
  klass->get_property = print_get_property;
  klass->finalize = print_finalize;
  g_object_class_install_property (klass, PRINT_PROP_DATA,
                                   g_param_spec_variant ("fpi-data", NULL, NULL, G_VARIANT_TYPE_ANY, NULL,
                                                         G_PARAM_READWRITE));
}

void
fpi_print_set_type (FpPrint *print, FpiPrintType type)
{
  print->type = type;
}

gint64 fake_monotonic_time (void) { return virtual_time; }
void fake_advance_time (gint64 usec) { virtual_time += usec; }

FpImage *
fp_image_new (gint width, gint height)
{
  FpImage *image = g_object_new (fp_image_get_type (), NULL);
  image->width = width;
  image->height = height;
  image->data = g_malloc0 (width * height);
  return image;
}

/* Ownership and dimensions only: deliberately not a substitute for Pixman/NBIS.
 * Nearest-neighbour keeps synthetic sample checks simple; production uses bilinear. */
FpImage *
fpi_image_resize (FpImage *image, guint x, guint y)
{
  FpImage *out = fp_image_new (image->width * x, image->height * y);
  for (guint row = 0; row < out->height; row++)
    for (guint col = 0; col < out->width; col++)
      out->data[row * out->width + col] = image->data[(row / y) * image->width + col / x];
  return out;
}

static GError *
error_new_valist (GQuark domain, gint code, const char *format, va_list args) G_GNUC_PRINTF (3, 0);

static GError *
error_new_valist (GQuark domain, gint code, const char *format, va_list args)
{
  return g_error_new_valist (domain, code, format, args);
}

GError *
fpi_device_error_new (FpDeviceError code)
{
  return g_error_new (FP_DEVICE_ERROR, code, "device error %d", code);
}

GError *
fpi_device_error_new_msg (FpDeviceError code, const char *format, ...)
{
  va_list args;
  GError *error;
  va_start (args, format);
  error = error_new_valist (FP_DEVICE_ERROR, code, format, args);
  va_end (args);
  return error;
}

GError *
fpi_device_retry_new_msg (FpDeviceRetry code, const char *format, ...)
{
  va_list args;
  GError *error;
  va_start (args, format);
  error = error_new_valist (FP_DEVICE_RETRY, code, format, args);
  va_end (args);
  return error;
}

FakeUsb *
fpi_device_get_usb_device (FpDevice *dev)
{
  FakeUsb *usb = g_object_get_data (G_OBJECT (dev), "fake-usb");
  g_assert_nonnull (usb);
  return usb;
}

typedef struct {
  GBytes *bytes;
  GError *error;
} Reply;

static void
reply_free (Reply *reply)
{
  g_clear_pointer (&reply->bytes, g_bytes_unref);
  g_clear_error (&reply->error);
  g_free (reply);
}

void
fake_attach (FakeUsb *usb, FpDevice *dev)
{
  usb->device = dev;
  usb->writes = g_ptr_array_new_with_free_func ((GDestroyNotify) g_bytes_unref);
  g_object_set_data (G_OBJECT (dev), "fake-usb", usb);
  virtual_time = 0;
}

static void
action_clear (FakeUsb *usb)
{
  usb->action = FPI_DEVICE_ACTION_NONE;
  g_clear_object (&usb->action_cancel);
  g_clear_object (&usb->action_print);
  g_clear_pointer (&usb->action_gallery, g_ptr_array_unref);
}

void
fake_clear (FakeUsb *usb)
{
  g_assert_null (usb->pending);
  g_assert_cmpuint (usb->machines, ==, 0);
  g_assert_cmpint (usb->action, ==, FPI_DEVICE_ACTION_NONE);
  action_clear (usb);
  g_queue_clear_full (&usb->replies, (GDestroyNotify) reply_free);
  g_ptr_array_unref (usb->writes);
  g_clear_error (&usb->notify.error);
  g_clear_error (&usb->notify.retry);
  g_clear_object (&usb->notify.last_image);
  g_clear_object (&usb->notify.enrolled);
}

void
fake_drop_replies (FakeUsb *usb)
{
  g_queue_clear_full (&usb->replies, (GDestroyNotify) reply_free);
}

/* libfprint's core: one action at a time, each with its own cancellable. */
static FpDeviceClass *
action_start (FakeUsb *usb, FpiDeviceAction action)
{
  g_assert_cmpint (usb->action, ==, FPI_DEVICE_ACTION_NONE);
  usb->action = action;
  usb->action_cancel = g_cancellable_new ();
  usb->notify.reported = FALSE;
  usb->notify.match = NULL;
  return FP_DEVICE_GET_CLASS (usb->device);
}

void fake_open (FakeUsb *usb) { action_start (usb, FPI_DEVICE_ACTION_OPEN)->open (usb->device); }
void fake_close (FakeUsb *usb) { action_start (usb, FPI_DEVICE_ACTION_CLOSE)->close (usb->device); }

void
fake_enroll (FakeUsb *usb, FpPrint *print)
{
  FpDeviceClass *cls = action_start (usb, FPI_DEVICE_ACTION_ENROLL);
  usb->action_print = g_object_ref (print);
  cls->enroll (usb->device);
}

void
fake_verify (FakeUsb *usb, FpPrint *print)
{
  FpDeviceClass *cls = action_start (usb, FPI_DEVICE_ACTION_VERIFY);
  usb->action_print = g_object_ref (print);
  cls->verify (usb->device);
}

void
fake_identify (FakeUsb *usb, GPtrArray *gallery)
{
  FpDeviceClass *cls = action_start (usb, FPI_DEVICE_ACTION_IDENTIFY);
  usb->action_gallery = g_ptr_array_ref (gallery);
  cls->identify (usb->device);
}

void
fake_capture (FakeUsb *usb, gboolean wait_for_finger)
{
  FpDeviceClass *cls = action_start (usb, FPI_DEVICE_ACTION_CAPTURE);
  usb->wait_for_finger = wait_for_finger;
  cls->capture (usb->device);
}

/* Upstream calls the cancel vfunc from an idle source after the cancellable
 * fires, and only while the action is still running. */
void
fake_cancel (FakeUsb *usb)
{
  g_assert_cmpint (usb->action, !=, FPI_DEVICE_ACTION_NONE);
  g_cancellable_cancel (usb->action_cancel);
  FP_DEVICE_GET_CLASS (usb->device)->cancel (usb->device);
}

void
fpi_device_class_auto_initialize_features (FpDeviceClass *cls)
{
  if (cls->capture)
    cls->features |= FP_DEVICE_FEATURE_CAPTURE;
  if (cls->identify)
    cls->features |= FP_DEVICE_FEATURE_IDENTIFY;
  if (cls->verify)
    cls->features |= FP_DEVICE_FEATURE_VERIFY;
  if (cls->temp_hot_seconds < 0)
    cls->features |= FP_DEVICE_FEATURE_ALWAYS_ON;
}

FpiDeviceAction
fpi_device_get_current_action (FpDevice *dev)
{
  return fpi_device_get_usb_device (dev)->action;
}

void
fpi_device_get_enroll_data (FpDevice *dev, FpPrint **print)
{
  FakeUsb *usb = fpi_device_get_usb_device (dev);
  g_assert_cmpint (usb->action, ==, FPI_DEVICE_ACTION_ENROLL);
  *print = usb->action_print;
}

void
fpi_device_get_verify_data (FpDevice *dev, FpPrint **print)
{
  FakeUsb *usb = fpi_device_get_usb_device (dev);
  g_assert_cmpint (usb->action, ==, FPI_DEVICE_ACTION_VERIFY);
  *print = usb->action_print;
}

void
fpi_device_get_identify_data (FpDevice *dev, GPtrArray **prints)
{
  FakeUsb *usb = fpi_device_get_usb_device (dev);
  g_assert_cmpint (usb->action, ==, FPI_DEVICE_ACTION_IDENTIFY);
  *prints = usb->action_gallery;
}

void
fpi_device_get_capture_data (FpDevice *dev, gboolean *wait_for_finger)
{
  FakeUsb *usb = fpi_device_get_usb_device (dev);
  g_assert_cmpint (usb->action, ==, FPI_DEVICE_ACTION_CAPTURE);
  *wait_for_finger = usb->wait_for_finger;
}

static void
record_error (FakeUsb *usb, GError *error)
{
  if (!error)
    return;
  g_clear_error (&usb->notify.error);
  usb->notify.error = error; /* driver hands off ownership */
}

/* Ends the current action, which must be @action. */
static FakeUsb *
action_end (FpDevice *dev, FpiDeviceAction action, GError *error)
{
  FakeUsb *usb = fpi_device_get_usb_device (dev);
  g_assert_cmpint (usb->action, ==, action);
  /* Upstream rejects a retry error in a completion (it must go to a report). */
  g_assert_true (error == NULL || error->domain != FP_DEVICE_RETRY);
  if (action != FPI_DEVICE_ACTION_OPEN && action != FPI_DEVICE_ACTION_CLOSE)
    {
      usb->notify.completions++;
      if (error)
        usb->notify.action_errors++;
    }
  record_error (usb, error);
  action_clear (usb);
  return usb;
}

void
fpi_device_open_complete (FpDevice *dev, GError *error)
{
  action_end (dev, FPI_DEVICE_ACTION_OPEN, error)->notify.opens++;
}

void
fpi_device_close_complete (FpDevice *dev, GError *error)
{
  action_end (dev, FPI_DEVICE_ACTION_CLOSE, error)->notify.closes++;
}

void
fpi_device_action_error (FpDevice *dev, GError *error)
{
  g_assert_nonnull (error);
  action_end (dev, fpi_device_get_usb_device (dev)->action, error);
}

void
fpi_device_enroll_progress (FpDevice *dev, gint stages, FpPrint *print, GError *error)
{
  FakeUsb *usb = fpi_device_get_usb_device (dev);
  g_assert_cmpint (usb->action, ==, FPI_DEVICE_ACTION_ENROLL);
  g_assert_null (print);
  g_assert_true (error == NULL || error->domain == FP_DEVICE_RETRY);
  usb->notify.progress++;
  usb->notify.stage = stages;
  if (error)
    {
      usb->notify.retries++;
      g_clear_error (&usb->notify.retry);
      usb->notify.retry = error;
    }
}

void
fpi_device_enroll_complete (FpDevice *dev, FpPrint *print, GError *error)
{
  FakeUsb *usb = fpi_device_get_usb_device (dev);
  g_assert_true ((print == NULL) != (error == NULL));
  if (print)
    {
      g_assert_cmpint (print->type, !=, FPI_PRINT_UNDEFINED);
      g_clear_object (&usb->notify.enrolled);
      usb->notify.enrolled = print; /* transfer full */
    }
  action_end (dev, FPI_DEVICE_ACTION_ENROLL, error);
}

static void
report (FakeUsb *usb, FpPrint *print, GError *error)
{
  g_assert_false (usb->notify.reported);
  g_assert_null (print);
  g_assert_true (error == NULL || error->domain == FP_DEVICE_RETRY);
  usb->notify.reported = TRUE;
  if (error)
    {
      g_clear_error (&usb->notify.retry);
      usb->notify.retry = error;
    }
}

void
fpi_device_verify_report (FpDevice *dev, FpiMatchResult result, FpPrint *print, GError *error)
{
  FakeUsb *usb = fpi_device_get_usb_device (dev);
  g_assert_cmpint (usb->action, ==, FPI_DEVICE_ACTION_VERIFY);
  g_assert_true ((result == FPI_MATCH_ERROR) == (error != NULL));
  report (usb, print, error);
  usb->notify.result = result;
}

void
fpi_device_verify_complete (FpDevice *dev, GError *error)
{
  FakeUsb *usb = fpi_device_get_usb_device (dev);
  /* Upstream reports a general error for success without an earlier result. */
  g_assert_true (error != NULL || usb->notify.reported);
  action_end (dev, FPI_DEVICE_ACTION_VERIFY, error);
}

void
fpi_device_identify_report (FpDevice *dev, FpPrint *match, FpPrint *print, GError *error)
{
  FakeUsb *usb = fpi_device_get_usb_device (dev);
  g_assert_cmpint (usb->action, ==, FPI_DEVICE_ACTION_IDENTIFY);
  g_assert_true (match == NULL || error == NULL);
  g_assert_true (match == NULL || g_ptr_array_find (usb->action_gallery, match, NULL));
  report (usb, print, error);
  usb->notify.match = match;
}

void
fpi_device_identify_complete (FpDevice *dev, GError *error)
{
  FakeUsb *usb = fpi_device_get_usb_device (dev);
  g_assert_true (error != NULL || usb->notify.reported);
  action_end (dev, FPI_DEVICE_ACTION_IDENTIFY, error);
}

void
fpi_device_capture_complete (FpDevice *dev, FpImage *image, GError *error)
{
  FakeUsb *usb = fpi_device_get_usb_device (dev);
  g_assert_true ((image == NULL) != (error == NULL));
  if (image)
    {
      usb->notify.images++;
      g_clear_object (&usb->notify.last_image);
      usb->notify.last_image = image; /* transfer full */
    }
  action_end (dev, FPI_DEVICE_ACTION_CAPTURE, error);
}

gboolean
fpi_device_report_finger_status_changes (FpDevice *dev, FpFingerStatusFlags added, FpFingerStatusFlags removed)
{
  FakeUsb *usb = fpi_device_get_usb_device (dev);
  g_assert_cmpint (usb->action, >=, FPI_DEVICE_ACTION_ENROLL);
  if (added & FP_FINGER_STATUS_NEEDED)
    usb->notify.needed++;
  if (added & FP_FINGER_STATUS_PRESENT)
    usb->notify.fingers_on++;
  if (removed & FP_FINGER_STATUS_PRESENT)
    usb->notify.fingers_off++;
  return TRUE;
}

struct _FpiSsm {
  FpDevice *dev; /* borrowed, as upstream */
  FpiSsmHandlerCallback handler;
  FpiSsmCompletedCallback done;
  FpiSsm *parent;
  const char *name;
  int state, states;
};

FpiSsm *
fake_ssm_new (FpDevice *dev, FpiSsmHandlerCallback handler, int states, const char *name)
{
  FpiSsm *ssm = g_new0 (FpiSsm, 1);
  ssm->dev = dev;
  ssm->handler = handler;
  ssm->states = states;
  ssm->name = name;
  fpi_device_get_usb_device (dev)->machines++;
  fpi_device_get_usb_device (dev)->machines_started++;
  return ssm;
}

static void
ssm_call (FpiSsm *ssm)
{
  FakeUsb *usb = fpi_device_get_usb_device (ssm->dev);
  if (usb->state_hook)
    usb->state_hook (ssm->dev, ssm->name, ssm->state, usb->hook_data);
  ssm->handler (ssm, ssm->dev);
}

void
fpi_ssm_start (FpiSsm *ssm, FpiSsmCompletedCallback done)
{
  ssm->done = done;
  ssm_call (ssm);
}

static void
subsm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  (void) dev;
  if (error)
    fpi_ssm_mark_failed (ssm->parent, error);
  else
    fpi_ssm_next_state (ssm->parent);
}

void
fpi_ssm_start_subsm (FpiSsm *parent, FpiSsm *child)
{
  child->parent = parent;
  fpi_ssm_start (child, subsm_done);
}

static void
ssm_finish (FpiSsm *ssm, GError *error)
{
  /* Upstream invokes completion before freeing, with an owned error copy. */
  FakeUsb *usb = fpi_device_get_usb_device (ssm->dev);
  if (ssm->done)
    ssm->done (ssm, ssm->dev, error ? g_error_copy (error) : NULL);
  g_clear_error (&error);
  usb->machines--;
  g_free (ssm);
}

void fpi_ssm_mark_completed (FpiSsm *ssm) { ssm_finish (ssm, NULL); }
void fpi_ssm_mark_failed (FpiSsm *ssm, GError *error) { ssm_finish (ssm, error); }
int fpi_ssm_get_cur_state (FpiSsm *ssm) { return ssm->state; }

void
fpi_ssm_next_state (FpiSsm *ssm)
{
  if (++ssm->state == ssm->states)
    fpi_ssm_mark_completed (ssm);
  else
    ssm_call (ssm);
}

void
fpi_ssm_jump_to_state (FpiSsm *ssm, int state)
{
  g_assert_cmpint (state, >=, 0);
  g_assert_cmpint (state, <, ssm->states);
  ssm->state = state;
  ssm_call (ssm);
}

FpiUsbTransfer *
fpi_usb_transfer_new (FpDevice *dev)
{
  FakeUsb *usb = fpi_device_get_usb_device (dev);
  FpiUsbTransfer *transfer = g_new0 (FpiUsbTransfer, 1);

  fake_advance_time (usb->next_transfer_delay);
  usb->next_transfer_delay = 0;
  transfer->device = dev;
  return transfer;
}

void
fpi_usb_transfer_unref (FpiUsbTransfer *transfer)
{
  if (transfer->free_buffer)
    transfer->free_buffer (transfer->buffer);
  g_free (transfer);
}

void
fpi_usb_transfer_fill_bulk_full (FpiUsbTransfer *t, guint8 endpoint, guint8 *buffer,
                                gsize length, GDestroyNotify free_buffer)
{
  t->endpoint = endpoint;
  t->buffer = buffer;
  t->length = length;
  t->free_buffer = free_buffer;
}

void
fpi_usb_transfer_fill_bulk (FpiUsbTransfer *t, guint8 endpoint, gsize length)
{
  fpi_usb_transfer_fill_bulk_full (t, endpoint, g_malloc0 (length), length, g_free);
}

void
fpi_usb_transfer_submit (FpiUsbTransfer *t, guint timeout, GCancellable *cancel,
                         FpiUsbTransferCallback callback, gpointer user_data)
{
  FakeUsb *usb = fpi_device_get_usb_device (t->device);
  g_assert_null (usb->pending); /* half duplex, including submission from callbacks */
  g_assert_true (usb->claimed);
  usb->pending = t;
  usb->timeout = timeout;
  usb->callback = callback;
  usb->user_data = user_data;
  usb->cancel = cancel ? g_object_ref (cancel) : NULL;
  if (!(t->endpoint & FPI_USB_ENDPOINT_IN))
    g_ptr_array_add (usb->writes, g_bytes_new (t->buffer, t->length));
}

void
fake_usb_complete (FakeUsb *usb, const guint8 *bytes, gsize len, GError *error)
{
  FpiUsbTransfer *t = usb->pending;
  FpiUsbTransferCallback callback = usb->callback;
  gpointer user_data = usb->user_data;
  g_assert_nonnull (t);
  g_assert_cmpuint (len, <=, t->length);
  usb->pending = NULL;
  usb->completions++;
  usb->callback = NULL;
  g_clear_object (&usb->cancel);
  if (!error && t->short_is_error && len > 0 && len < (gsize) t->length)
    error = g_error_new_literal (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_FAILED, "short transfer");
  t->actual_length = error ? -1 : (gssize) len;
  if (!error && (t->endpoint & FPI_USB_ENDPOINT_IN) && len)
    memcpy (t->buffer, bytes, len);
  if (!error && !(t->endpoint & FPI_USB_ENDPOINT_IN) && usb->write_hook)
    usb->write_hook (t->buffer, len, usb->hook_data);
  /* Callback may synchronously submit the next transfer and free its SSM. */
  callback (t, t->device, user_data, error);
  fpi_usb_transfer_unref (t);
}

void
fake_queue_bytes (FakeUsb *usb, const guint8 *bytes, gsize len)
{
  Reply *reply = g_new0 (Reply, 1);
  reply->bytes = g_bytes_new (bytes, len);
  g_queue_push_tail (&usb->replies, reply);
}

void
fake_queue_error (FakeUsb *usb, GQuark domain, gint code)
{
  Reply *reply = g_new0 (Reply, 1);
  reply->error = g_error_new_literal (domain, code, "injected transfer error");
  g_queue_push_tail (&usb->replies, reply);
}

gboolean
fake_usb_step (FakeUsb *usb)
{
  FpiUsbTransfer *t = usb->pending;
  Reply *reply;
  if (!t)
    return FALSE;
  if (usb->cancel && g_cancellable_is_cancelled (usb->cancel))
    {
      fake_usb_complete (usb, NULL, 0, g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED, "cancelled"));
      return TRUE;
    }
  if (!(t->endpoint & FPI_USB_ENDPOINT_IN))
    {
      fake_usb_complete (usb, NULL, t->length, NULL);
      return TRUE;
    }
  reply = g_queue_pop_head (&usb->replies);
  if (reply)
    {
      gsize len = 0;
      const guint8 *bytes = reply->bytes ? g_bytes_get_data (reply->bytes, &len) : NULL;
      fake_usb_complete (usb, bytes, len, g_steal_pointer (&reply->error));
      reply_free (reply);
      return TRUE;
    }
  if (!usb->timeout)
    return FALSE; /* held indefinite FDT read */
  virtual_time += (gint64) usb->timeout * 1000;
  fake_usb_complete (usb, NULL, 0,
                     g_error_new_literal (G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_TIMED_OUT, "timeout"));
  return TRUE;
}

void
fpi_ssm_usb_transfer_cb (FpiUsbTransfer *t, FpDevice *dev, gpointer unused, GError *error)
{
  (void) dev;
  (void) unused;
  if (error)
    fpi_ssm_mark_failed (t->ssm, error);
  else
    fpi_ssm_next_state (t->ssm);
}

gboolean
g_usb_device_claim_interface (FakeUsb *usb, guint interface, guint flags, GError **error)
{
  g_assert_cmpuint (interface, ==, 1);
  usb->claims++;
  usb->claim_flags = flags;
  /* GUsb detaches before claiming, with no rollback when claim fails. */
  if ((flags & G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER) && usb->kernel_bound)
    {
      usb->kernel_bound = FALSE;
      usb->kernel_detached = TRUE;
    }
  if (usb->claim_fails)
    {
      g_set_error_literal (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_FAILED, "claim failed");
      return FALSE;
    }
  g_assert_false (usb->claimed);
  usb->claimed = TRUE;
  return TRUE;
}

gboolean
g_usb_device_release_interface (FakeUsb *usb, guint interface, guint flags, GError **error)
{
  g_assert_cmpuint (interface, ==, 1);
  usb->releases++;
  usb->release_flags = flags;
  if (!usb->claimed)
    {
      g_set_error_literal (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_FAILED, "not claimed");
      return FALSE;
    }
  if (usb->release_fails)
    {
      g_set_error_literal (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_FAILED, "release failed");
      return FALSE;
    }
  usb->claimed = FALSE;
  if (flags & G_USB_DEVICE_CLAIM_INTERFACE_BIND_KERNEL_DRIVER)
    {
      if (usb->attach_fails)
        {
          g_set_error_literal (error, G_USB_DEVICE_ERROR, G_USB_DEVICE_ERROR_FAILED, "attach failed");
          return FALSE;
        }
      if (usb->kernel_detached)
        {
          usb->kernel_bound = TRUE;
          usb->kernel_detached = FALSE;
        }
    }
  return TRUE;
}
