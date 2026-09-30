/*
 * Test-only libfprint boundary adapter, based on the used API semantics in
 * libfprint 6f9479c3d55f847c1b3769f28ceb99227f9858cf.
 * SSM/image callbacks are synchronous and reentrant. USB completion is explicitly
 * stepped after submission; there is exactly one outstanding transfer.
 */
#include "fake-libfprint.h"
#include <stdarg.h>
#include <string.h>

G_DEFINE_TYPE (FpDevice, fp_device, G_TYPE_OBJECT)
G_DEFINE_TYPE (FpImageDevice, fp_image_device, FP_TYPE_DEVICE)
G_DEFINE_TYPE (FpImage, fp_image, G_TYPE_OBJECT)

static gint64 virtual_time;

static void fp_device_init (FpDevice *dev) { (void) dev; }
static void fp_device_class_init (FpDeviceClass *klass) { (void) klass; }
static void fp_image_device_init (FpImageDevice *dev) { (void) dev; }
static void fp_image_device_class_init (FpImageDeviceClass *klass) { (void) klass; }
static void fp_image_init (FpImage *image) { (void) image; }

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

gint64 fake_monotonic_time (void) { return virtual_time; }

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

GError *
fpi_device_error_new_msg (FpDeviceError code, const char *format, ...)
{
  va_list args;
  GError *error;
  va_start (args, format);
  error = g_error_new_valist (g_quark_from_static_string ("fake-device-error"), code, format, args);
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
  usb->notify.state = FPI_IMAGE_DEVICE_STATE_INACTIVE;
  g_object_set_data (G_OBJECT (dev), "fake-usb", usb);
  virtual_time = 0;
}

void
fake_clear (FakeUsb *usb)
{
  g_assert_null (usb->pending);
  g_assert_cmpuint (usb->machines, ==, 0);
  g_queue_clear_full (&usb->replies, (GDestroyNotify) reply_free);
  g_ptr_array_unref (usb->writes);
  g_clear_error (&usb->notify.error);
  g_clear_object (&usb->notify.last_image);
}

void
fake_drop_replies (FakeUsb *usb)
{
  g_queue_clear_full (&usb->replies, (GDestroyNotify) reply_free);
}

void
fake_change_state (FakeUsb *usb, FpiImageDeviceState state)
{
  usb->notify.state = state;
  FP_IMAGE_DEVICE_GET_CLASS (usb->device)->change_state (FP_IMAGE_DEVICE (usb->device), state);
}

void
fake_deactivate (FakeUsb *usb)
{
  usb->notify.processing_ready = FALSE;
  fake_change_state (usb, FPI_IMAGE_DEVICE_STATE_DEACTIVATING);
  FP_IMAGE_DEVICE_GET_CLASS (usb->device)->deactivate (FP_IMAGE_DEVICE (usb->device));
}

static void
record_error (FakeUsb *usb, GError *error)
{
  if (!error)
    return;
  g_clear_error (&usb->notify.error);
  usb->notify.error = error; /* driver hands off ownership */
}

void
fpi_image_device_open_complete (FpImageDevice *dev, GError *error)
{
  FakeUsb *usb = fpi_device_get_usb_device (FP_DEVICE (dev));
  usb->notify.opens++;
  record_error (usb, error);
}

void
fpi_image_device_close_complete (FpImageDevice *dev, GError *error)
{
  FakeUsb *usb = fpi_device_get_usb_device (FP_DEVICE (dev));
  usb->notify.closes++;
  record_error (usb, error);
}

void
fpi_image_device_activate_complete (FpImageDevice *dev, GError *error)
{
  FakeUsb *usb = fpi_device_get_usb_device (FP_DEVICE (dev));
  usb->notify.activations++;
  record_error (usb, error);
  if (!error && usb->notify.automatic)
    {
      usb->notify.processing_done = usb->notify.processing_ready = usb->notify.finger_off = FALSE;
      fake_change_state (usb, FPI_IMAGE_DEVICE_STATE_IDLE);
      fake_change_state (usb, FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON);
    }
}

void
fpi_image_device_deactivate_complete (FpImageDevice *dev, GError *error)
{
  FakeUsb *usb = fpi_device_get_usb_device (FP_DEVICE (dev));
  usb->notify.deactivations++;
  record_error (usb, error);
  fake_change_state (usb, FPI_IMAGE_DEVICE_STATE_INACTIVE);
}

void
fpi_image_device_session_error (FpImageDevice *dev, GError *error)
{
  FakeUsb *usb = fpi_device_get_usb_device (FP_DEVICE (dev));
  usb->notify.session_errors++;
  record_error (usb, error);
  fake_deactivate (usb);
}

/* Intermediate enrollment stages wait for both image processing and finger-off.
 * Final processing completion deactivates immediately, like upstream. */
static void
maybe_next_stage (FakeUsb *usb)
{
  FakeNotifications *n = &usb->notify;
  if (!n->automatic || !n->processing_done ||
      n->state == FPI_IMAGE_DEVICE_STATE_INACTIVE ||
      n->state == FPI_IMAGE_DEVICE_STATE_DEACTIVATING)
    return;
  if (n->images >= n->target_images)
    fake_deactivate (usb);
  else if (n->finger_off)
    {
      n->processing_done = n->finger_off = FALSE;
      fake_change_state (usb, FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_ON);
    }
}

void
fake_processing_complete (FakeUsb *usb)
{
  usb->notify.processing_ready = FALSE;
  if (usb->notify.state == FPI_IMAGE_DEVICE_STATE_INACTIVE ||
      usb->notify.state == FPI_IMAGE_DEVICE_STATE_DEACTIVATING)
    return;
  usb->notify.processing_done = TRUE;
  maybe_next_stage (usb);
}

void
fpi_image_device_report_finger_status (FpImageDevice *dev, gboolean present)
{
  FakeUsb *usb = fpi_device_get_usb_device (FP_DEVICE (dev));
  if (present)
    {
      usb->notify.fingers_on++;
      if (usb->notify.automatic)
        fake_change_state (usb, FPI_IMAGE_DEVICE_STATE_CAPTURE);
    }
  else
    {
      usb->notify.fingers_off++;
      usb->notify.finger_off = TRUE;
      fake_change_state (usb, FPI_IMAGE_DEVICE_STATE_IDLE);
      maybe_next_stage (usb);
    }
}

void
fpi_image_device_image_captured (FpImageDevice *dev, FpImage *image)
{
  FakeUsb *usb = fpi_device_get_usb_device (FP_DEVICE (dev));
  usb->notify.images++;
  g_clear_object (&usb->notify.last_image);
  usb->notify.last_image = image; /* transfer full */
  if (usb->notify.automatic)
    {
      fake_change_state (usb, FPI_IMAGE_DEVICE_STATE_AWAIT_FINGER_OFF);
      if (!usb->notify.defer_processing)
        usb->notify.processing_ready = TRUE;
    }
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
  FpiUsbTransfer *transfer = g_new0 (FpiUsbTransfer, 1);
  transfer->device = dev;
  return transfer;
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
  t->free_buffer (t->buffer);
  g_free (t);
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
  /* A controllable asynchronous image-processing completion, distinct from USB. */
  if (usb->notify.processing_ready)
    {
      fake_processing_complete (usb);
      return TRUE;
    }
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
