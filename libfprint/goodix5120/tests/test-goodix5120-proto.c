/*
 * Unit tests for goodix5120_proto.c.
 *
 * Every vector here is either copied from the Go reference's tests
 * (internal/proto/packet_test.go, fdt_test.go, internal/image/image_test.go,
 * frame_test.go) or is a byte sequence observed on the wire
 * (docs/protocol.md). Where one is derived instead, the comment says how.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include <string.h>

#include "goodix5120_proto.h"
#include "shared-fixtures.h"

static GByteArray *
hex (const char *s)
{
  GByteArray *out = g_byte_array_new ();

  for (; s[0] && s[1]; s += 2)
    {
      guint8 b;

      while (*s == ' ')
        s++;
      b = (g_ascii_xdigit_value (s[0]) << 4) | g_ascii_xdigit_value (s[1]);
      g_byte_array_append (out, &b, 1);
    }
  return out;
}

#define assert_bytes(arr, want_hex) G_STMT_START {                  \
    g_autoptr(GByteArray) _w = hex (want_hex);                         \
    g_assert_cmpmem ((arr)->data, (arr)->len, _w->data, _w->len);      \
  } G_STMT_END

/* ---- Framing: packet_test.go golden frames ----------------------------- */

static void
test_message_golden (void)
{
  const guint8 one[] = { 0x01 };
  const guint8 ffff[] = { 0xff, 0xff };
  const guint8 twelve[] = { 0x01, 0x02 };
  g_autoptr(GByteArray) a = g5120_message_encode (0x00, NULL, 0, FALSE);
  g_autoptr(GByteArray) b = g5120_message_encode (0xa8, NULL, 0, FALSE);
  g_autoptr(GByteArray) c = g5120_message_encode (0x96, one, 1, FALSE);
  g_autoptr(GByteArray) d = g5120_message_encode (0xa8, ffff, 2, FALSE);
  g_autoptr(GByteArray) e = g5120_message_encode (0xa8, twelve, 2, TRUE);
  g_autoptr(GByteArray) f = g5120_message_encode (0x00, NULL, 0, TRUE);

  assert_bytes (a, "000100a9");        /* nop empty payload */
  assert_bytes (b, "a8010001");        /* firmware_version empty payload */
  assert_bytes (c, "9602000111");      /* one byte payload */
  assert_bytes (d, "a80300ffff01");    /* checksum wraps past 0xff */
  assert_bytes (e, "a80300010288");    /* no checksum mode: literal 0x88 */
  assert_bytes (f, "00010088");
}

static void
test_pack_golden (void)
{
  const guint8 nop[] = { 0x00, 0x01, 0x00, 0xa9 };
  const guint8 dead[] = { 0xde, 0xad, 0xbe, 0xef };
  g_autoptr(GByteArray) a = g5120_pack_encode (0xa0, NULL, 0);
  g_autoptr(GByteArray) b = g5120_pack_encode (0xa0, nop, sizeof (nop));
  g_autoptr(GByteArray) c = g5120_pack_encode (0xb0, dead, sizeof (dead));
  g_autofree guint8 *zeros = g_malloc0 (300);
  g_autoptr(GByteArray) d = g5120_pack_encode (0xb0, zeros, 192);
  g_autoptr(GByteArray) e = g5120_pack_encode (0xa0, zeros, 300);

  assert_bytes (a, "a00000a0");
  assert_bytes (b, "a00400a4000100a9");
  assert_bytes (c, "b00400b4deadbeef");
  /* 192 bytes: checksum (0xb0 + 0xc0) & 0xff = 0x70 */
  g_assert_cmpuint (d->len, ==, 4 + 192);
  g_assert_cmphex (d->data[0], ==, 0xb0);
  g_assert_cmphex (d->data[1], ==, 0xc0);
  g_assert_cmphex (d->data[2], ==, 0x00);
  g_assert_cmphex (d->data[3], ==, 0x70);
  /* 300 bytes: little endian 2c 01, checksum 0xcd */
  g_assert_cmphex (e->data[1], ==, 0x2c);
  g_assert_cmphex (e->data[2], ==, 0x01);
  g_assert_cmphex (e->data[3], ==, 0xcd);
}

static void
test_command_frame (void)
{
  const guint8 zero2[] = { 0x00, 0x00 };
  g_autoptr(GError) error = NULL;
  g_autoptr(GByteArray) f = g5120_command_frame (0xa8, zero2, 2, &error);

  g_assert_no_error (error);
  /* message a8 03 00 00 00 ff (checksum 0xaa - 0xab = 0xff), six bytes, so
   * the pack header is a0 06 00 a6 */
  g_assert_cmpuint (f->len, ==, G5120_USB_PACKET_SIZE);
  g_assert_cmpmem (f->data, 9, ((const guint8[]) { 0xa0, 0x06, 0x00, 0xa6, 0xa8, 0x03, 0x00, 0x00, 0x00 }), 9);
  g_assert_cmphex (f->data[9], ==, 0xff);
  for (guint i = 10; i < f->len; i++)
    g_assert_cmphex (f->data[i], ==, 0x00);
}

static void
test_padding (void)
{
  for (gsize n = 0; n <= 200; n += 7)
    {
      g_autoptr(GByteArray) a = g_byte_array_new ();

      g_byte_array_set_size (a, n);
      if (n > 0)
        memset (a->data, 0x5a, n);
      g5120_pad_to_packet (a);
      g_assert_cmpuint (a->len % G5120_USB_PACKET_SIZE, ==, 0);
      g_assert_cmpuint (a->len, >=, n);
      g_assert_cmpuint (a->len, <, n + G5120_USB_PACKET_SIZE);
      for (gsize i = n; i < a->len; i++)
        g_assert_cmphex (a->data[i], ==, 0);
    }
}

static void
test_round_trip (void)
{
  const gsize sizes[] = { 0, 1, 2, 3, 15, 16, 64, 255, 256, 1024 };

  for (guint nc = 0; nc < 2; nc++)
    for (guint s = 0; s < G_N_ELEMENTS (sizes); s++)
      {
        g_autofree guint8 *payload = g_malloc (sizes[s] + 1);
        g_autoptr(GByteArray) msg = NULL;
        g_autoptr(GByteArray) pack = NULL;
        g_autoptr(GError) error = NULL;
        const guint8 *inner, *got;
        gsize inner_len, got_len;
        guint8 flags, cmd;

        for (gsize i = 0; i < sizes[s]; i++)
          payload[i] = (guint8) (i * 7);

        msg = g5120_message_encode (0xa8, payload, sizes[s], nc);
        pack = g5120_pack_encode (0xa0, msg->data, msg->len);
        g5120_pad_to_packet (pack);   /* decode must ignore padding */

        g_assert_true (g5120_pack_decode (pack->data, pack->len, &flags, &inner, &inner_len, &error));
        g_assert_no_error (error);
        g_assert_cmphex (flags, ==, 0xa0);
        g_assert_true (g5120_message_decode (inner, inner_len, &cmd, &got, &got_len, &error));
        g_assert_no_error (error);
        g_assert_cmphex (cmd, ==, 0xa8);
        g_assert_cmpmem (got, got_len, payload, sizes[s]);
      }
}

/* Replies observed from this device (docs/protocol.md). Their checksums must
 * verify, which is what proves the framing against real hardware. */
static void
test_decode_observed (void)
{
  struct
  {
    const char *msg;
    guint8      cmd;
    gsize       payload_len;
  } cases[] = {
    /* firmware_version reply: GF_ITE_EC_20063\0 */
    { "a81100" "47465f4954455f45435f323030363300" "e2", 0xa8, 16 },
    /* ACKs */
    { "b00300" "a801" "4e", 0xb0, 2 },
    { "b00300" "e401" "12", 0xb0, 2 },
    /* unsolicited FDT-down event on attach */
    { "321100" "02002f001e013801ff00f7003f013401" "73", 0x32, 16 },
  };

  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      g_autoptr(GByteArray) m = hex (cases[i].msg);
      g_autoptr(GByteArray) p = g5120_pack_encode (0xa0, m->data, m->len);
      g_autoptr(GError) error = NULL;
      const guint8 *inner, *payload;
      gsize inner_len, payload_len;
      guint8 flags, cmd;

      g_assert_true (g5120_pack_decode (p->data, p->len, &flags, &inner, &inner_len, &error));
      g_assert_true (g5120_message_decode (inner, inner_len, &cmd, &payload, &payload_len, &error));
      g_assert_no_error (error);
      g_assert_cmphex (cmd, ==, cases[i].cmd);
      g_assert_cmpuint (payload_len, ==, cases[i].payload_len);
    }

  {
    g_autoptr(GByteArray) m = hex ("b00300a8014e");
    const guint8 *payload;
    gsize payload_len;
    guint8 cmd, acked, status;

    g_assert_true (g5120_message_decode (m->data, m->len, &cmd, &payload, &payload_len, NULL));
    g_assert_true (g5120_ack_decode (cmd, payload, payload_len, &acked, &status));
    g_assert_cmphex (acked, ==, 0xa8);
    g_assert_cmphex (status, ==, 0x01);
    /* A data message is not an ACK. */
    g_assert_false (g5120_ack_decode (0xa8, payload, payload_len, &acked, &status));
  }
}

static void
test_decode_errors (void)
{
  g_autoptr(GError) error = NULL;
  const guint8 *p;
  gsize n;
  guint8 f, c;
  const guint8 bad_pack[] = { 0xa0, 0x04, 0x00, 0xa5, 0, 1, 0, 0xa9 };
  const guint8 short_pack[] = { 0xa0, 0x08, 0x00, 0xa8, 0, 1, 0, 0xa9 };
  const guint8 bad_msg[] = { 0xa8, 0x01, 0x00, 0x02 };
  const guint8 trailing_msg[] = { 0xa8, 0x01, 0x00, 0x01, 0x00 };
  const guint8 zero_len_msg[] = { 0xa8, 0x00, 0x00, 0x02 };

  g_assert_false (g5120_pack_decode (bad_pack, 3, &f, &p, &n, &error));
  g_assert_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_SHORT);
  g_clear_error (&error);
  g_assert_false (g5120_pack_decode (bad_pack, sizeof (bad_pack), &f, &p, &n, &error));
  g_assert_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_CHECKSUM);
  g_clear_error (&error);
  g_assert_false (g5120_pack_decode (short_pack, sizeof (short_pack), &f, &p, &n, &error));
  g_assert_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_LENGTH);
  g_clear_error (&error);
  g_assert_false (g5120_message_decode (bad_msg, sizeof (bad_msg), &c, &p, &n, &error));
  g_assert_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_CHECKSUM);
  g_clear_error (&error);
  g_assert_false (g5120_message_decode (trailing_msg, sizeof (trailing_msg), &c, &p, &n, &error));
  g_assert_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_LENGTH);
  g_clear_error (&error);
  g_assert_false (g5120_message_decode (zero_len_msg, sizeof (zero_len_msg), &c, &p, &n, &error));
  g_assert_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_LENGTH);
}

/* ---- The send gate ------------------------------------------------------ */

static void
test_gate_has_no_destructive_opcodes (void)
{
  gsize n;
  const G5120Opcode *t = g5120_opcode_table (&n);

  for (gsize i = 0; i < n; i++)
    {
      g_assert_cmphex (t[i].cmd, !=, 0xe0);   /* preset_psk_write */
      g_assert_cmphex (t[i].cmd, !=, 0xf0);   /* write_firmware */
      g_assert_cmphex (t[i].cmd, !=, 0xb0);   /* ACK is receive-only */
      g_assert_cmpuint (t[i].payload_len, >, 0);
    }

  g_assert_false (g5120_check_send (0xe0, 0, NULL));
  g_assert_false (g5120_check_send (0xe0, 32, NULL));
  g_assert_false (g5120_check_send (0xf0, 0, NULL));
  g_assert_false (g5120_check_send (0xb0, 2, NULL));
  g_assert_false (g5120_check_send (0x00, 0, NULL));  /* nop: never sent to an ITE EC */
  g_assert_null (g5120_command_frame (0xe0, NULL, 0, NULL));
  g_assert_null (g5120_command_frame (0xf0, NULL, 0, NULL));
}

static void
test_gate_refuses_empty_e4 (void)
{
  g_autoptr(GError) error = NULL;
  const guint8 arg[8] = { 0x03, 0x00, 0x02, 0xbb };

  /* The frame that wedged the EC three times (Runs 1, 2, 4). */
  g_assert_null (g5120_command_frame (0xe4, NULL, 0, &error));
  g_assert_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_REFUSED);
  g_assert_true (g5120_check_send (0xe4, sizeof (arg), NULL));
}

static void
test_vendor_init_matches_reference (void)
{
  /* cmd/goodix-probe/vendor.go vendorInit, steps 1..11 (before 0xd0). */
  const guint8 order[] = { 0x96, 0xa8, 0xae, 0xe4, 0xa2, 0x82, 0xa6, 0xa2, 0x70, 0x98, 0x90 };
  gsize n;
  const G5120Step *steps = g5120_vendor_init_pre_tls (&n);

  g_assert_cmpuint (n, ==, G_N_ELEMENTS (order));
  for (gsize i = 0; i < n; i++)
    {
      g_autoptr(GError) error = NULL;
      g_autoptr(GByteArray) f = NULL;

      g_assert_cmphex (steps[i].cmd, ==, order[i]);
      f = g5120_command_frame (steps[i].cmd, steps[i].payload, steps[i].payload_len, &error);
      g_assert_no_error (error);
      g_assert_nonnull (f);
    }

  /* Exact payloads that matter most. */
  g_assert_cmpmem (steps[3].payload, steps[3].payload_len,
                   ((const guint8[]) { 0x03, 0x00, 0x02, 0xbb, 0x00, 0x00, 0x00, 0x00 }), 8);
  g_assert_cmpmem (steps[2].payload, steps[2].payload_len,
                   ((const guint8[]) { 0x55, 0xa2, 0x52, 0x00, 0x00 }), 5);
  g_assert_cmpmem (steps[9].payload, steps[9].payload_len,
                   ((const guint8[]) { 0xc8, 0x0b, 0xbe, 0x00, 0xbc, 0x00, 0xbc, 0x00 }), 8);
  g_assert_true (steps[3].secret_reply);   /* 0xe4: PSK hash */
  g_assert_true (steps[6].secret_reply);   /* 0xa6: OTP */
  g_assert_cmpint (steps[0].reply, ==, G5120_REPLY_NONE);        /* 0x96 */
  g_assert_cmpint (steps[2].reply, ==, G5120_REPLY_DATA);        /* 0xae: no ACK */
  g_assert_cmpint (steps[8].reply, ==, G5120_REPLY_ACK);         /* 0x70: ACK only */

  /* The 0x90 config: 224 bytes whose sum & 0xff == 0xaa (the vendor's own
   * checksum convention, which pins the extraction window), and the prefix
   * the driver log shows. */
  {
    const G5120Step *cfg = &steps[10];
    guint8 sum = 0;

    g_assert_cmpuint (cfg->payload_len, ==, 224);
    for (gsize i = 0; i < cfg->payload_len; i++)
      sum += cfg->payload[i];
    g_assert_cmphex (sum, ==, 0xaa);
    g_assert_cmpmem (cfg->payload, 8, ((const guint8[]) { 0x70, 0x11, 0x60, 0x71, 0x00, 0x71, 0x2c, 0x9d }), 8);
    g_assert_cmphex (cfg->payload[223], ==, 0x15);
  }

  g_assert_cmphex (g5120_step_health_check ()->cmd, ==, 0xa8);
  g_assert_cmphex (g5120_step_request_tls ()->cmd, ==, 0xd0);
  g_assert_cmpint (g5120_step_request_tls ()->reply, ==, G5120_REPLY_TLS);
  g_assert_cmphex (g5120_step_tls_established ()->cmd, ==, 0xd4);
  g_assert_cmpint (g5120_step_tls_established ()->reply, ==, G5120_REPLY_ACK);
  g_assert_cmpmem (g5120_step_get_image ()->payload, 2, ((const guint8[]) { 0x01, 0x00 }), 2);
}

static void
test_tls_frame (void)
{
  g_autoptr(GError) error = NULL;
  /* ServerHelloDone: 16 03 03 00 04 0e 00 00 00 */
  const guint8 shd[] = { 0x16, 0x03, 0x03, 0x00, 0x04, 0x0e, 0x00, 0x00, 0x00 };
  guint8 two[18];
  g_autoptr(GByteArray) f = g5120_tls_frame (shd, sizeof (shd), &error);

  g_assert_no_error (error);
  /* "SENT DATA LEN: 9, 13" in the vendor log: 9-byte record, 13-byte pack */
  g_assert_cmphex (f->data[0], ==, 0xb0);
  g_assert_cmpuint (f->data[1] | (f->data[2] << 8), ==, 9);
  g_assert_cmphex (f->data[3], ==, (0xb0 + 9) & 0xff);
  g_assert_cmpmem (f->data + 4, 9, shd, 9);
  g_assert_cmpuint (f->len, ==, 64);

  /* Half a record, and two records, are both refused. */
  g_assert_null (g5120_tls_frame (shd, sizeof (shd) - 1, &error));
  g_assert_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_REFUSED);
  g_clear_error (&error);
  memcpy (two, shd, 9);
  memcpy (two + 9, shd, 9);
  g_assert_null (g5120_tls_frame (two, sizeof (two), &error));
  g_assert_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_REFUSED);

  g_assert_cmpuint (g5120_tls_record_len (two, sizeof (two)), ==, 9);
  g_assert_cmpuint (g5120_tls_record_len (two, 4), ==, 0);
}

static void
test_tls_frame_validation (void)
{
  const struct { guint8 type, major, minor; gsize body; gboolean valid; } cases[] = {
    { 0x13, 3, 3, 1, FALSE }, { 0x18, 3, 3, 1, FALSE },
    { 0x14, 3, 1, 1, TRUE }, { 0x15, 3, 2, 2, TRUE },
    { 0x16, 3, 3, 18432, TRUE }, { 0x17, 3, 3, 1, TRUE },
    { 0x16, 2, 3, 1, FALSE }, { 0x16, 3, 0, 1, FALSE },
    { 0x16, 3, 4, 1, FALSE }, { 0x16, 3, 255, 1, FALSE },
    { 0x16, 3, 3, 0, FALSE }, { 0x16, 3, 3, 18433, FALSE },
    { 0x16, 3, 3, 65530, FALSE }, { 0x16, 3, 3, 65531, FALSE },
    { 0x16, 3, 3, 65535, FALSE },
  };

  for (gsize i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      g_autoptr(GError) error = NULL;
      g_autofree guint8 *rec = g_malloc0 (5 + cases[i].body);
      g_autoptr(GByteArray) pack = NULL;

      rec[0] = cases[i].type;
      rec[1] = cases[i].major;
      rec[2] = cases[i].minor;
      rec[3] = cases[i].body >> 8;
      rec[4] = cases[i].body & 0xff;
      pack = g5120_tls_frame (rec, 5 + cases[i].body, &error);
      if (cases[i].valid)
        {
          g_assert_no_error (error);
          g_assert_nonnull (pack);
          g_assert_cmpmem (pack->data + 4, 5 + cases[i].body, rec, 5 + cases[i].body);
          g_assert_cmpuint (pack->data[1] | (pack->data[2] << 8), ==, 5 + cases[i].body);
        }
      else
        {
          g_assert_null (pack);
          g_assert_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_REFUSED);
        }
    }
}

/* ---- FDT: fdt_test.go vectors ------------------------------------------- */

static void
test_fdt_arm_vectors (void)
{
  g_autoptr(GKeyFile) c = fixture_load ();
  const char *names[] = { "arm.down", "arm.up", "arm.manual" };
  for (guint i = 0; i < G_N_ELEMENTS (names); i++)
    {
      g_autoptr(GByteArray) thr = fixture_hex (c, names[i], "thresholds");
      g_autoptr(GByteArray) want = fixture_hex (c, names[i], "payload");
      guint8 out[16], cmd = fixture_cmd (c, names[i], "cmd");
      gsize n = g5120_fdt_encode_arm (cmd, thr->data, fixture_uint (c, names[i], "timestamp"), out);
      g_assert_cmpmem (out, n, want->data, want->len);
      g_assert_true (g5120_check_send (cmd, n, NULL));
    }
  g_autoptr(GByteArray) initial = fixture_hex (c, "arm.down", "thresholds");
  g_assert_cmpmem (g5120_fdt_initial_down_thresholds, 6, initial->data, initial->len);
  g_assert_cmpuint (g5120_fdt_encode_arm (0xa8, initial->data, 0, (guint8[16]) { 0 }), ==, 0);
}

static void
test_fdt_event_headers (void)
{
  g_autoptr(GKeyFile) c = fixture_load ();
  g_auto(GStrv) groups = g_key_file_get_groups (c, NULL);
  for (guint i = 0; groups[i]; i++)
    if (g_str_has_prefix (groups[i], "event."))
      {
        g_autoptr(GByteArray) p = fixture_hex (c, groups[i], "payload");
        G5120FdtEvent ev;
        g_assert_true (g5120_fdt_decode_event (fixture_cmd (c, groups[i], "cmd"), p->data, p->len, &ev, NULL));
        g_assert_cmpuint (ev.kind, ==, fixture_uint (c, groups[i], "kind"));
        g_assert_cmpuint (ev.touchflags, ==, p->data[2]);
      }
  for (gsize n = 0; n <= 17; n++)
    if (n != 16)
      {
        G5120FdtEvent ev;
        guint8 zero[17] = { 0 };
        g_assert_false (g5120_fdt_decode_event (0x32, zero, n, &ev, NULL));
      }
}

static void
test_fdt_event_zones (void)
{
  g_autoptr(GKeyFile) c = fixture_load ();
  g_autoptr(GByteArray) p = fixture_hex (c, "event.down-3f", "payload");
  gsize n;
  g_autofree gint *want = fixture_ints (c, "event.down-3f", "zones", &n);
  G5120FdtEvent ev;
  g_assert_true (g5120_fdt_decode_event (0x32, p->data, p->len, &ev, NULL));
  for (guint i = 0; i < n; i++)
    g_assert_cmpuint (ev.zones[i], ==, want[i]);
}

static void
test_fdt_thresholds (void)
{
  g_autoptr(GKeyFile) c = fixture_load ();
  const char *names[] = { "pair.attach-delta27", "pair.attach-delta21" };
  const guint8 deltas[] = { G5120_FDT_DELTA_THIS_DEVICE, G5120_FDT_DELTA_DEFAULT };
  for (guint i = 0; i < G_N_ELEMENTS (names); i++)
    {
      g_autoptr(GByteArray) p = fixture_hex (c, names[i], "event");
      g_autoptr(GByteArray) want = fixture_hex (c, names[i], "thresholds");
      guint8 thr[6];
      G5120FdtEvent ev;
      g_assert_true (g5120_fdt_decode_event (0x32, p->data, p->len, &ev, NULL));
      g5120_fdt_up_thresholds (ev.zones, ev.touchflags, deltas[i], thr);
      g_assert_cmpmem (thr, 6, want->data, want->len);
    }
}

/* Preserve the three-touch derivation chain, with shared literal inputs and
 * independently recorded expected arms instead of a second table in C. */
static void
test_fdt_run22_session (void)
{
  g_autoptr(GKeyFile) c = fixture_load ();
  g_autoptr(GByteArray) baseline = fixture_hex (c, "arm.down", "thresholds");
  guint8 down_thr[6], up_thr[6], arm[16];
  memcpy (down_thr, baseline->data, 6);
  for (guint i = 0; i < 3; i++)
    {
      g_autofree gchar *down_name = g_strdup_printf ("pair.run22-down-%u", i);
      g_autofree gchar *up_name = i < 2 ? g_strdup_printf ("pair.run22-up-%u", i) : g_strdup ("event.run22-final-up");
      g_autoptr(GByteArray) down_ev = fixture_hex (c, down_name, "event");
      g_autoptr(GByteArray) up_ev = fixture_hex (c, up_name, i < 2 ? "event" : "payload");
      g_autoptr(GByteArray) want_up = fixture_hex (c, down_name, "payload");
      G5120FdtEvent ev;
      gsize n = g5120_fdt_encode_arm (0x32, down_thr, 0, arm);
      g_assert_true (g5120_check_send (0x32, n, NULL));
      g_assert_true (g5120_fdt_decode_event (0x32, down_ev->data, down_ev->len, &ev, NULL));
      g_assert_cmpuint (ev.kind, ==, G5120_FDT_EVENT_DOWN);
      g5120_fdt_up_thresholds (ev.zones, ev.touchflags, G5120_FDT_DELTA_THIS_DEVICE, up_thr);
      n = g5120_fdt_encode_arm (0x34, up_thr, 0, arm);
      g_assert_cmpmem (arm, n, want_up->data, want_up->len);
      g_assert_true (g5120_check_send (0x34, n, NULL));
      g_assert_true (g5120_fdt_decode_event (0x34, up_ev->data, up_ev->len, &ev, NULL));
      g_assert_cmpuint (ev.kind, ==, G5120_FDT_EVENT_UP);
      g5120_fdt_down_thresholds (ev.zones, down_thr);
      if (i < 2)
        {
          g_autoptr(GByteArray) want_down = fixture_hex (c, up_name, "thresholds");
          g_assert_cmpmem (down_thr, 6, want_down->data, want_down->len);
        }
    }
}

/* ---- Image: image_test.go / frame_test.go vectors ----------------------- */

static void
test_decode_12bit_vector (void)
{
  const guint8 raw[] = { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc };
  const guint16 want[] = { 0x234, 0x781, 0xc56, 0x9ab };
  guint16 got[4];
  guint8 gray[4];

  g_assert_true (g5120_decode_12bit (raw, sizeof (raw), got, 4, NULL));
  g_assert_cmpmem (got, sizeof (got), want, sizeof (want));
  g5120_samples_to_gray8 (got, 4, gray);
  g_assert_cmpmem (gray, 4, ((const guint8[]) { 0x23, 0x78, 0xc5, 0x9a }), 4);
}

static void
test_decode_12bit_full_range (void)
{
  const guint8 raw[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
  guint16 got[4];
  guint8 gray[4];

  g_assert_true (g5120_decode_12bit (raw, 6, got, 4, NULL));
  g5120_samples_to_gray8 (got, 4, gray);
  for (guint i = 0; i < 4; i++)
    g_assert_cmphex (gray[i], ==, 0xff);
}

/* Expected values are computed by hand: (v - lo) * 255 / (hi - lo), rounded. */
static void
test_stretch_vector (void)
{
  const guint16 samples[] = { 0x234, 0x781, 0xc56, 0x9ab };
  guint8 gray[4];
  guint16 lo = 0, hi = 0;

  /* n = 4 clips nothing: the bounds are the minimum and maximum. */
  g5120_samples_to_gray8_stretched (samples, 4, gray, &lo, &hi);
  g_assert_cmphex (lo, ==, 0x234);
  g_assert_cmphex (hi, ==, 0xc56);
  g_assert_cmpmem (gray, 4, ((const guint8[]) { 0x00, 0x85, 0xff, 0xbc }), 4);
}

static void
test_stretch_clips_outliers (void)
{
  guint16 samples[200];
  guint8 gray[200];
  guint16 lo = 0, hi = 0;

  /* Values 1000..1100 then 1000..1098, with a dead (0) and hot (0xfff) pixel
   * in place of the first 1000 and 1001. 200 samples clip two from each end,
   * so the bounds are 1001 (after 0, 1000) and 1099 (after 0xfff, 1100). */
  for (guint i = 0; i < 200; i++)
    samples[i] = 1000 + (i % 101);
  samples[0] = 0;
  samples[1] = 0xfff;
  g5120_samples_to_gray8_stretched (samples, 200, gray, &lo, &hi);
  g_assert_cmpuint (lo, ==, 1001);
  g_assert_cmpuint (hi, ==, 1099);
  g_assert_cmpuint (gray[0], ==, 0);        /* dead pixel clamps */
  g_assert_cmpuint (gray[1], ==, 255);      /* hot pixel clamps */
  g_assert_cmpuint (gray[2], ==, 3);        /* 1002: (1 * 255 + 49) / 98 */
  g_assert_cmpuint (gray[100], ==, 255);    /* 1100 is above hi */
  g_assert_cmpuint (gray[50], ==, 128);     /* 1050: (49 * 255 + 49) / 98 */
}

static void
test_stretch_flat_frame (void)
{
  guint16 samples[64];
  guint8 gray[64];
  guint16 lo = 0, hi = 0;

  for (guint i = 0; i < 64; i++)
    samples[i] = 0x7a3;
  g5120_samples_to_gray8_stretched (samples, 64, gray, &lo, &hi);
  g_assert_cmphex (lo, ==, 0x7a3);
  g_assert_cmphex (hi, ==, 0x7a3);
  for (guint i = 0; i < 64; i++)
    g_assert_cmphex (gray[i], ==, 0x7a);   /* plain >> 4 fallback */
}

static void
test_decode_12bit_errors (void)
{
  guint16 out[8];
  const guint8 raw[12] = { 0 };

  g_assert_false (g5120_decode_12bit (raw, 5, out, 4, NULL));   /* short */
  g_assert_false (g5120_decode_12bit (raw, 12, out, 3, NULL));  /* not a multiple of 4 */
  g_assert_false (g5120_decode_12bit (raw, 12, out, 0, NULL));
  g_assert_true (g5120_decode_12bit (raw, 6 + 13, out, 4, NULL)); /* trailing bytes tolerated */
}

/* The inverse of the packing, defined only here (as pack12Bit is in the Go
 * test) so the deliberately irregular layout is pinned by a round trip. */
static void
pack12 (const guint16 *s, gsize n, guint8 *out)
{
  for (gsize i = 0, o = 0; i < n; i += 4, o += 6)
    {
      out[o + 0] = ((s[i] >> 8) & 0x0f) | ((s[i + 1] & 0x0f) << 4);
      out[o + 1] = s[i] & 0xff;
      out[o + 2] = s[i + 2] & 0xff;
      out[o + 3] = (s[i + 1] >> 4) & 0xff;
      out[o + 4] = (s[i + 3] >> 4) & 0xff;
      out[o + 5] = ((s[i + 2] >> 8) & 0x0f) | ((s[i + 3] & 0x0f) << 4);
    }
}

static void
test_decode_12bit_round_trip_64x80 (void)
{
  g_autofree guint16 *samples = g_new (guint16, G5120_IMG_SAMPLES);
  g_autofree guint16 *got = g_new (guint16, G5120_IMG_SAMPLES);
  g_autofree guint8 *raw = g_malloc (G5120_IMG_PACKED_LEN);

  g_assert_cmpint (G5120_IMG_WIDTH, ==, 64);
  g_assert_cmpint (G5120_IMG_HEIGHT, ==, 80);
  g_assert_cmpint (G5120_IMG_PACKED_LEN, ==, 7680);
  g_assert_cmpint (G5120_IMG_WRAPPED_LEN, ==, 7693);

  for (gsize i = 0; i < G5120_IMG_SAMPLES; i++)
    samples[i] = (i * 7) & 0x0fff;
  pack12 (samples, G5120_IMG_SAMPLES, raw);
  g_assert_true (g5120_decode_12bit (raw, G5120_IMG_PACKED_LEN, got, G5120_IMG_SAMPLES, NULL));
  g_assert_cmpmem (got, G5120_IMG_SAMPLES * 2, samples, G5120_IMG_SAMPLES * 2);
}

static void
test_frame_layouts (void)
{
  g_autofree guint8 *plain = g_malloc0 (G5120_IMG_WRAPPED_LEN + 64);
  const gsize refused[] = { 0, 7679, 7681, 7692, 7694, 7744 };
  gboolean wrapped;
  const guint8 *s;

  s = g5120_frame_samples (plain, G5120_IMG_WRAPPED_LEN, &wrapped, NULL);
  g_assert_true (s == plain + 8);
  g_assert_true (wrapped);
  s = g5120_frame_samples (plain, G5120_IMG_PACKED_LEN, &wrapped, NULL);
  g_assert_true (s == plain);
  g_assert_false (wrapped);

  for (guint i = 0; i < G_N_ELEMENTS (refused); i++)
    {
      g_autoptr(GError) error = NULL;

      g_assert_null (g5120_frame_samples (plain, refused[i], &wrapped, &error));
      g_assert_error (error, G5120_PROTO_ERROR, G5120_PROTO_ERROR_IMAGE);
    }
}

int
main (int argc, char **argv)
{
  g_test_init (&argc, &argv, NULL);

  g_test_add_func ("/goodix5120/framing/message-golden", test_message_golden);
  g_test_add_func ("/goodix5120/framing/pack-golden", test_pack_golden);
  g_test_add_func ("/goodix5120/framing/command-frame", test_command_frame);
  g_test_add_func ("/goodix5120/framing/padding", test_padding);
  g_test_add_func ("/goodix5120/framing/round-trip", test_round_trip);
  g_test_add_func ("/goodix5120/framing/decode-observed", test_decode_observed);
  g_test_add_func ("/goodix5120/framing/decode-errors", test_decode_errors);
  g_test_add_func ("/goodix5120/gate/no-destructive-opcodes", test_gate_has_no_destructive_opcodes);
  g_test_add_func ("/goodix5120/gate/refuses-empty-e4", test_gate_refuses_empty_e4);
  g_test_add_func ("/goodix5120/gate/vendor-init", test_vendor_init_matches_reference);
  g_test_add_func ("/goodix5120/gate/tls-frame", test_tls_frame);
  g_test_add_func ("/goodix5120/gate/tls-frame-validation", test_tls_frame_validation);
  g_test_add_func ("/goodix5120/fdt/arm-vectors", test_fdt_arm_vectors);
  g_test_add_func ("/goodix5120/fdt/event-headers", test_fdt_event_headers);
  g_test_add_func ("/goodix5120/fdt/event-zones", test_fdt_event_zones);
  g_test_add_func ("/goodix5120/fdt/thresholds", test_fdt_thresholds);
  g_test_add_func ("/goodix5120/fdt/run22-session", test_fdt_run22_session);
  g_test_add_func ("/goodix5120/image/12bit-vector", test_decode_12bit_vector);
  g_test_add_func ("/goodix5120/image/12bit-full-range", test_decode_12bit_full_range);
  g_test_add_func ("/goodix5120/image/12bit-errors", test_decode_12bit_errors);
  g_test_add_func ("/goodix5120/image/stretch-vector", test_stretch_vector);
  g_test_add_func ("/goodix5120/image/stretch-clips-outliers", test_stretch_clips_outliers);
  g_test_add_func ("/goodix5120/image/stretch-flat-frame", test_stretch_flat_frame);
  g_test_add_func ("/goodix5120/image/12bit-round-trip-64x80", test_decode_12bit_round_trip_64x80);
  g_test_add_func ("/goodix5120/image/frame-layouts", test_frame_layouts);

  return g_test_run ();
}
