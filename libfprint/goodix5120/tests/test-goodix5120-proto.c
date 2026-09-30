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

/* ---- FDT: fdt_test.go vectors ------------------------------------------- */

static void
test_fdt_arm_vectors (void)
{
  struct
  {
    guint8      cmd;
    const char *want;
    guint8      thr[6];
    guint16     ts;
  } cases[] = {
    { 0x32, "0c0180b880c580ab80b980aa80b9ec5f", { 0xb8, 0xc5, 0xab, 0xb9, 0xaa, 0xb9 }, 0x5fec },
    { 0x34, "0e0180b480aa80808092808a8092", { 0xb4, 0xaa, 0x80, 0x92, 0x8a, 0x92 }, 0 },
    { 0x36, "0d0180b480c380a780b780a680b7", { 0xb4, 0xc3, 0xa7, 0xb7, 0xa6, 0xb7 }, 0 },
  };

  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      g_autoptr(GByteArray) want = hex (cases[i].want);
      guint8 out[16];
      gsize n = g5120_fdt_encode_arm (cases[i].cmd, cases[i].thr, cases[i].ts, out);

      g_assert_cmpmem (out, n, want->data, want->len);
      g_assert_true (g5120_check_send (cases[i].cmd, n, NULL));
    }

  g_assert_cmpuint (g5120_fdt_encode_arm (0xa8, cases[0].thr, 0, (guint8[16]) { 0 }), ==, 0);

  /* The initial down arm is this device's observed baseline, which is the
   * 0x32 vector above. */
  g_assert_cmpmem (g5120_fdt_initial_down_thresholds, 6, cases[0].thr, 6);
}

static void
test_fdt_event_headers (void)
{
  struct
  {
    guint8            cmd;
    const char       *header;
    G5120FdtEventKind want;
  } cases[] = {
    { 0x32, "02003f00", G5120_FDT_EVENT_DOWN },
    { 0x32, "02002f00", G5120_FDT_EVENT_DOWN },
    { 0x32, "02003d00", G5120_FDT_EVENT_DOWN },
    { 0x32, "02003700", G5120_FDT_EVENT_DOWN },
    { 0x32, "80000000", G5120_FDT_EVENT_BASE_INVALID },
    { 0x34, "00020000", G5120_FDT_EVENT_UP },
    { 0x36, "00013f00", G5120_FDT_EVENT_MANUAL },
    { 0x36, "00012f00", G5120_FDT_EVENT_MANUAL },
    { 0x32, "7f7f7f7f", G5120_FDT_EVENT_UNKNOWN },
  };

  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    {
      g_autoptr(GByteArray) p = hex (cases[i].header);
      g_autoptr(GError) error = NULL;
      G5120FdtEvent ev;

      g_byte_array_set_size (p, 16);
      memset (p->data + 4, 0, 12);
      g_assert_true (g5120_fdt_decode_event (cases[i].cmd, p->data, p->len, &ev, &error));
      g_assert_no_error (error);
      g_assert_cmpint (ev.kind, ==, cases[i].want);
      g_assert_cmphex (ev.touchflags, ==, p->data[2]);
    }

  for (gsize n = 0; n <= 17; n++)
    if (n != 16)
      {
        G5120FdtEvent ev;
        g_autofree guint8 *z = g_malloc0 (17);

        g_assert_false (g5120_fdt_decode_event (0x32, z, n, &ev, NULL));
      }
}

static void
test_fdt_event_zones (void)
{
  g_autoptr(GByteArray) p = hex ("02003f00" "1e01" "3801" "ff00" "f700" "3f01" "3401");
  const guint16 want[6] = { 0x011e, 0x0138, 0x00ff, 0x00f7, 0x013f, 0x0134 };
  G5120FdtEvent ev;

  g_assert_true (g5120_fdt_decode_event (0x32, p->data, p->len, &ev, NULL));
  g_assert_cmpmem (ev.zones, sizeof (ev.zones), want, sizeof (want));
}

/* Threshold derivation. The rules are Phase 5d facts (dump.pcapng + vendor
 * log); the expected values are computed by hand from those rules for the
 * unsolicited down event this device sent on attach:
 *   32 11 00 | 02 00 2f 00 1e 01 38 01 ff 00 f7 00 3f 01 34 01 | 73
 * touchflags 0x2f = zones 0,1,2,3,5 touched, zone 4 not. */
static void
test_fdt_thresholds (void)
{
  const guint16 down[6] = { 0x011e, 0x0138, 0x00ff, 0x00f7, 0x013f, 0x0134 };
  /* reading >> 1, plus 27 when touched, 0x19 when not */
  const guint8 want_up[6] = { 0x8f + 27, 0x9c + 27, 0x7f + 27, 0x7b + 27, 0x19, 0x9a + 27 };
  const guint8 want_up_default[6] = { 0x8f + 21, 0x9c + 21, 0x7f + 21, 0x7b + 21, 0x19, 0x9a + 21 };
  /* Down thresholds are no-finger readings >> 1. Readings of exactly twice
   * the observed baseline give the baseline back. */
  const guint16 nofinger[6] = { 0xb8 * 2, 0xc5 * 2 + 1, 0xab * 2, 0xb9 * 2 + 1, 0xaa * 2, 0xb9 * 2 };
  const guint16 huge[6] = { 0xffff, 0x200, 0x1ff, 0, 1, 2 };
  const guint16 huge_up[6] = { 0x1ff, 0x1c8, 0, 0, 0, 0 };
  guint8 thr[6];

  g5120_fdt_up_thresholds (down, 0x2f, G5120_FDT_DELTA_THIS_DEVICE, thr);
  g_assert_cmpmem (thr, 6, want_up, 6);
  g5120_fdt_up_thresholds (down, 0x2f, G5120_FDT_DELTA_DEFAULT, thr);
  g_assert_cmpmem (thr, 6, want_up_default, 6);
  g5120_fdt_up_thresholds (down, 0x00, G5120_FDT_DELTA_THIS_DEVICE, thr);
  for (guint i = 0; i < 6; i++)
    g_assert_cmphex (thr[i], ==, 0x19);

  g5120_fdt_down_thresholds (nofinger, thr);
  g_assert_cmpmem (thr, 6, g5120_fdt_initial_down_thresholds, 6);

  /* Clamping: a threshold is one byte on the wire. */
  g5120_fdt_down_thresholds (huge, thr);
  g_assert_cmpmem (thr, 6, ((const guint8[]) { 0xff, 0xff, 0xff, 0, 0, 1 }), 6);
  g5120_fdt_up_thresholds (huge_up, 0x03, 27, thr);
  g_assert_cmphex (thr[0], ==, 0xff);   /* 0xff + 27 clamps */
  g_assert_cmphex (thr[1], ==, 0xff);   /* 0xe4 + 27 clamps */
}

/* Run 22 (docs/protocol.md): three touches in one TLS session, driven by the
 * Go probe. The capture loop here must send the same arms from the same
 * events: the first down arm is the baseline, each up arm comes from the
 * down event before it, and each later down arm from the lift before it.
 * The events are rebuilt from the logged flags and readings (header, then
 * six little-endian readings); the arms are the thresholds the EC accepted. */
static GByteArray *
fdt_event_bytes (guint8 b0, guint8 b1, guint8 flags, const guint16 *readings)
{
  GByteArray *p = g_byte_array_new ();
  const guint8 header[4] = { b0, b1, flags, 0x00 };

  g_byte_array_append (p, header, sizeof (header));
  for (guint i = 0; i < G5120_FDT_ZONES; i++)
    {
      const guint8 le[2] = { readings[i] & 0xff, readings[i] >> 8 };

      g_byte_array_append (p, le, sizeof (le));
    }
  return p;
}

static void
test_fdt_run22_session (void)
{
  struct
  {
    guint8      flags;
    guint16     down[6];
    const char *up_arm;
    guint16     up[6];
    const char *next_down;
  } touches[] = {
    { 0x3d, { 318, 361, 231, 251, 210, 291 }, "0e0180ba8019808e8098808480ac",
      { 370, 396, 344, 373, 343, 373 }, "b9c6acbaabba" },
    { 0x3d, { 328, 363, 209, 254, 247, 259 }, "0e0180bf80198083809a8096809c",
      { 368, 395, 342, 371, 340, 371 }, "b8c5abb9aab9" },
    { 0x3f, { 262, 283, 267, 275, 236, 267 }, "0e01809e80a880a080a4809180a0",
      { 369, 396, 344, 373, 341, 372 }, NULL },
  };
  guint8 down_thr[6], up_thr[6];

  memcpy (down_thr, g5120_fdt_initial_down_thresholds, sizeof (down_thr));
  g_assert_cmpmem (down_thr, 6, ((const guint8[]) { 0xb8, 0xc5, 0xab, 0xb9, 0xaa, 0xb9 }), 6);

  for (guint i = 0; i < G_N_ELEMENTS (touches); i++)
    {
      g_autoptr(GByteArray) down_ev = fdt_event_bytes (0x02, 0x00, touches[i].flags, touches[i].down);
      g_autoptr(GByteArray) up_ev = fdt_event_bytes (0x00, 0x02, 0x00, touches[i].up);
      g_autoptr(GByteArray) want_up = hex (touches[i].up_arm);
      guint8 arm[16];
      G5120FdtEvent ev;
      gsize n;

      /* The down arm goes out; the EC answers with a finger-down event. */
      n = g5120_fdt_encode_arm (G5120_CMD_FDT_DOWN, down_thr, 0, arm);
      g_assert_true (g5120_check_send (G5120_CMD_FDT_DOWN, n, NULL));
      g_assert_true (g5120_fdt_decode_event (G5120_CMD_FDT_DOWN, down_ev->data, down_ev->len, &ev, NULL));
      g_assert_cmpint (ev.kind, ==, G5120_FDT_EVENT_DOWN);
      g_assert_cmphex (ev.touchflags, ==, touches[i].flags);

      /* The up arm: reading >> 1 + 27 where flagged, 0x19 where not. */
      g5120_fdt_up_thresholds (ev.zones, ev.touchflags, G5120_FDT_DELTA_THIS_DEVICE, up_thr);
      n = g5120_fdt_encode_arm (G5120_CMD_FDT_UP, up_thr, 0, arm);
      g_assert_cmpmem (arm, n, want_up->data, want_up->len);
      g_assert_true (g5120_check_send (G5120_CMD_FDT_UP, n, NULL));

      /* The lift; the next down arm is its readings >> 1. */
      g_assert_true (g5120_fdt_decode_event (G5120_CMD_FDT_UP, up_ev->data, up_ev->len, &ev, NULL));
      g_assert_cmpint (ev.kind, ==, G5120_FDT_EVENT_UP);
      g5120_fdt_down_thresholds (ev.zones, down_thr);
      if (touches[i].next_down)
        {
          g_autoptr(GByteArray) want_down = hex (touches[i].next_down);

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
  g_test_add_func ("/goodix5120/fdt/arm-vectors", test_fdt_arm_vectors);
  g_test_add_func ("/goodix5120/fdt/event-headers", test_fdt_event_headers);
  g_test_add_func ("/goodix5120/fdt/event-zones", test_fdt_event_zones);
  g_test_add_func ("/goodix5120/fdt/thresholds", test_fdt_thresholds);
  g_test_add_func ("/goodix5120/fdt/run22-session", test_fdt_run22_session);
  g_test_add_func ("/goodix5120/image/12bit-vector", test_decode_12bit_vector);
  g_test_add_func ("/goodix5120/image/12bit-full-range", test_decode_12bit_full_range);
  g_test_add_func ("/goodix5120/image/12bit-errors", test_decode_12bit_errors);
  g_test_add_func ("/goodix5120/image/12bit-round-trip-64x80", test_decode_12bit_round_trip_64x80);
  g_test_add_func ("/goodix5120/image/frame-layouts", test_frame_layouts);

  return g_test_run ();
}
