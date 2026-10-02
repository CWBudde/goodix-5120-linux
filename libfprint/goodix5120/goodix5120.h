/*
 * Goodix 27c6:5120 (behind an ITE embedded controller) driver for libfprint
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#pragma once

#include "fpi-device.h"
#include "fpi-ssm.h"

/* A plain FpDevice, not an FpImageDevice: libfprint's image-device class
 * matches with NBIS, which cannot work on this sensor (Run 37), so the driver
 * runs its own enroll/verify/identify loop and matches with SIGFM
 * (goodix5120_match.h). Capture still returns the image. */
G_DECLARE_FINAL_TYPE (FpiDeviceGoodix5120, fpi_device_goodix5120, FPI,
                      DEVICE_GOODIX5120, FpDevice)

/* USB: interface 1 is the CDC-Data interface with the bulk pair. */
#define G5120_INTERFACE 1
#define G5120_EP_IN     (FPI_USB_ENDPOINT_IN | 0x03)
#define G5120_EP_OUT    (FPI_USB_ENDPOINT_OUT | 0x01)
/* Ceiling on one IN transfer; an image pack is 7753 bytes. */
#define G5120_IN_BUF_SIZE 0x10000

/* Timeouts, in milliseconds. */
#define G5120_TIMEOUT_REPLY      2000  /* an ACK or a data reply */
#define G5120_TIMEOUT_QUIET       200  /* "nothing more is coming" */
#define G5120_TIMEOUT_OUT        2000  /* complete padded OUT frame, across its 64-byte writes */
#define G5120_TIMEOUT_HS_READ    1000  /* one read during the handshake */
#define G5120_TIMEOUT_HS_PACE      60  /* read between two records of the first host flight */
#define G5120_TIMEOUT_HS_SETTLE    10  /* read after the host's Finished, before 0xd4 */
#define G5120_TIMEOUT_POST_D4    5000  /* listen-only read after the 0xd4 ACK, before 0xae (Go: Run 18) */
#define G5120_HANDSHAKE_BUDGET   5000  /* the vendor's own budget is 1100 */
#define G5120_TIMEOUT_IMAGE      2000  /* the image pack arrives ~88 ms after 0x20 */

/* Bounds, as in the Go reference (maxReadsPerStep, maxDrainReads). */
#define G5120_MAX_READS_PER_STEP 4
#define G5120_MAX_DRAIN_READS    8
/* Consecutive "base invalid" replies to one 0x32 arm before giving up. */
#define G5120_MAX_BASE_INVALID   8

/* Where the 32-byte raw PSK is read from. The environment variable wins.
 * TODO(provisioning): see README.md, "PSK provisioning". */
#define G5120_PSK_ENV          "GOODIX5120_PSK_FILE"
#define G5120_PSK_DEFAULT_PATH "/var/lib/fprint/goodix5120/psk.bin"

/* The 64 x 80 frame is enlarged x3 (Pixman bilinear), as aes4000 does for its
 * small press sensor. SIGFM features are extracted from this 192 x 240 image,
 * the size Runs 38-40 measured; templates record it (goodix5120_match.h). */
#define G5120_ENLARGE_FACTOR 3

/* Each touch images about 3 x 4 mm of the finger: Run 39 rejected 3 of 6
 * genuine attempts against 5 views, Run 40 accepted 14 of 15 against 14.
 * The goodixtls fork enrolls 20 views for its 64 x 80 goodix511. */
#define G5120_ENROLL_STAGES 15
