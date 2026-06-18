// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI admin command selftests.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#include <errno.h>
#include <linux/sdxi.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "lib/fixture-device.h"
#include "../kselftest_harness.h"

/*
 * SDXI DSC_DISC uses RFC4122-like GUIDs, but with time_low/time_mid/time_hi
 * stored in little-endian order.
 */
static const uint8_t sdxi_amd_guid_qos[16] = {
	0x0b, 0x61, 0xb7, 0xf5, 0xc6, 0x0d, 0x03, 0x4c,
	0xab, 0x79, 0x65, 0xf1, 0xf4, 0xef, 0xcf, 0x4c,
};

/*
 * AMD QoS vendor operations are GUID-scoped and not part of the generic
 * UAPI header. The kernel maps these op ids onto the vendor descriptors
 * internally.
 */
#define SDXI_AMD_QOS_ADMIN_OP_CAP	1U

TEST_F(dev_sdxi, admin_disc_operation_groups)
{
	uint8_t disc_buf[31 * 16] = {0};
	struct sdxi_admin_disc_args args = {
		.argsz = sizeof(args),
		.index = {
			.start = 1,
			.end = 31,
		},
		.buf_uptr = (uint64_t)(uintptr_t)disc_buf,
		.buf_size = sizeof(disc_buf),
	};
	int rc;

	rc = ioctl(self->fd, SDXI_ADMIN_DISC, &args);
	if (rc != 0) {
		if (errno == EOPNOTSUPP)
			SKIP(return, "admin discovery not supported");
		ASSERT_EQ(rc, 0);
	}

	EXPECT_EQ(args.buf_size, sizeof(disc_buf));
}

TEST_F(dev_sdxi, admin_vendor_qos_cap)
{
	uint8_t cap_buf[48] = {0};
	uint32_t word;
	int rc;

	if (geteuid() != 0)
		SKIP(return, "requires root");

	struct sdxi_admin_vendor_args probe = {
		.argsz = sizeof(probe),
		.op = SDXI_ADMIN_VENDOR_PROBE,
	};
	struct sdxi_admin_vendor_args cap = {
		.argsz = sizeof(cap),
		.op = SDXI_AMD_QOS_ADMIN_OP_CAP,
		.out_uptr = (uint64_t)(uintptr_t)cap_buf,
		.out_size = sizeof(cap_buf),
	};

	memcpy(probe.guid, sdxi_amd_guid_qos, sizeof(probe.guid));
	memcpy(cap.guid, sdxi_amd_guid_qos, sizeof(cap.guid));

	rc = ioctl(self->fd, SDXI_ADMIN_VENDOR, &probe);
	if (rc != 0) {
		if (errno == EOPNOTSUPP)
			SKIP(return, "QoS vendor path not supported");
		EXPECT_EQ(0, rc);
		return;
	}

	rc = ioctl(self->fd, SDXI_ADMIN_VENDOR, &cap);
	if (rc != 0) {
		if (errno == EOPNOTSUPP)
			SKIP(return, "QoS CAP not supported");
		EXPECT_EQ(0, rc);
		return;
	}

	word = (uint32_t)cap_buf[8] |
	       ((uint32_t)cap_buf[9] << 8) |
	       ((uint32_t)cap_buf[10] << 16) |
	       ((uint32_t)cap_buf[11] << 24);
	EXPECT_NE(0U, word & 0x0fff);
}

TEST_HARNESS_MAIN
