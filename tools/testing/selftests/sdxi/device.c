// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI device ioctl selftests.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <linux/sdxi.h>

#include "lib.h"
#include "lib/fixture-device.h"
#include "../kselftest_harness.h"

TEST_F(dev_sdxi, open_and_close_device)
{
	// Just run the fixture setup and teardown
}

TEST_F(dev_sdxi, get_uapi_info)
{
	struct sdxi_uapi_info_args info = {};

	info.argsz = sizeof(info);

	ASSERT_EQ(ioctl(self->fd, SDXI_GET_UAPI_INFO, &info), 0);
	EXPECT_EQ(info.uapi_major, SDXI_UAPI_MAJOR);
	EXPECT_EQ(info.uapi_minor, SDXI_UAPI_MINOR);
	EXPECT_GT(info.cap_words, 0);
	EXPECT_LE(info.cap_words, SDXI_UAPI_CAP_WORDS);
	EXPECT_EQ(info.rsvd0, 0);
	/* The driver must publish at least one capability bit. */
	EXPECT_NE(info.caps[0], 0ULL);
	EXPECT_NE(info.caps[0] & SDXI_UAPI_CAP_ADMIN_VENDOR, 0ULL);
	EXPECT_NE(info.caps[0] & SDXI_UAPI_CAP_CXT_EVENTFD, 0ULL);
}

TEST_F(dev_sdxi, get_uapi_info_rejects_flags)
{
	struct sdxi_uapi_info_args info = {};

	info.argsz = sizeof(info);
	info.flags = 1;

	errno = 0;
	EXPECT_EQ(ioctl(self->fd, SDXI_GET_UAPI_INFO, &info), -1);
	EXPECT_EQ(errno, EINVAL);
}

TEST_F(dev_sdxi, get_dev_info)
{
	struct sdxi_dev_info_args info = {};

	info.argsz = sizeof(info);

	ASSERT_EQ(ioctl(self->fd, SDXI_GET_DEV_INFO, &info), 0);
	EXPECT_EQ(info.argsz, sizeof(info));
	/* SDXI 1.x devices report a non-zero major version. */
	EXPECT_GE(info.hw_major, 1);
	EXPECT_EQ(info.rsvd0, 0U);
	EXPECT_EQ(info.rsvd1[0], 0ULL);
	EXPECT_EQ(info.rsvd1[1], 0ULL);
	EXPECT_EQ(info.rsvd1[2], 0ULL);
	EXPECT_EQ(info.rsvd1[3], 0ULL);
}

TEST_F(dev_sdxi, get_dev_info_rejects_flags)
{
	struct sdxi_dev_info_args info = {};

	info.argsz = sizeof(info);
	info.flags = 1;

	errno = 0;
	EXPECT_EQ(ioctl(self->fd, SDXI_GET_DEV_INFO, &info), -1);
	EXPECT_EQ(errno, EINVAL);
}

TEST_F(dev_sdxi, get_dev_info_rejects_short_argsz)
{
	struct sdxi_dev_info_args info = {};

	info.argsz = sizeof(info) - 1;

	errno = 0;
	EXPECT_EQ(ioctl(self->fd, SDXI_GET_DEV_INFO, &info), -1);
	EXPECT_EQ(errno, EINVAL);
}

static int sdxi_get_dev_attr(int fd, uint64_t attr, uint64_t *out)
{
	struct sdxi_dev_attr_args args = {};
	int rc;

	args.argsz = sizeof(args);
	args.attr = attr;

	rc = ioctl(fd, SDXI_GET_DEV_ATTR, &args);
	if (rc == 0 && out)
		*out = args.val;
	return rc;
}

TEST_F(dev_sdxi, get_dev_attr)
{
	uint64_t val;

	ASSERT_EQ(sdxi_get_dev_attr(self->fd, SDXI_DEV_ATTR_MAX_BUFFER, &val), 0);
	EXPECT_LE(val, 11U);

	ASSERT_EQ(sdxi_get_dev_attr(self->fd, SDXI_DEV_ATTR_MAX_AKEY_SZ, &val), 0);
	EXPECT_LE(val, 8U);

	ASSERT_EQ(sdxi_get_dev_attr(self->fd, SDXI_DEV_ATTR_MAX_CXT, &val), 0);
	EXPECT_GT(val, 0U);

	/* MAX_RKEY_SZ is read-only and may be 0 if RKEY isn't supported. */
	EXPECT_EQ(sdxi_get_dev_attr(self->fd, SDXI_DEV_ATTR_MAX_RKEY_SZ, &val), 0);
}

TEST_F(dev_sdxi, get_dev_attr_rejects_unknown)
{
	struct sdxi_dev_attr_args args = {};

	args.argsz = sizeof(args);
	args.attr = 0;
	errno = 0;
	EXPECT_EQ(ioctl(self->fd, SDXI_GET_DEV_ATTR, &args), -1);
	EXPECT_EQ(errno, EOPNOTSUPP);

	args.attr = 0xffff;
	errno = 0;
	EXPECT_EQ(ioctl(self->fd, SDXI_GET_DEV_ATTR, &args), -1);
	EXPECT_EQ(errno, EOPNOTSUPP);
}

TEST_F(dev_sdxi, get_dev_attr_rejects_flags)
{
	struct sdxi_dev_attr_args args = {};

	args.argsz = sizeof(args);
	args.attr = SDXI_DEV_ATTR_MAX_BUFFER;
	args.flags = 1;

	errno = 0;
	EXPECT_EQ(ioctl(self->fd, SDXI_GET_DEV_ATTR, &args), -1);
	EXPECT_EQ(errno, EINVAL);
}

TEST_F(dev_sdxi, set_dev_attr_requires_admin)
{
	struct sdxi_dev_attr_args args = {};
	uint64_t cur;
	int rc;

	if (geteuid() == 0)
		SKIP(return, "needs non-root");

	ASSERT_EQ(sdxi_get_dev_attr(self->fd, SDXI_DEV_ATTR_GRP_ID, &cur), 0);

	args.argsz = sizeof(args);
	args.attr = SDXI_DEV_ATTR_GRP_ID;
	args.val = cur;

	errno = 0;
	rc = ioctl(self->fd, SDXI_SET_DEV_ATTR, &args);
	EXPECT_EQ(rc, -1);
	EXPECT_EQ(errno, EPERM);
}

TEST_F(dev_sdxi, set_dev_attr_round_trip)
{
	struct sdxi_dev_attr_args args = {};
	uint64_t orig, applied;

	if (geteuid() != 0)
		SKIP(return, "requires root");

	ASSERT_EQ(sdxi_get_dev_attr(self->fd, SDXI_DEV_ATTR_GRP_ID, &orig), 0);

	args.argsz = sizeof(args);
	args.attr = SDXI_DEV_ATTR_GRP_ID;
	args.val = orig;

	ASSERT_EQ(ioctl(self->fd, SDXI_SET_DEV_ATTR, &args), 0);
	EXPECT_EQ(args.argsz, sizeof(args));
	EXPECT_EQ(args.val, orig);

	ASSERT_EQ(sdxi_get_dev_attr(self->fd, SDXI_DEV_ATTR_GRP_ID, &applied), 0);
	EXPECT_EQ(applied, orig);
}

TEST_F(dev_sdxi, set_dev_attr_rejects_exceeding_caps)
{
	struct sdxi_dev_info_args info = {};
	struct sdxi_dev_attr_args args = {};
	uint64_t cap_max_buffer;
	int rc;

	if (geteuid() != 0)
		SKIP(return, "requires root");

	info.argsz = sizeof(info);
	ASSERT_EQ(ioctl(self->fd, SDXI_GET_DEV_INFO, &info), 0);

	cap_max_buffer = info.cap1 & 0xf;
	if (cap_max_buffer == 0xf)
		SKIP(return, "cap1.max_buffer already saturates the field");

	args.argsz = sizeof(args);
	args.attr = SDXI_DEV_ATTR_MAX_BUFFER;
	args.val = cap_max_buffer + 1;

	errno = 0;
	rc = ioctl(self->fd, SDXI_SET_DEV_ATTR, &args);
	EXPECT_EQ(rc, -1);
	EXPECT_EQ(errno, EINVAL);
}

TEST_F(dev_sdxi, set_dev_attr_rejects_read_only)
{
	struct sdxi_dev_attr_args args = {};
	int rc;

	if (geteuid() != 0)
		SKIP(return, "requires root");

	args.argsz = sizeof(args);
	args.attr = SDXI_DEV_ATTR_MAX_RKEY_SZ;
	args.val = 0;

	errno = 0;
	rc = ioctl(self->fd, SDXI_SET_DEV_ATTR, &args);
	EXPECT_EQ(rc, -1);
	EXPECT_EQ(errno, EOPNOTSUPP);
}

TEST_HARNESS_MAIN
