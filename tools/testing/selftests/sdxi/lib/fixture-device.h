/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SDXI selftest device fixture.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#ifndef SELFTEST_SDXI_FIXTURE_DEVICE_H
#define SELFTEST_SDXI_FIXTURE_DEVICE_H

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <linux/sdxi.h>

#include "lib.h"

#include "../../kselftest_harness.h"

FIXTURE(dev_sdxi) {
	int fd;
};

FIXTURE_SETUP(dev_sdxi) {
	errno = 0;
	self->fd = open("/dev/sdxi0", O_RDONLY | O_CLOEXEC);
	ASSERT_GE(self->fd, 0) {
		if (errno == ENOENT)
			SKIP(return,
			     "/dev/sdxi0 does not exist");
		if (errno == EACCES && geteuid() != 0)
			SKIP(return,
			     "insufficient privileges");
	}
}

FIXTURE_TEARDOWN(dev_sdxi) {
	EXPECT_EQ(close(self->fd), 0);
}

#endif /* SELFTEST_SDXI_FIXTURE_DEVICE_H */
