/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SDXI selftest context fixture.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#ifndef SELFTEST_SDXI_FIXTURE_CONTEXT_H
#define SELFTEST_SDXI_FIXTURE_CONTEXT_H

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <linux/sdxi.h>

#include "lib.h"

#include "../../kselftest_harness.h"

FIXTURE(sdxi_context) {
	struct sdxi_context context;
};

FIXTURE_SETUP(sdxi_context)
{
	struct sdxi_context *cxt = &self->context;
	int cxt_fd;
	int device_fd;
	long page_size;
	size_t doorbell_bytes;
	size_t ring_bytes;
	void *cxt_sts;
	void *ring;
	void *write_idx;

	errno = 0;
	device_fd = open("/dev/sdxi0", O_RDWR | O_CLOEXEC);
	ASSERT_GE(device_fd, 0) {
		if (errno == ENOENT)
			SKIP(return,
			     "/dev/sdxi0 does not exist");
		if (errno == EACCES && geteuid() != 0)
			SKIP(return,
			     "insufficient privileges");
	}

	struct sdxi_create_cxt_args arg = {
		.argsz = sizeof(struct sdxi_create_cxt_args),
		.ds_ring_entries = 1024,
	};

	page_size = sysconf(_SC_PAGESIZE);
	ASSERT_GT(page_size, 0);
	ring_bytes = (size_t)arg.ds_ring_entries * sizeof(cxt->ring->entry[0]);

	cxt_sts = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	write_idx = mmap(NULL, (size_t)page_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	ring = mmap(NULL, ring_bytes, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	ASSERT_NE(cxt_sts, MAP_FAILED);
	ASSERT_NE(write_idx, MAP_FAILED);
	ASSERT_NE(ring, MAP_FAILED);

	/* Fault in and invalidate the ring before the device can fetch it. */
	memset(ring, 0, ring_bytes);

	arg.cxt_sts_base = (uint64_t)(uintptr_t)cxt_sts;
	arg.write_index_base = (uint64_t)(uintptr_t)write_idx;
	arg.ds_ring_base = (uint64_t)(uintptr_t)ring;

	ASSERT_EQ(ioctl(device_fd, SDXI_CREATE_CXT, &arg), 0);
	ASSERT_GE(arg.cxt_fd, 0);
	cxt_fd = arg.cxt_fd;
	doorbell_bytes = sdxi_context_db_stride_bytes(device_fd);
	ASSERT_GT(doorbell_bytes, 0U);

	*cxt = (struct sdxi_context) {
		.device_fd = device_fd,
		.cxt_fd = cxt_fd,
		.pasid = arg.pasid,
		.doorbell = mmap(NULL, doorbell_bytes,
				 PROT_WRITE, MAP_SHARED,
				 cxt_fd, arg.doorbell_mmap_base),
		.doorbell_bytes = doorbell_bytes,
		.write_idx = write_idx,
		.write_idx_bytes = (size_t)page_size,
		.cxt_sts = cxt_sts,
		.cxt_sts_bytes = (size_t)page_size,
		.ring = ring,
		.ring_bytes = ring_bytes,
		.n_entries = arg.ds_ring_entries,
	};

	EXPECT_NE(cxt->doorbell, MAP_FAILED);
	EXPECT_NE(cxt->write_idx, MAP_FAILED);
	EXPECT_NE(cxt->cxt_sts, MAP_FAILED);
	EXPECT_NE(cxt->ring, MAP_FAILED);
}

FIXTURE_TEARDOWN(sdxi_context)
{
	struct sdxi_context *cxt = &self->context;
	struct sdxi_quiesce_cxt_args quiesce = {};

	quiesce.argsz = sizeof(quiesce);

	EXPECT_EQ(ioctl(cxt->cxt_fd, SDXI_QUIESCE_CXT, &quiesce),
		  0);
	EXPECT_EQ(munmap(cxt->doorbell, cxt->doorbell_bytes), 0);
	EXPECT_EQ(munmap(cxt->write_idx, cxt->write_idx_bytes), 0);
	EXPECT_EQ(munmap(cxt->cxt_sts, cxt->cxt_sts_bytes), 0);
	EXPECT_EQ(munmap(cxt->ring, cxt->ring_bytes), 0);
	EXPECT_EQ(close(cxt->cxt_fd), 0);
	EXPECT_EQ(close(cxt->device_fd), 0);
}

#endif /* SELFTEST_SDXI_FIXTURE_CONTEXT_H */
