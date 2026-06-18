// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI context ioctl selftests.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <linux/sdxi.h>

#include "lib.h"
#include "lib/fixture-context.h"
#include "../kselftest_harness.h"

#define AKEY_ENT_VL		(1U << 0)
#define AKEY_ENT_IV		(1U << 1)
#define AKEY_ENT_PV		(1U << 2)
#define AKEY_ENT_STE		(1U << 3)
#define AKEY_ENT_PH_SHIFT	30
#define AKEY_ENT_INTR_SHIFT	4
#define AKEY_ENT_INTR_MAX	((1U << 11) - 1)

static void akey_pack_intr(uint32_t data[4], uint32_t pasid,
			   uint32_t intr_num, bool iv)
{
	memset(data, 0, sizeof(uint32_t) * 4);
	data[0] = AKEY_ENT_VL | AKEY_ENT_PV;
	if (iv)
		data[0] |= AKEY_ENT_IV;
	data[0] |= (intr_num & AKEY_ENT_INTR_MAX) << AKEY_ENT_INTR_SHIFT;
	data[1] = pasid;
}

static int set_single_akey(int cxt_fd, uint16_t index, const uint32_t data[4])
{
	struct sdxi_set_keys_args *args;
	size_t bytes = sizeof(*args) + sizeof(args->entries[0]);
	int rc;

	args = calloc(1, bytes);
	if (!args)
		return -ENOMEM;

	args->argsz = sizeof(*args);
	args->nkeys = 1;
	args->entries[0].index = index;
	memcpy(args->entries[0].data, data, sizeof(args->entries[0].data));

	rc = ioctl(cxt_fd, SDXI_SET_AKEYS, args);
	rc = rc ? -errno : 0;

	free(args);
	return rc;
}

static int get_single_akey(int cxt_fd, uint16_t index, uint32_t data[4])
{
	struct sdxi_get_keys_args *args;
	size_t bytes = sizeof(*args) + sizeof(args->entries[0]);
	int rc;

	args = calloc(1, bytes);
	if (!args)
		return -ENOMEM;

	args->argsz = sizeof(*args);
	args->nkeys = 1;
	args->entries[0].index = index;

	rc = ioctl(cxt_fd, SDXI_GET_AKEYS, args);
	rc = rc ? -errno : 0;
	if (!rc)
		memcpy(data, args->entries[0].data, sizeof(args->entries[0].data));

	free(args);
	return rc;
}

// This basically duplicates the normal context fixture, maybe this
// could be fixed by using a variant?
FIXTURE(sdxi_context_nomap) {
	int cxt_fd;
	int device_fd;
	void *write_idx;
	size_t write_idx_bytes;
	void *cxt_sts;
	size_t cxt_sts_bytes;
	void *ring;
	size_t ring_bytes;
};

FIXTURE_SETUP(sdxi_context_nomap)
{
	int device_fd;
	long page_size;
	size_t ring_bytes;
	void *cxt_sts;
	void *ring;
	void *write_idx;

	errno = 0;
	device_fd = open("/dev/sdxi0", O_RDONLY | O_CLOEXEC);
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
	ring_bytes = (size_t)arg.ds_ring_entries * sizeof(struct sdxi_desc);

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

	self->cxt_fd = arg.cxt_fd;
	self->device_fd = device_fd;
	self->write_idx = write_idx;
	self->write_idx_bytes = (size_t)page_size;
	self->cxt_sts = cxt_sts;
	self->cxt_sts_bytes = (size_t)page_size;
	self->ring = ring;
	self->ring_bytes = ring_bytes;
}

FIXTURE_TEARDOWN(sdxi_context_nomap) {
	int cxt_fd = self->cxt_fd;
	int device_fd = self->device_fd;
	struct sdxi_quiesce_cxt_args quiesce = {};

	quiesce.argsz = sizeof(quiesce);

	EXPECT_EQ(ioctl(cxt_fd, SDXI_QUIESCE_CXT, &quiesce),
		  0);
	EXPECT_EQ(munmap(self->write_idx, self->write_idx_bytes), 0);
	EXPECT_EQ(munmap(self->cxt_sts, self->cxt_sts_bytes), 0);
	EXPECT_EQ(munmap(self->ring, self->ring_bytes), 0);
	EXPECT_EQ(close(cxt_fd), 0);
	EXPECT_EQ(close(device_fd), 0);
}

TEST_F(sdxi_context_nomap, context_create_and_destroy_nomap)
{
	// Just run the fixture setup and teardown
}

TEST(sdxi_create_cxt_rejects_nonzero_flags)
{
	struct sdxi_create_cxt_args arg = {
		.argsz = sizeof(arg),
		.flags = 1,
		.ds_ring_entries = 1024,
	};
	int device_fd;

	errno = 0;
	device_fd = open("/dev/sdxi0", O_RDONLY | O_CLOEXEC);
	ASSERT_GE(device_fd, 0) {
		if (errno == ENOENT)
			SKIP(return, "/dev/sdxi0 does not exist");
		if (errno == EACCES && geteuid() != 0)
			SKIP(return, "insufficient privileges");
	}

	errno = 0;
	EXPECT_EQ(ioctl(device_fd, SDXI_CREATE_CXT, &arg), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(close(device_fd), 0);
}

TEST(sdxi_create_cxt_requires_user_dataplane)
{
	struct sdxi_create_cxt_args arg = {
		.argsz = sizeof(arg),
		.ds_ring_entries = 1024,
	};
	int device_fd;

	errno = 0;
	device_fd = open("/dev/sdxi0", O_RDONLY | O_CLOEXEC);
	ASSERT_GE(device_fd, 0) {
		if (errno == ENOENT)
			SKIP(return, "/dev/sdxi0 does not exist");
		if (errno == EACCES && geteuid() != 0)
			SKIP(return, "insufficient privileges");
	}

	errno = 0;
	EXPECT_EQ(ioctl(device_fd, SDXI_CREATE_CXT, &arg), -1);
	EXPECT_EQ(errno, EINVAL);
	EXPECT_EQ(close(device_fd), 0);
}

TEST_F(sdxi_context, context_create_and_destroy)
{
	EXPECT_TRUE(sdxi_context_running(&self->context));
}

TEST_F(sdxi_context, cxt_eventfd_bind_unbind)
{
	struct sdxi_cxt_eventfd_args args = {};
	int efd;
	int rc;

	args.argsz = sizeof(args);

	efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	ASSERT_GE(efd, 0);

	args.eventfd = efd;
	rc = ioctl(self->context.cxt_fd, SDXI_CXT_EVENTFD, &args);
	if (rc != 0) {
		if (errno == EOPNOTSUPP) {
			close(efd);
			SKIP(return, "context interrupts not supported");
		}
		ASSERT_EQ(rc, 0);
	}

	EXPECT_GE(args.intr_akey, 2);
	EXPECT_GT(args.intr_num, 0U);

	args.eventfd = -1;
	args.argsz = sizeof(args);
	EXPECT_EQ(ioctl(self->context.cxt_fd, SDXI_CXT_EVENTFD, &args), 0);
	EXPECT_EQ(args.intr_akey, 0);
	EXPECT_EQ(args.intr_num, 0U);

	close(efd);
}

TEST_F(sdxi_context, akey_iv_requires_cxt_eventfd)
{
	uint32_t data[4];
	int rc;

	akey_pack_intr(data, self->context.pasid, 1, true);
	rc = set_single_akey(self->context.cxt_fd, 2, data);
	if (rc == -EOPNOTSUPP)
		SKIP(return, "context interrupts not supported");

	EXPECT_EQ(rc, -ENOTCONN);
}

TEST_F(sdxi_context, akey_iv_requires_matching_intr_num)
{
	struct sdxi_cxt_eventfd_args args = {};
	uint32_t data[4];
	uint32_t wrong_intr;
	uint16_t test_akey;
	int efd;
	int rc;

	args.argsz = sizeof(args);

	efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	ASSERT_GE(efd, 0);

	args.eventfd = efd;
	rc = ioctl(self->context.cxt_fd, SDXI_CXT_EVENTFD, &args);
	if (rc != 0) {
		if (errno == EOPNOTSUPP) {
			close(efd);
			SKIP(return, "context interrupts not supported");
		}
		ASSERT_EQ(rc, 0);
	}

	ASSERT_NE(args.intr_akey, UINT16_MAX);
	test_akey = args.intr_akey + 1;

	wrong_intr = (args.intr_num == 1U) ? 2U : 1U;
	akey_pack_intr(data, self->context.pasid, wrong_intr, true);
	EXPECT_EQ(set_single_akey(self->context.cxt_fd, test_akey, data),
		  -EINVAL);

	akey_pack_intr(data, self->context.pasid, args.intr_num, true);
	EXPECT_EQ(set_single_akey(self->context.cxt_fd, test_akey, data), 0);

	args.eventfd = -1;
	args.argsz = sizeof(args);
	EXPECT_EQ(ioctl(self->context.cxt_fd, SDXI_CXT_EVENTFD, &args), 0);
	close(efd);
}

TEST_F(sdxi_context, akey_user_rejects_dsh_fields)
{
	uint32_t data[4];

	if (geteuid() == 0)
		SKIP(return, "non-admin AKey validation test");

	ASSERT_EQ(get_single_akey(self->context.cxt_fd, 1, data), 0);

	data[0] |= AKEY_ENT_STE;
	EXPECT_EQ(set_single_akey(self->context.cxt_fd, 2, data), -EPERM);

	ASSERT_EQ(get_single_akey(self->context.cxt_fd, 1, data), 0);

	data[1] |= 1U << AKEY_ENT_PH_SHIFT;
	EXPECT_EQ(set_single_akey(self->context.cxt_fd, 2, data), -EPERM);

	ASSERT_EQ(get_single_akey(self->context.cxt_fd, 1, data), 0);

	data[2] = 1;
	EXPECT_EQ(set_single_akey(self->context.cxt_fd, 2, data), -EPERM);
}

TEST_HARNESS_MAIN
