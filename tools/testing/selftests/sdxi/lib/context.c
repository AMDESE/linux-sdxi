// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI selftest context helpers.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <linux/kernel.h>
#include <linux/sdxi.h>

#include "lib.h"

#define alloc(...)					\
	({						\
		size_t sz = sizeof(__VA_ARGS__);	\
		void *ptr = malloc(sz);			\
		if (ptr)				\
			memset(ptr, 0, sz);		\
		(typeof(__VA_ARGS__) *)ptr;		\
	})

enum {
	SELFTEST_SDXI_CAP0_DB_STRIDE_SHIFT = 20,
	SELFTEST_SDXI_CAP0_DB_STRIDE_MASK = 0x7,
};

static size_t sdxi_page_size(void)
{
	long page_size = sysconf(_SC_PAGESIZE);

	if (page_size <= 0)
		return 4096;

	return (size_t)page_size;
}

size_t sdxi_context_db_stride_bytes(int device_fd)
{
	struct sdxi_dev_info_args info = {};
	uint64_t shift;

	info.argsz = sizeof(info);
	if (ioctl(device_fd, SDXI_GET_DEV_INFO, &info) != 0)
		return 0;

	shift = (info.cap0 >> SELFTEST_SDXI_CAP0_DB_STRIDE_SHIFT) &
		SELFTEST_SDXI_CAP0_DB_STRIDE_MASK;

	return 4096ull << shift;
}

static void sdxi_context_munmap_safe(void *addr, size_t bytes)
{
	if (!addr || addr == MAP_FAILED || bytes == 0)
		return;

	(void)munmap(addr, bytes);
}

struct sdxi_context *sdxi_context_create(void)
{
	struct sdxi_create_cxt_args arg = {
		.argsz = sizeof(struct sdxi_create_cxt_args),
		.ds_ring_entries = 1024,
	};
	struct sdxi_context *cxt;
	void *doorbell = MAP_FAILED;
	void *write_idx = MAP_FAILED;
	void *cxt_sts = MAP_FAILED;
	void *ring = MAP_FAILED;
	size_t page_size;
	size_t doorbell_bytes;
	size_t ring_bytes;
	int cxt_fd = -1;
	int device_fd;
	int err;

	cxt = alloc(*cxt);
	if (!cxt)
		return NULL;

	errno = 0;
	device_fd = open("/dev/sdxi0", O_RDWR | O_CLOEXEC);
	if (device_fd < 0)
		goto free_cxt;

	page_size = sdxi_page_size();
	doorbell_bytes = sdxi_context_db_stride_bytes(device_fd);
	if (doorbell_bytes == 0)
		goto close_fd;

	ring_bytes = (size_t)arg.ds_ring_entries * sizeof(cxt->ring->entry[0]);
	cxt_sts = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		       MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	write_idx = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
			 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	ring = mmap(NULL, ring_bytes, PROT_READ | PROT_WRITE,
		    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (cxt_sts == MAP_FAILED || write_idx == MAP_FAILED ||
	    ring == MAP_FAILED)
		goto unmap_local;

	arg.cxt_sts_base = (uint64_t)(uintptr_t)cxt_sts;
	arg.write_index_base = (uint64_t)(uintptr_t)write_idx;
	arg.ds_ring_base = (uint64_t)(uintptr_t)ring;

	err = ioctl(device_fd, SDXI_CREATE_CXT, &arg);
	if (err)
		goto unmap_local;

	cxt_fd = arg.cxt_fd;
	if (cxt_fd < 0)
		goto unmap_local;

	ring_bytes = (size_t)arg.ds_ring_entries * sizeof(cxt->ring->entry[0]);

	doorbell = mmap(NULL, doorbell_bytes, PROT_WRITE, MAP_SHARED,
			cxt_fd, arg.doorbell_mmap_base);
	if (doorbell == MAP_FAILED)
		goto unmap;

	*cxt = (struct sdxi_context) {
		.device_fd = device_fd,
		.cxt_fd = cxt_fd,
		.pasid = arg.pasid,
		.doorbell = doorbell,
		.doorbell_bytes = doorbell_bytes,
		.write_idx = write_idx,
		.write_idx_bytes = page_size,
		.cxt_sts = cxt_sts,
		.cxt_sts_bytes = page_size,
		.ring = ring,
		.ring_bytes = ring_bytes,
		.n_entries = arg.ds_ring_entries,
	};

	return cxt;

unmap:
	(void)ioctl(cxt_fd, SDXI_QUIESCE_CXT,
	      &(struct sdxi_quiesce_cxt_args) {
		      .argsz = sizeof(struct sdxi_quiesce_cxt_args),
	      });
	sdxi_context_munmap_safe(doorbell, doorbell_bytes);
unmap_local:
	sdxi_context_munmap_safe(write_idx, page_size);
	sdxi_context_munmap_safe(cxt_sts, page_size);
	sdxi_context_munmap_safe(ring,
				 (size_t)arg.ds_ring_entries *
				 sizeof(cxt->ring->entry[0]));
close_fd:
	if (cxt_fd >= 0)
		(void)close(cxt_fd);
	(void)close(device_fd);
free_cxt:
	free(cxt);
	return NULL;
}

void sdxi_context_destroy(struct sdxi_context *cxt)
{
	if (!cxt)
		return;

	(void)ioctl(cxt->cxt_fd, SDXI_QUIESCE_CXT,
	      &(struct sdxi_quiesce_cxt_args) {
		      .argsz = sizeof(struct sdxi_quiesce_cxt_args),
	      });
	sdxi_context_munmap_safe(cxt->doorbell, cxt->doorbell_bytes);
	sdxi_context_munmap_safe(cxt->write_idx, cxt->write_idx_bytes);
	sdxi_context_munmap_safe(cxt->cxt_sts, cxt->cxt_sts_bytes);
	sdxi_context_munmap_safe(cxt->ring, cxt->ring_bytes);
	(void)close(cxt->cxt_fd);
	(void)close(cxt->device_fd);
	free(cxt);
}

bool sdxi_context_running(const struct sdxi_context *cxt)
{
	struct sdxi_cxt_sts *sts = cxt->cxt_sts;
	enum {
		CXTV_RUN = 1,
	};

	return (READ_ONCE(sts->state) & 0xf) == CXTV_RUN;
}
