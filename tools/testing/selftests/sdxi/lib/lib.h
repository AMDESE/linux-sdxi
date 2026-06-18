/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SDXI selftest library helpers.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#ifndef SELFTEST_SDXI_LIB_H
#define SELFTEST_SDXI_LIB_H

#include <inttypes.h>
#include <stdbool.h>

#include "descriptor.h"
#include "linux/build_bug.h"
#include "linux/types.h"

struct sdxi_cxt_sts {
	__u8   state;
	__u8   misc0;
	__u8   rsvd_0[6];
	__le64 read_index;
};

enum {
	SDXI_DESC_RING_ENTRIES = 1024,
};

struct descriptor_ring {
	struct sdxi_desc entry[SDXI_DESC_RING_ENTRIES];
};

struct sdxi_context {
	int device_fd;
	int cxt_fd;
	__u32 pasid;
	__le64 *doorbell;
	size_t doorbell_bytes;
	__le64 *write_idx;
	size_t write_idx_bytes;
	size_t n_entries;
	struct sdxi_cxt_sts *cxt_sts;
	size_t cxt_sts_bytes;
	struct descriptor_ring *ring;
	size_t ring_bytes;
};

size_t sdxi_context_db_stride_bytes(int device_fd);
struct sdxi_context *sdxi_context_create(void);
void sdxi_context_destroy(struct sdxi_context *cxt);
bool sdxi_context_running(const struct sdxi_context *cxt);

struct sdxi_desc sdxi_dsc_encode_copy(void *dest, const void *src, size_t n);
struct sdxi_desc sdxi_dsc_encode_nop(void);
struct sdxi_desc sdxi_dsc_encode_rsvd(void);

int sdxi_submit_async(struct sdxi_context *cxt, const struct sdxi_desc *desc, u64 *pos);
int sdxi_submit_sync(struct sdxi_context *cxt, const struct sdxi_desc *desc);
int sdxi_submit_oneshot(const struct sdxi_desc *desc);

#endif/* SELFTEST_SDXI_LIB_H */
