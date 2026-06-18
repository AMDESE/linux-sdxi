// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI selftest library helpers.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#include <stdatomic.h>
#include <time.h>
#include <errno.h>

#include "linux/kernel.h"
#include "linux/bitfield.h"
#include "linux/bits.h"
#include "linux/types.h"

#include "descriptor.h"
#include "lib.h"

#define DESC_SUBTYPE GENMASK(15, 8)
#define DESC_TYPE GENMASK(26, 16)
#define DESC_VL  BIT(0)
#define DESC_SE  BIT(1)
#define DESC_FE  BIT(2)
#define DESC_CH  BIT(3)
#define DESC_CSR BIT(4)
#define DESC_RB BIT(5)

#define DESC_NP BIT_ULL(0)
#define DESC_CSB_PTR GENMASK_ULL(63, 5)

enum sdxi_op_group {
	OPGRP_DMAB = 0x001,
};

enum sdxi_operation {
	DMAB_NOP = 0x01,
	DMAB_COPY = 0x03,
};

struct sdxi_desc sdxi_dsc_encode_rsvd(void)
{
	u32 opcode =
		FIELD_PREP(DESC_VL, 1) |
		FIELD_PREP(DESC_SE, 0) |
		FIELD_PREP(DESC_FE, 1) |
		FIELD_PREP(DESC_CH, 0) |
		FIELD_PREP(DESC_CSR, 1) |
		FIELD_PREP(DESC_SUBTYPE, 0) |
		FIELD_PREP(DESC_TYPE, 0);
	u64 csb_ptr =
		FIELD_PREP(DESC_NP, 1) |
		FIELD_PREP(DESC_CSB_PTR, 0);

	return (struct sdxi_desc) {
		.opcode = cpu_to_le32(opcode),
		.csb_ptr = cpu_to_le64(csb_ptr),
	};
}

struct sdxi_desc sdxi_dsc_encode_nop(void)
{
	u32 opcode =
		FIELD_PREP(DESC_VL, 1) |
		FIELD_PREP(DESC_SE, 0) |
		FIELD_PREP(DESC_FE, 1) |
		FIELD_PREP(DESC_CH, 0) |
		FIELD_PREP(DESC_CSR, 1) |
		FIELD_PREP(DESC_SUBTYPE, DMAB_NOP) |
		FIELD_PREP(DESC_TYPE, OPGRP_DMAB);
	u64 csb_ptr =
		FIELD_PREP(DESC_NP, 1) |
		FIELD_PREP(DESC_CSB_PTR, 0);

	return (struct sdxi_desc) {
		.opcode = cpu_to_le32(opcode),
		.csb_ptr = cpu_to_le64(csb_ptr),
	};
}

struct sdxi_desc sdxi_dsc_encode_copy(void *dest, const void *src, size_t n)
{
	u32 opcode =
		FIELD_PREP(DESC_VL, 1) |
		FIELD_PREP(DESC_SE, 0) |
		FIELD_PREP(DESC_FE, 1) |
		FIELD_PREP(DESC_CH, 0) |
		FIELD_PREP(DESC_CSR, 1) |
		FIELD_PREP(DESC_SUBTYPE, DMAB_COPY) |
		FIELD_PREP(DESC_TYPE, OPGRP_DMAB);
	u64 csb_ptr =
		FIELD_PREP(DESC_NP, 1) |
		FIELD_PREP(DESC_CSB_PTR, 0);

	return (struct sdxi_desc) {
		.opcode = cpu_to_le32(opcode),
		.csb_ptr = cpu_to_le64(csb_ptr),

		.copy = (struct sdxi_desc_copy) {
			.size = cpu_to_le32(n - 1),

			// Note that akeys are hardcoded to 1 here and
			// in the driver.
			.akey0 = cpu_to_le16(1),
			.akey1 = cpu_to_le16(1),
			.addr0 = cpu_to_le64((uintptr_t)src),
			.addr1 = cpu_to_le64((uintptr_t)dest),
		},
	};
}

static void copy_desc_to_ring(struct descriptor_ring *ring, size_t idx,
			      const struct sdxi_desc *src)
{
	struct sdxi_desc *dst;

	idx = idx % ARRAY_SIZE(ring->entry);
	dst = &ring->entry[idx];

	for (size_t i = 1; i < ARRAY_SIZE(src->qw); ++i)
		dst->qw[i] = src->qw[i];

	atomic_thread_fence(memory_order_acq_rel);

	dst->qw[0] = src->qw[0];
}

static u64 sample_read_index(const struct sdxi_context *cxt)
{
	return le64_to_cpu(READ_ONCE(cxt->cxt_sts->read_index));
}

int sdxi_submit_async(struct sdxi_context *cxt, const struct sdxi_desc *desc, u64 *pos)
{
	u64 read, old_write, new_write;

	if (!sdxi_context_running(cxt))
		return -EIO;

	read = le64_to_cpu(READ_ONCE(cxt->cxt_sts->read_index));
	atomic_thread_fence(memory_order_acq_rel);
	old_write = le64_to_cpu(READ_ONCE(*cxt->write_idx));

	if (read > old_write)
		return -EINVAL;

	new_write = old_write + 1;
	if (new_write - read > cxt->n_entries)
		return -ENOSPC;

	WRITE_ONCE(*cxt->write_idx, cpu_to_le64(new_write));
	atomic_thread_fence(memory_order_acq_rel);
	copy_desc_to_ring(cxt->ring, old_write, desc);
	WRITE_ONCE(*cxt->doorbell, cpu_to_le64(new_write));

	if (pos)
		*pos = old_write;
	return 0;
}

// Submit nops until the function increments the read index or the
// threshold is reached. Sleeps 1ms between each nop.
static int force_read_index_advance(struct sdxi_context *cxt, u64 target)
{
	struct sdxi_desc nop = sdxi_dsc_encode_nop();

	for (size_t tries = 1000; tries > 0; --tries) {
		if (sample_read_index(cxt) >= target)
			return 0;
		sdxi_submit_async(cxt, &nop, NULL);
		nanosleep(&(struct timespec) {
				.tv_nsec = 1000000,
			  }, NULL);
	}

	fprintf(stderr, "Failed to force read index advance to %llu\n",
		(unsigned long long)target);
	return -ETIMEDOUT;
}

int sdxi_submit_sync(struct sdxi_context *cxt, const struct sdxi_desc *desc)
{
	u64 pos;
	int err;

	err = sdxi_submit_async(cxt, desc, &pos);
	if (err)
		return err;

	return force_read_index_advance(cxt, pos + 1);
}

int sdxi_submit_oneshot(const struct sdxi_desc *desc)
{
	struct sdxi_context *context = sdxi_context_create();
	int err;

	if (!context)
		return -EIO;

	err = sdxi_submit_async(context, desc, NULL);

	sdxi_context_destroy(context);

	return err;
}
