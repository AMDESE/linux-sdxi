/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SDXI ioctl and context mapping definitions.
 *
 * Copyright Advanced Micro Devices, Inc.
 */

#ifndef DMA_SDXI_IOCTL_H
#define DMA_SDXI_IOCTL_H

#include <linux/bits.h>
#include <linux/types.h>
#include <asm/page.h>

#include "process.h"

struct file;
struct sdxi_cxt;

enum sdxi_file_type {
	SDXI_FILE_DEVICE,
	SDXI_FILE_CONTEXT,
};

struct sdxi_file {
	enum sdxi_file_type type;
	struct sdxi_process *process;
	struct sdxi_cxt *cxt;
};

typedef int sdxi_ioctl_t(struct file *file, struct sdxi_file *sf, void *data);

enum sdxi_ioctl_access_class {
	SDXI_IOCTL_A_PUBLIC_DEVICE,
	SDXI_IOCTL_A_CONTEXT_OWNER,
	SDXI_IOCTL_A_ADMIN_DEVICE,
	SDXI_IOCTL_A_VENDOR_HANDLER,
};

struct sdxi_ioctl_desc {
	unsigned int cmd;
	unsigned int file_flags;
	enum sdxi_ioctl_access_class access;
	sdxi_ioctl_t *func;
};

#define SDXI_IOCTL_F_DEVICE	BIT(0)
#define SDXI_IOCTL_F_CONTEXT	BIT(1)

#define SDXI_MMAP_TYPE_SHIFT		40
#define SDXI_MMAP_TYPE_DOORBELL		(0x4ULL << SDXI_MMAP_TYPE_SHIFT)
#define SDXI_MMAP_TYPE_MASK		(0x7ULL << SDXI_MMAP_TYPE_SHIFT)

#define SDXI_MMAP_CXT_ID_SHIFT		24
#define SDXI_MMAP_CXT_ID_MASK		GENMASK_ULL(39, 24)
#define SDXI_MMAP_GEN_SHIFT		PAGE_SHIFT
#define SDXI_MMAP_GEN_MASK		GENMASK_ULL(23, PAGE_SHIFT)

static inline u64 sdxi_mmap_token(u64 type, u32 cxt_id, u32 generation)
{
	return type |
	       (((u64)cxt_id << SDXI_MMAP_CXT_ID_SHIFT) &
		SDXI_MMAP_CXT_ID_MASK) |
	       (((u64)generation << SDXI_MMAP_GEN_SHIFT) &
		SDXI_MMAP_GEN_MASK);
}

static inline u32 sdxi_mmap_token_cxt_id(u64 token)
{
	return (token & SDXI_MMAP_CXT_ID_MASK) >> SDXI_MMAP_CXT_ID_SHIFT;
}

static inline u32 sdxi_mmap_token_gen(u64 token)
{
	return (token & SDXI_MMAP_GEN_MASK) >> SDXI_MMAP_GEN_SHIFT;
}

#endif /* DMA_SDXI_IOCTL_H */
