/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright Advanced Micro Devices, Inc. */
#ifndef DMA_SDXI_COMPLETION_H
#define DMA_SDXI_COMPLETION_H

#include <linux/compiler_attributes.h>
#include "sdxi.h"
#include "hw.h"


/*
 * Polled completion status block that can be attached to a
 * descriptor.
 */
struct sdxi_desc;

struct sdxi_completion {
	struct sdxi_dev *sdxi;
	struct sdxi_cst_blk *cst_blk;
	dma_addr_t cst_blk_dma;
};

struct sdxi_cq {
	dma_addr_t handle;
	u32 count;
	struct sdxi_cst_blk entry[] __counted_by(count);
};

/*
 * Descriptor completion states. These are not architected values and
 * are for software use only.
 */
enum sdxi_completion_state {
	SDXI_COMPLETION_PENDING, /* Not done yet. */
	SDXI_COMPLETION_DONE,	 /* Completed without error. */
	SDXI_COMPLETION_ERROR,	 /* Completed with at least one error. */
};

struct sdxi_completion sdxi_cq_entry(struct sdxi_cq *cq, u64 index);
struct sdxi_cq *sdxi_cq_alloc(struct sdxi_dev *sdxi, unsigned int count);
void sdxi_cq_free(struct sdxi_dev *sdxi, struct sdxi_cq *cq);

static inline void sdxi_cst_blk_init(struct sdxi_cst_blk *cst)
{
	*cst = (typeof(*cst)) {
		.signal = cpu_to_le64(SDXI_CST_BLK_SIGNAL_INIT),
	};
}

int __must_check sdxi_cst_blk_poll(const struct sdxi_cst_blk *cst);
enum sdxi_completion_state sdxi_cst_blk_check(const struct sdxi_cst_blk *cst);

struct sdxi_completion *sdxi_completion_alloc(struct sdxi_dev *sdxi);
void sdxi_completion_free(struct sdxi_completion *sc);
int __must_check sdxi_completion_poll(const struct sdxi_completion *sc);
void sdxi_completion_attach(struct sdxi_desc *desc,
			    const struct sdxi_completion *sc);
enum sdxi_completion_state
sdxi_completion_check(const struct sdxi_completion *sc);

DEFINE_FREE(sdxi_completion, struct sdxi_completion *, if (_T) sdxi_completion_free(_T))

#endif /* DMA_SDXI_COMPLETION_H */
