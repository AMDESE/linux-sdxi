// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI Descriptor Completion Status Block handling.
 *
 * Copyright Advanced Micro Devices, Inc.
 */
#include <linux/cleanup.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/iopoll.h>
#include <linux/slab.h>

#include "completion.h"
#include "descriptor.h"
#include "hw.h"

struct sdxi_completion sdxi_cq_entry(struct sdxi_cq *cq, u64 index)
{
	u32 pos = do_div(index, cq->count);
	u32 off = struct_offset(cq, entry) + pos * sizeof(cq->entry[0]);

	return (struct sdxi_completion) {
		.cst_blk = &cq->entry[pos],
		.cst_blk_dma = cq->handle + off,
	};
}

struct sdxi_cq *sdxi_cq_alloc(struct sdxi_dev *sdxi, unsigned int count)
{
	dma_addr_t handle;
	struct sdxi_cq *cq;
	size_t sz = struct_size(cq, entry, count);

	cq = dma_alloc_coherent(sdxi->dev, sz, &handle, GFP_KERNEL);
	if (!cq)
		return NULL;

	cq->count = count;
	cq->handle = handle;
	return cq;
}

void sdxi_cq_free(struct sdxi_dev *sdxi, struct sdxi_cq *cq)
{
	size_t sz = struct_size(cq, entry, cq->count);

	dma_free_coherent(sdxi->dev, sz, cq, cq->handle);
}



struct sdxi_completion *sdxi_completion_alloc(struct sdxi_dev *sdxi)
{
	struct sdxi_cst_blk *cst_blk;
	dma_addr_t cst_blk_dma;

	/*
	 * Assume callers can't tolerate GFP_KERNEL and use
	 * GFP_NOWAIT. Add a gfp_t flags parameter if that changes.
	 */
	struct sdxi_completion *sc __free(kfree) = kmalloc(sizeof(*sc), GFP_NOWAIT);
	if (!sc)
		return NULL;

	cst_blk = dma_pool_zalloc(sdxi->cst_blk_pool, GFP_NOWAIT, &cst_blk_dma);
	if (!cst_blk)
		return NULL;

	cst_blk->signal = cpu_to_le64(1);

	*sc = (typeof(*sc)) {
		.sdxi        = sdxi,
		.cst_blk     = cst_blk,
		.cst_blk_dma = cst_blk_dma,
	};

	return_ptr(sc);
}

void sdxi_completion_free(struct sdxi_completion *sc)
{
	dma_pool_free(sc->sdxi->cst_blk_pool, sc->cst_blk, sc->cst_blk_dma);
	kfree(sc);
}

enum sdxi_completion_state sdxi_cst_blk_check(const struct sdxi_cst_blk *cst)
{
	u64 signal = le64_to_cpu(READ_ONCE(cst->signal));

	if (signal != SDXI_CST_BLK_SIGNAL_TERMINAL)
		return SDXI_COMPLETION_PENDING;
	/*
	 * The final ER state (and the operation's effects) are
	 * guaranteed visible only after a cleared signal is observed.
	 * See SDXI 1.0 5.6 Memory Consistency Model.
	 */
	dma_rmb();

	if (FIELD_GET(SDXI_CST_BLK_ER, le32_to_cpu(cst->flags)))
		return SDXI_COMPLETION_ERROR;

	return SDXI_COMPLETION_DONE;
}
/*
 * A descriptor isn't done until this returns something other than
 * SDXI_COMPLETION_PENDING.
 */
enum sdxi_completion_state
sdxi_completion_check(const struct sdxi_completion *sc)
{
	return sdxi_cst_blk_check(sc->cst_blk);
}

int sdxi_cst_blk_poll(const struct sdxi_cst_blk *cst)
{
	enum sdxi_completion_state state;
	int ret;

	ret = read_poll_timeout(sdxi_cst_blk_check, state,
				state != SDXI_COMPLETION_PENDING,
				10, USEC_PER_SEC, false, cst);
	if (ret)
		return ret;		/* -ETIMEDOUT */

	return state == SDXI_COMPLETION_ERROR ? -EIO : 0;
}

int sdxi_completion_poll(const struct sdxi_completion *sc)
{
	return sdxi_cst_blk_poll(sc->cst_blk);
}


void sdxi_completion_attach(struct sdxi_desc *desc,
			    const struct sdxi_completion *cs)
{
	sdxi_desc_set_csb(desc, cs->cst_blk_dma);
}
