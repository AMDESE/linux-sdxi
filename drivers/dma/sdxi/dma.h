/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright Advanced Micro Devices, Inc. */

#ifndef DMA_SDXI_DMA_H
#define DMA_SDXI_DMA_H

#include "../virt-dma.h"
#include "descriptor.h"

struct sdxi_dev;
struct sdxi_cxt;
struct sdxi_cst_blk;

struct sdxi_dma_chan {
	struct virt_dma_chan vchan;
	struct sdxi_cxt *cxt;
	unsigned int vector;
	unsigned int irq;
	struct sdxi_akey_ent *akey;
	/*
	 * Issued transactions waiting for ring space. Guarded by vchan.lock.
	 */
	struct list_head pending;
	/* Synchronization state is also guarded by vchan.lock. */
	struct sdxi_cst_blk *sync_cst;
	u64 sync_index;
	bool sync_polling;
};

struct sdxi_dma_txd {
	struct virt_dma_desc vdesc;
	struct sdxi_copy copy;	/* Copy operation parameters */
	/*
	 * This transaction's entry in the context's completion array,
	 * bound to its ring slot at issue time. NULL until issued.
	 */
	struct sdxi_cst_blk *cst;
	u64 copy_index;
	u64 retire_index; /* Includes the terminator for the last copy in a batch. */
};

#if IS_ENABLED(CONFIG_KUNIT)
bool sdxi_dma_drain_locked(struct sdxi_dma_chan *sdchan);
void sdxi_dma_reap_locked(struct sdxi_dma_chan *sdchan);
#endif

int sdxi_dma_register(struct sdxi_dev *sdxi);

#endif /* DMA_SDXI_DMA_H */
