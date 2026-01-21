/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Header for sq and descriptor management
 *
 * Copyright (C) 2025 Advanced Micro Devices, Inc.
 */

#ifndef __SDXI_SQ_H
#define __SDXI_SQ_H

#include <linux/io-64-nonatomic-lo-hi.h>
#include <asm/barrier.h>

#include "sdxi.h"

struct sdxi_cxt {
	struct sdxi_dev *sdxi;	/* owner */
	unsigned int id;
	bool privileged;

	resource_size_t db_base;	/* doorbell MMIO base addr */
	__le64 __iomem *db;		/* doorbell virt addr */

	struct sdxi_cxt_ctl *cxt_ctl;
	dma_addr_t cxt_ctl_dma;

	struct sdxi_akey_table *akey_table;
	dma_addr_t akey_table_dma;

	struct sdxi_sq *sq;

	struct sdxi_process *process;	/* process reprsentation */

	struct sdxi_ring_state *ring_state;
};

enum sdxi_cxt_id {
	SDXI_ADMIN_CXT_ID = 0,
	SDXI_ANY_CXT_ID,
};

/* Context Control */
struct sdxi_cxt *sdxi_working_cxt_init(struct sdxi_dev *sdxi,
				       enum sdxi_cxt_id);
void sdxi_working_cxt_exit(struct sdxi_cxt *cxt);
struct sdxi_cxt *sdxi_kcxt_new(struct sdxi_dev *sdxi);

void sdxi_cxt_push_doorbell(struct sdxi_cxt *cxt, u64 index);

#endif /* __SDXI_SQ_H */
