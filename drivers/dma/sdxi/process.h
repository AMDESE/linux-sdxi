/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SDXI userspace process state.
 *
 * Copyright Advanced Micro Devices, Inc.
 */

#ifndef DMA_SDXI_PROCESS_H
#define DMA_SDXI_PROCESS_H

#include <linux/mmu_notifier.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/types.h>

struct iommu_sva;
struct sdxi_cxt;
struct sdxi_dev;

struct sdxi_process {
	refcount_t refs;
	struct mutex mutex;		/* context and SVA serialization */
	struct task_struct *lead_thread;
	struct mm_struct *mm;
	struct mmu_notifier notifier;
	bool notifier_registered;

	struct sdxi_dev *sdxi;
	struct sdxi_cxt *cxt;
	struct iommu_sva *sva;
	u32 pasid;
};

struct sdxi_process *sdxi_process_create(struct sdxi_dev *sdxi);
void sdxi_process_get(struct sdxi_process *process);
void sdxi_process_put(struct sdxi_process *process);
int sdxi_process_bind(struct sdxi_process *process);
struct iommu_sva *
sdxi_process_detach_sva_locked(struct sdxi_process *process, u32 *pasid);
void sdxi_process_unbind_sva(struct sdxi_process *process,
			     struct iommu_sva *sva, u32 pasid);

#endif /* DMA_SDXI_PROCESS_H */
