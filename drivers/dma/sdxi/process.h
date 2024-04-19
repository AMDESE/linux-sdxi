/*
 * User space process management
 *
 * Copyright (C) 2022 AMD, Inc. All rights reserved.
 *
 * Author: Wei Huang <wei.huang2@amd.com>
 *
 */

#ifndef __SDXI_PROCESS_H
#define __SDXI_PROCESS_H

#include <linux/mmu_notifier.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/workqueue.h>

#include "sdxi.h"

/* User Space Process Info */
struct sdxi_process {
	struct hlist_node list;

	struct mutex mutex;
	struct task_struct *lead_thread;
	void *mm;				/* pointer to mm_struct */
	struct mmu_notifier mmu_notifier;	/* mm_struct notifier */

	struct sdxi_cxt *cxt;
	u32 pasid;				/* no meaning if !cxt */
};

/* SDXI Device IOMMU Management */
#if IS_REACHABLE(CONFIG_AMD_IOMMU_V2)
int sdxi_iommu_device_init(struct sdxi_dev *sdxi);
void sdxi_iommu_device_exit(struct sdxi_dev *sdxi);
void sdxi_iommu_suspend(struct sdxi_dev *sdxi);
int sdxi_iommu_resume(struct sdxi_dev *sdxi);
#else
static inline int sdxi_iommu_device_init(struct sdxi_dev *sdxi)
{
#if IS_MODULE(CONFIG_AMD_IOMMU_V2)
	WARN_ONCE(1, "iommu_v2 module is not usable by SDXI");
#endif
	return 0;
}

static inline void sdxi_iommu_device_exit(struct sdxi_dev *sdxi)
{
}

static inline void sdxi_iommu_suspend(struct sdxi_dev *sdxi)
{
}

static inline int sdxi_iommu_resume(struct sdxi_dev *sdxi)
{
	return 0;
}
#endif /* CONFIG_AMD_IOMMU_V2 */

/* User Process Management */
struct sdxi_process *sdxi_create_process(struct file *filep);
void sdxi_destroy_process(struct sdxi_process *p);
int sdxi_bind_process_to_device(struct sdxi_process *p);
void sdxi_unbind_process_to_device(struct sdxi_process *p);
void sdxi_unref_process(struct sdxi_process *p);
struct sdxi_process *sdxi_get_process(struct task_struct *thread);

#endif /* __SDXI_PROCESS_H */
