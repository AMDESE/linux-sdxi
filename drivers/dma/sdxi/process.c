// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI userspace process and SVA management.
 *
 * Copyright Advanced Micro Devices, Inc.
 */

#include <linux/iommu.h>
#include <linux/module.h>
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#include <linux/slab.h>

#include "context.h"
#include "process.h"
#include "sdxi.h"

static void sdxi_process_cleanup(struct sdxi_process *process)
{
	struct sdxi_cxt *cxt;
	int ret;

	mutex_lock(&process->mutex);
	cxt = process->cxt;
	if (cxt)
		sdxi_cxt_get(cxt);
	mutex_unlock(&process->mutex);

	if (!cxt)
		return;

	ret = sdxi_cxt_notify_mm_release(cxt);
	if (ret)
		dev_err(process->sdxi->dev,
			"failed to quiesce context %u during mm release: %d\n",
			cxt->id, ret);
	sdxi_cxt_put(cxt);
}

static void sdxi_mmu_notifier_release(struct mmu_notifier *notifier,
				      struct mm_struct *mm)
{
	struct sdxi_process *process;

	process = container_of(notifier, struct sdxi_process, notifier);
	sdxi_process_cleanup(process);
}

static const struct mmu_notifier_ops sdxi_mmu_notifier_ops = {
	.release = sdxi_mmu_notifier_release,
};

static int sdxi_process_register_notifier(struct sdxi_process *process)
{
	int ret;

	if (process->notifier_registered)
		return 0;

	ret = mmu_notifier_register(&process->notifier, process->mm);
	if (ret)
		return ret;

	process->notifier_registered = true;
	return 0;
}

struct iommu_sva *
sdxi_process_detach_sva_locked(struct sdxi_process *process, u32 *pasid)
{
	struct iommu_sva *sva;

	lockdep_assert_held(&process->mutex);

	sva = process->sva;
	if (!sva) {
		if (pasid)
			*pasid = 0;
		return NULL;
	}

	if (pasid)
		*pasid = process->pasid;
	process->sva = NULL;
	process->pasid = 0;

	return sva;
}

void sdxi_process_unbind_sva(struct sdxi_process *process,
			     struct iommu_sva *sva, u32 pasid)
{
	if (process->notifier_registered) {
		process->notifier_registered = false;
		mmu_notifier_unregister(&process->notifier, process->mm);
	}

	if (sva)
		iommu_sva_unbind_device(sva);
}

static void sdxi_process_free(struct sdxi_process *process)
{
	struct sdxi_dev *sdxi = process->sdxi;
	struct iommu_sva *sva;
	u32 pasid;

	mutex_lock(&process->mutex);
	sva = sdxi_process_detach_sva_locked(process, &pasid);
	mutex_unlock(&process->mutex);

	sdxi_process_unbind_sva(process, sva, pasid);
	put_task_struct(process->lead_thread);
	mmdrop(process->mm);
	kfree(process);
	module_put(sdxi->bus_ops->owner);
	put_device(&sdxi->chardev);
}

void sdxi_process_get(struct sdxi_process *process)
{
	refcount_inc(&process->refs);
}

void sdxi_process_put(struct sdxi_process *process)
{
	if (process && refcount_dec_and_test(&process->refs))
		sdxi_process_free(process);
}

int sdxi_process_bind(struct sdxi_process *process)
{
	struct iommu_sva *sva;
	u32 pasid;
	int ret;

	if (!process->sdxi)
		return -ENODEV;

	sva = iommu_sva_bind_device(process->sdxi->dev, process->mm);
	if (IS_ERR(sva))
		return PTR_ERR(sva);

	pasid = iommu_sva_get_pasid(sva);
	if (pasid == IOMMU_PASID_INVALID) {
		ret = -EINVAL;
		goto unbind;
	}

	/*
	 * Register after the IOMMU notifier so SDXI quiesces the context
	 * before SVA translations disappear during exit_mmap().
	 */
	ret = sdxi_process_register_notifier(process);
	if (ret)
		goto unbind;

	process->pasid = pasid;
	process->sva = sva;
	return 0;

unbind:
	iommu_sva_unbind_device(sva);
	return ret;
}

struct sdxi_process *sdxi_process_create(struct sdxi_dev *sdxi)
{
	struct task_struct *task = current;
	struct sdxi_process *process;

	if (!task->mm)
		return ERR_PTR(-EINVAL);
	if (!try_module_get(sdxi->bus_ops->owner))
		return ERR_PTR(-ENODEV);
	get_device(&sdxi->chardev);

	process = kzalloc_obj(*process, GFP_KERNEL);
	if (!process) {
		put_device(&sdxi->chardev);
		module_put(sdxi->bus_ops->owner);
		return ERR_PTR(-ENOMEM);
	}

	refcount_set(&process->refs, 1);
	mutex_init(&process->mutex);
	process->lead_thread = task->group_leader;
	get_task_struct(process->lead_thread);
	process->mm = task->mm;
	mmgrab(process->mm);
	process->sdxi = sdxi;
	process->notifier.ops = &sdxi_mmu_notifier_ops;
	INIT_HLIST_NODE(&process->notifier.hlist);

	return process;
}
