/*
 * User space process management (IOMMU, PASID, etc.)
 *
 * Copyright (C) 2022 AMD, Inc. All rights reserved.
 *
 * Author: Wei Huang <wei.huang2@amd.com>
 */

#include <linux/device.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/idr.h>
#include <linux/dma-fence-array.h>
#include <linux/amd-iommu.h>
#include <linux/hashtable.h>
#include <asm/mmu.h>

#include "process.h"
#include "trace.h"

#define SDXI_PROCESS_LIST_SIZE	16
static DEFINE_MUTEX(process_list_mutex);
static DEFINE_HASHTABLE(process_list, SDXI_PROCESS_LIST_SIZE);
DEFINE_SRCU(process_list_srcu);

/**********************/
/* PROCESS MANAGEMENT */
/**********************/
static struct sdxi_process *find_process_by_mm(const struct mm_struct *mm)
{
	struct sdxi_process *process;

	hash_for_each_possible_rcu(process_list, process, list,
				   (uintptr_t)mm) {
		if (process->mm == mm)
			return process;
	}

	return NULL;
}

static struct sdxi_process *find_process(const struct task_struct *thread)
{
	struct sdxi_process *p;
	int idx;

	idx = srcu_read_lock(&process_list_srcu);
	p = find_process_by_mm(thread->mm);
	srcu_read_unlock(&process_list_srcu, idx);

	return p;
}

/****************************/
/* PROCESS PASID MANAGEMENT */
/****************************/
static u32 pasid_alloc(struct sdxi_dev *sdxi)
{
	u32 ret = 0;

	ret = ida_simple_get(&sdxi->pasid_ida, 1, sdxi->pasid_limit,
			     GFP_KERNEL);

	if (ret)
		return ret;

	return 0;
}

static void pasid_free(struct sdxi_dev *sdxi, u32 pasid)
{
	if (pasid)
		ida_simple_remove(&sdxi->pasid_ida, pasid);
}

void sdxi_unref_process(struct sdxi_process *p)
{
	/* NB: more checking to be done here based on kref count */
}

struct sdxi_process *sdxi_get_process(struct task_struct *thread)
{
	struct sdxi_process *process;

	if (!thread->mm)
		return ERR_PTR(-EINVAL);

	process = find_process(thread);
	if (!process)
		return ERR_PTR(-EINVAL);

	return process;
}

int sdxi_bind_process_to_device(struct sdxi_process *process)
{
	struct sdxi_cxt *cxt = process->cxt;
	struct sdxi_dev *sdxi;
	int err;

	if (!cxt)
		return -EINVAL;

	sdxi = cxt->sdxi;
	/* alloc pasid */
	process->pasid = pasid_alloc(sdxi);
	if (process->pasid == 0)
		return -EBUSY;

	/* NB: more code to be added such as power management */
	err = amd_iommu_bind_pasid(sdxi->pdev, process->pasid,
				   process->lead_thread);

	if (err) {
		pasid_free(sdxi, process->pasid);
		return -EINVAL;
	}

	trace_sdxi_bind_process(sdxi, process->pasid);

	return 0;
}

void sdxi_unbind_process_to_device(struct sdxi_process *process)
{
	struct sdxi_cxt *cxt = process->cxt;
	struct sdxi_dev *sdxi;

	if (!cxt)
		return;

	sdxi = cxt->sdxi;

	amd_iommu_unbind_pasid(cxt->sdxi->pdev, process->pasid);
	pasid_free(cxt->sdxi, process->pasid);

	trace_sdxi_bind_process(sdxi, process->pasid);
}

struct sdxi_process *sdxi_create_process(struct file *filep)
{
	struct task_struct *thread = current;
	struct sdxi_process *process;
	int err = -ENOMEM;

	mutex_lock(&process_list_mutex);

	process = kzalloc(sizeof(*process), GFP_KERNEL);
	if (!process)
		return ERR_PTR(err);

	mutex_init(&process->mutex);
	process->mm = thread->mm;
	process->lead_thread = thread->group_leader;
	hash_add_rcu(process_list, &process->list, (uintptr_t)process->mm);
	get_task_struct(process->lead_thread);
	mutex_unlock(&process_list_mutex);

	return process;
}

void sdxi_destroy_process(struct sdxi_process *process)
{
	if (!process)
		return;

	mutex_lock(&process_list_mutex);

	put_task_struct(process->lead_thread);
	hash_del_rcu(&process->list);
	mutex_destroy(&process->mutex);
	kfree(process);

	mutex_unlock(&process_list_mutex);
}

/***************************/
/* DEVICE IOMMU MANAGEMENT */
/***************************/
#if IS_REACHABLE(CONFIG_AMD_IOMMU_V2)
static const u32 required_flags = AMD_IOMMU_DEVICE_FLAG_ATS_SUP |
	AMD_IOMMU_DEVICE_FLAG_PRI_SUP |
	AMD_IOMMU_DEVICE_FLAG_PASID_SUP;

static void iommu_pasid_shutdown_cb(struct pci_dev *pdev, u32 pasid)
{
	pr_info("PASID shutdown called: device=%s, pasid=%d\n",
		dev_name(&pdev->dev), pasid);
}

static int iommu_invalid_ppr_cb(struct pci_dev *pdev, u32 pasid,
				unsigned long address, u16 flags)
{
	pr_info("Invalid ppr called: device=%s, pasid=%d\n",
		dev_name(&pdev->dev), pasid);
	return AMD_IOMMU_INV_PRI_RSP_INVALID;
}

/* Bind all processes of SDXI from IOMMU */
static int iommu_bind_processes(struct sdxi_dev *sdxi)
{
	return 0;
}

/* Unbind all processes of SDXI from IOMMU */
static void iommu_unbind_processes(struct sdxi_dev *sdxi)
{
}

int sdxi_iommu_device_init(struct sdxi_dev *sdxi)
{
	struct pci_dev *pdev = sdxi->pdev;
	struct amd_iommu_device_info info;
	int err;

	info.flags = 0;
	err = amd_iommu_device_info(pdev, &info);
	if (err < 0) {
		pr_err("No IOMMU device info found\n");
		return -ENODEV;
	}

	if ((info.flags & required_flags) != required_flags) {
		pr_err_once("Require IOMMU flags ATS %i, PRI %i, PASID %i\n",
			    (info.flags & AMD_IOMMU_DEVICE_FLAG_ATS_SUP) != 0,
			    (info.flags & AMD_IOMMU_DEVICE_FLAG_PRI_SUP) != 0,
			    (info.flags & AMD_IOMMU_DEVICE_FLAG_PASID_SUP) != 0);

		return -ENODEV;
	}

	sdxi->pasid_limit = min_t(u32, sdxi->max_pasids, info.max_pasids);
	/* According to design, IOMMU v2 will be picked automatically if device
	 * supports PRI/ATS/PASID. Since SDXI device current doesn't declare
	 * PRI/ATS/PASID, we have to force pasid_limit to IOMMU max_pasids.
	 */
	//sdxi->pasid_limit = sdxi->max_pasids;
	err = amd_iommu_init_device(pdev, sdxi->pasid_limit);
	if (err < 0) {
		pr_err("Failed to init IOMMU for %s\n", dev_name(&pdev->dev));
		return -ENXIO;
	}

	ida_init(&sdxi->pasid_ida);
	sdxi->use_iommu_v2 = true;

	return 0;
}

void sdxi_iommu_device_exit(struct sdxi_dev *sdxi)
{
	iommu_unbind_processes(sdxi);
	amd_iommu_free_device(sdxi->pdev);
}

void sdxi_iommu_suspend(struct sdxi_dev *sdxi)
{
	if (!sdxi || !sdxi->use_iommu_v2)
		return;

	iommu_unbind_processes(sdxi);

	amd_iommu_set_invalidate_ctx_cb(sdxi->pdev, NULL);
	amd_iommu_set_invalid_ppr_cb(sdxi->pdev, NULL);
	amd_iommu_free_device(sdxi->pdev);
}

int sdxi_iommu_resume(struct sdxi_dev *sdxi)
{
	int err;

	if (!sdxi || !sdxi->use_iommu_v2)
		return 0;

	err = amd_iommu_init_device(sdxi->pdev, sdxi->pasid_limit);
	if (err)
		return -ENXIO;

	amd_iommu_set_invalidate_ctx_cb(sdxi->pdev,
					iommu_pasid_shutdown_cb);
	amd_iommu_set_invalid_ppr_cb(sdxi->pdev,
				     iommu_invalid_ppr_cb);

	err = iommu_bind_processes(sdxi);
	if (err) {
		amd_iommu_set_invalidate_ctx_cb(sdxi->pdev, NULL);
		amd_iommu_set_invalid_ppr_cb(sdxi->pdev, NULL);
		amd_iommu_free_device(sdxi->pdev);
		return err;
	}

	return 0;
}
#endif /* CONFIG_AMD_IOMMU_V2 */
