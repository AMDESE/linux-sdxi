// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI context management
 *
 * Copyright Advanced Micro Devices, Inc.
 */

#define pr_fmt(fmt)     "SDXI: " fmt

#include <linux/align.h>
#include <linux/bitfield.h>
#include <linux/bug.h>
#include <linux/cleanup.h>
#include <linux/device/devres.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/errno.h>
#include <linux/idr.h>
#include <linux/iommu.h>
#include <linux/overflow.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <asm/barrier.h>
#include <asm/rwonce.h>

#include "admin.h"
#include "completion.h"
#include "context.h"
#include "descriptor.h"
#include "hw.h"
#include "intr.h"
#include "process.h"
#include "ring.h"
#include "sdxi.h"
#include "submission.h"

#define DEFAULT_DESC_RING_ENTRIES 1024
#define SDXI_CXT_QUIESCE_TIMEOUT_MS 5000U

enum {
	/*
	 * The admin context always has ID 0. See SDXI 1.0 3.5
	 * Administrative Context (Context 0).
	 */
	SDXI_ADMIN_CXT_ID = 0,
};

static void sdxi_cxt_cleanup_workfn(struct work_struct *work);

/*
 * Free context and its resources. @cxt may be partially allocated but
 * must have ->sdxi set.
 */
static void sdxi_free_cxt(struct sdxi_cxt *cxt)
{
	struct sdxi_dev *sdxi = cxt->sdxi;

	/* Release the id if this is a registered client context. */
	if (cxt->registered)
		WARN_ON(xa_erase(&sdxi->client_cxts, cxt->id) != cxt);

	if (cxt->cxt_ctl)
		dma_pool_free(sdxi->cxt_ctl_pool, cxt->cxt_ctl,
			      cxt->cxt_ctl_dma);
	if (cxt->akey_table)
		dma_free_coherent(sdxi->dev, sizeof(*cxt->akey_table),
				  cxt->akey_table, cxt->akey_table_dma);
	if (cxt->cst_pool)
		sdxi_cst_pool_destroy(sdxi, cxt->cst_pool);
	if (cxt->sq)
		sdxi_sq_free(sdxi, cxt->sq);
	ida_destroy(&cxt->akey_ida);
	mutex_destroy(&cxt->akey_lock);
	mutex_destroy(&cxt->cleanup_lock);
	kfree(cxt->ring_state);
	kfree(cxt);
	put_device(&sdxi->chardev);
}

DEFINE_FREE(sdxi_cxt, struct sdxi_cxt *, if (_T) sdxi_free_cxt(_T))

/* Allocate a context and its control structure hierarchy in memory. */
static struct sdxi_cxt *sdxi_alloc_cxt(struct sdxi_dev *sdxi)
{
	struct device *dev = sdxi->dev;
	struct sdxi_cxt *cxt __free(sdxi_cxt) = kzalloc(sizeof(*cxt), GFP_KERNEL);

	if (!cxt)
		return NULL;

	cxt->sdxi = sdxi;
	get_device(&sdxi->chardev);
	refcount_set(&cxt->refs, 1);
	mutex_init(&cxt->cleanup_lock);
	mutex_init(&cxt->akey_lock);
	spin_lock_init(&cxt->intr_lock);
	init_waitqueue_head(&cxt->poll_wq);
	INIT_DELAYED_WORK(&cxt->cleanup_work, sdxi_cxt_cleanup_workfn);
	cxt->intr_vector = -1;
	cxt->intr_irq = -1;
	ida_init(&cxt->akey_ida);
	cxt->pasid = IOMMU_NO_PASID;
	cxt->opb_000_enb = sdxi->op_grp_cap;

	cxt->akey_table = dma_alloc_coherent(dev, sizeof(*cxt->akey_table),
					     &cxt->akey_table_dma, GFP_KERNEL);
	if (!cxt->akey_table)
		return NULL;
	memset(cxt->akey_table, 0, sizeof(*cxt->akey_table));

	cxt->cxt_ctl = dma_pool_zalloc(sdxi->cxt_ctl_pool, GFP_KERNEL,
				       &cxt->cxt_ctl_dma);
	if (!cxt->cxt_ctl)
		return NULL;

	return_ptr(cxt);
}

/* Claim completion storage before making a ring reservation irrevocable. */
static int sdxi_cxt_reserve(struct sdxi_cxt *cxt, size_t nr,
			    struct sdxi_ring_resv *resv,
			    struct sdxi_completion *comp)
{
	int err;

	err = sdxi_cst_pool_get_wait(cxt->cst_pool, comp);
	if (err)
		return err;

	err = sdxi_ring_reserve(cxt->ring_state, nr, resv);
	if (err)
		sdxi_cst_pool_put(cxt->cst_pool, comp->cst_blk);

	return err;
}

static int sdxi_cxt_poll_completion(struct sdxi_cxt *cxt,
				    const struct sdxi_completion *comp)
{
	int err = sdxi_cst_blk_poll(comp->cst_blk);

	/*
	 * A timeout does not end hardware ownership. Keep these administrative
	 * blocks claimed until context teardown, even if they complete later.
	 * Repeated timeouts can exhaust the pool; allocation then times out too.
	 */
	if (err != -ETIMEDOUT)
		sdxi_cst_pool_put(cxt->cst_pool, comp->cst_blk);
	sdxi_ring_wake_up(cxt->ring_state);

	return err;
}

/*
 * Signal the function that a client context's control structures have
 * been modified so it discards any privately cached copies of them.
 * DSC_SYNC.CXT is required before the operation can be considered
 * complete.
 */
static int sdxi_cxt_update_locked(const struct sdxi_cxt *cxt)
{
	struct sdxi_cxt *adm = to_admin_cxt(cxt);
	struct sdxi_slot upd, sync;
	struct sdxi_ring_resv resv;
	struct sdxi_completion comp;
	int err;

	might_sleep();
	lockdep_assert_held(&cxt->sdxi->admin_lock);
	if (cxt->sdxi->admin_dead)
		return -EIO;

	err = sdxi_cxt_reserve(adm, 2, &resv, &comp);
	if (err)
		return err;

	upd = sdxi_ring_resv_slot(&resv, 0);
	sync = sdxi_ring_resv_slot(&resv, 1);

	sdxi_encode_cxt_upd(sdxi_slot_desc(upd), &(const struct sdxi_cxt_upd) {
			.level = SDXI_CXT_UPD_LVL_L1,
			.range = sdxi_cxt_range_single(cxt->id),
		});
	sdxi_encode_sync(sdxi_slot_desc(sync), &(const struct sdxi_sync) {
			.filter = SDXI_SYNC_FLT_CXT,
			.range = sdxi_cxt_range_single(cxt->id),
		});
	sdxi_cxt_submit(adm, upd, NULL, 0);
	sdxi_cxt_submit(adm, sync, &comp, SDXI_CXT_SUBMIT_KICK);

	return sdxi_cxt_poll_completion(adm, &comp);
}

static int sdxi_alloc_kernel_submission(struct sdxi_cxt *cxt)
{
	cxt->ring_state = kzalloc_obj(*cxt->ring_state, GFP_KERNEL);
	if (!cxt->ring_state)
		return -ENOMEM;

	cxt->sq = sdxi_sq_alloc(cxt->sdxi, DEFAULT_DESC_RING_ENTRIES);
	if (!cxt->sq)
		return -ENOMEM;

	cxt->cst_pool = sdxi_cst_pool_create(cxt->sdxi,
					     DEFAULT_DESC_RING_ENTRIES);
	if (!cxt->cst_pool)
		return -ENOMEM;

	sdxi_ring_state_init(cxt->ring_state, cxt->sq);
	return 0;
}

struct sdxi_cxt_ctl_cfg {
	dma_addr_t ds_ring_ptr;
	dma_addr_t cxt_sts_ptr;
	dma_addr_t write_index_ptr;
	u32 ds_ring_sz;
	u8 qos;
	u8 csa;
	bool se;
};

static int configure_cxt_ctl(struct sdxi_cxt_ctl *ctl, const struct sdxi_cxt_ctl_cfg *cfg)
{
	u64 ds_ring_ptr, cxt_sts_ptr, write_index_ptr;

	write_index_ptr = FIELD_PREP(SDXI_CXT_CTL_WRITE_INDEX_PTR,
				     cfg->write_index_ptr >> WRT_INDEX_PTR_SHIFT);
	cxt_sts_ptr = FIELD_PREP(SDXI_CXT_CTL_CXT_STS_PTR,
				 cfg->cxt_sts_ptr >> CXT_STATUS_PTR_SHIFT);

	*ctl = (typeof(*ctl)) {
		.ds_ring_sz      = cpu_to_le32(cfg->ds_ring_sz),
		.cxt_sts_ptr     = cpu_to_le64(cxt_sts_ptr),
		.write_index_ptr = cpu_to_le64(write_index_ptr),
	};

	ds_ring_ptr = FIELD_PREP(SDXI_CXT_CTL_VL, 1) |
		      FIELD_PREP(SDXI_CXT_CTL_QOS, cfg->qos) |
		      FIELD_PREP(SDXI_CXT_CTL_SE, cfg->se) |
		      FIELD_PREP(SDXI_CXT_CTL_CSA, cfg->csa) |
		      FIELD_PREP(SDXI_CXT_CTL_DS_RING_PTR,
				 cfg->ds_ring_ptr >> DESC_RING_BASE_PTR_SHIFT);
	/* Ensure other fields are visible before hw sees vl=1. */
	dma_wmb();
	WRITE_ONCE(ctl->ds_ring_ptr, cpu_to_le64(ds_ring_ptr));

	return 0;
}

static void invalidate_cxt_ctl(struct sdxi_cxt_ctl *ctl)
{
	u64 ds_ring_ptr = le64_to_cpu(ctl->ds_ring_ptr);

	FIELD_MODIFY(SDXI_CXT_CTL_VL, &ds_ring_ptr, 0);
	WRITE_ONCE(ctl->ds_ring_ptr, cpu_to_le64(ds_ring_ptr));
	dma_wmb();
	*ctl = (typeof(*ctl)) { 0 };
}

/*
 * Logical representation of CXT_L1_ENT subfields.
 */
struct sdxi_cxt_L1_cfg {
	dma_addr_t cxt_ctl_ptr;
	dma_addr_t akey_ptr;
	u32 cxt_pasid;
	u32 opb_000_enb;
	u16 max_buffer;
	u8 akey_sz;
	bool ka;
	bool pv;
};

static int configure_L1_entry(struct sdxi_cxt_L1_ent *ent,
			      const struct sdxi_cxt_L1_cfg *cfg)
{
	u64 cxt_ctl_ptr, akey_ptr;
	u32 misc0;

	if (WARN_ON_ONCE(!IS_ALIGNED(cfg->cxt_ctl_ptr, SZ_64)))
		return -EFAULT;
	if (WARN_ON_ONCE(!IS_ALIGNED(cfg->akey_ptr, SZ_4K)))
		return -EFAULT;

	akey_ptr = FIELD_PREP(SDXI_CXT_L1_ENT_AKEY_SZ, cfg->akey_sz) |
		   FIELD_PREP(SDXI_CXT_L1_ENT_AKEY_PTR,
			      cfg->akey_ptr >> L1_CXT_AKEY_PTR_SHIFT);

	misc0 = FIELD_PREP(SDXI_CXT_L1_ENT_PASID, cfg->cxt_pasid) |
		FIELD_PREP(SDXI_CXT_L1_ENT_MAX_BUFFER, cfg->max_buffer);

	*ent = (typeof(*ent)) {
		.akey_ptr    = cpu_to_le64(akey_ptr),
		.misc0       = cpu_to_le32(misc0),
		.opb_000_enb = cpu_to_le32(cfg->opb_000_enb),
	};

	cxt_ctl_ptr = FIELD_PREP(SDXI_CXT_L1_ENT_VL, 1) |
		      FIELD_PREP(SDXI_CXT_L1_ENT_KA, cfg->ka) |
		      FIELD_PREP(SDXI_CXT_L1_ENT_PV, cfg->pv) |
		      FIELD_PREP(SDXI_CXT_L1_ENT_CXT_CTL_PTR,
				 cfg->cxt_ctl_ptr >> L1_CXT_CTRL_PTR_SHIFT);
	/* Ensure other fields are visible before hw sees vl=1. */
	dma_wmb();
	WRITE_ONCE(ent->cxt_ctl_ptr, cpu_to_le64(cxt_ctl_ptr));

	return 0;
}

static void invalidate_L1_entry(struct sdxi_cxt_L1_ent *ent)
{
	u64 cxt_ctl_ptr = le64_to_cpu(ent->cxt_ctl_ptr);

	FIELD_MODIFY(SDXI_CXT_L1_ENT_VL, &cxt_ctl_ptr, 0);
	WRITE_ONCE(ent->cxt_ctl_ptr, cpu_to_le64(cxt_ctl_ptr));
	dma_wmb();
	*ent = (typeof(*ent)) { 0 };
}

static struct sdxi_cxt_L1_table *
sdxi_get_L1_table(struct sdxi_dev *sdxi, u16 l2_idx)
{
	struct sdxi_cxt_L1_table *table;
	struct sdxi_cxt_L2_ent *L2_ent;
	dma_addr_t dma;
	u64 lv01_ptr;

	lockdep_assert_held(&sdxi->cxt_lock);

	table = sdxi->L1_tables[l2_idx];
	if (table)
		return table;

	table = dmam_alloc_coherent(sdxi->dev, sizeof(*table), &dma, GFP_KERNEL);
	if (!table)
		return NULL;
	memset(table, 0, sizeof(*table));

	L2_ent = &sdxi->L2_table->entry[l2_idx];
	lv01_ptr = FIELD_PREP(SDXI_CXT_L2_ENT_LV01_PTR,
			      dma >> ilog2(SZ_4K));
	L2_ent->lv01_ptr = cpu_to_le64(lv01_ptr);
	dma_wmb();
	FIELD_MODIFY(SDXI_CXT_L2_ENT_VL, &lv01_ptr, 1);
	WRITE_ONCE(L2_ent->lv01_ptr, cpu_to_le64(lv01_ptr));

	sdxi->L1_tables[l2_idx] = table;
	sdxi->L1_dma[l2_idx] = dma;

	return table;
}

static void sdxi_put_L1_table(struct sdxi_dev *sdxi, u16 l2_idx)
{
	struct sdxi_cxt_L1_table *table;
	struct sdxi_cxt_L2_ent *L2_ent;

	lockdep_assert_held(&sdxi->cxt_lock);

	if (sdxi->L1_users[l2_idx])
		return;

	table = sdxi->L1_tables[l2_idx];
	if (!table)
		return;

	L2_ent = &sdxi->L2_table->entry[l2_idx];
	WRITE_ONCE(L2_ent->lv01_ptr, 0);
	dma_wmb();

	sdxi->L1_tables[l2_idx] = NULL;
	sdxi->L1_dma[l2_idx] = 0;
}

/*
 * Publish the context control structure hierarchy to the SDXI
 * implementation. This may allocate an L1 table page, so it is fallible.
 */
static int sdxi_publish_cxt(struct sdxi_cxt *cxt,
			    const struct sdxi_cxt_ctl_cfg *ctl_cfg)
{
	struct sdxi_cxt_L1_cfg L1_cfg;
	struct sdxi_cxt_L1_table *L1_table;
	struct sdxi_cxt_L1_ent *ent;
	u16 l2_idx;
	u8 l1_idx;
	int err;

	if (WARN_ONCE(cxt->id > cxt->sdxi->max_cxtid,
		      "can't install cxt with id %u (limit %u)",
		      cxt->id, cxt->sdxi->max_cxtid))
		return -EINVAL;

	err = configure_cxt_ctl(cxt->cxt_ctl, ctl_cfg);
	if (err)
		return err;

	l2_idx = ID_TO_L2_INDEX(cxt->id);
	l1_idx = ID_TO_L1_INDEX(cxt->id);

	mutex_lock(&cxt->sdxi->cxt_lock);
	L1_table = sdxi_get_L1_table(cxt->sdxi, l2_idx);
	if (!L1_table) {
		err = -ENOMEM;
		goto out_unlock;
	}
	ent = &L1_table->entry[l1_idx];

	L1_cfg = (typeof(L1_cfg)) {
		.ka          = 1,
		.pv          = cxt->pasid_valid,
		.cxt_ctl_ptr = cxt->cxt_ctl_dma,
		.akey_sz     = akey_table_order(cxt->akey_table),
		.akey_ptr    = cxt->akey_table_dma,
		.cxt_pasid   = cxt->pasid,
		.max_buffer  = cxt->sdxi->max_buffer,
		.opb_000_enb = cxt->opb_000_enb,
	};

	err = configure_L1_entry(ent, &L1_cfg);
	if (!err)
		cxt->sdxi->L1_users[l2_idx]++;

out_unlock:
	mutex_unlock(&cxt->sdxi->cxt_lock);
	if (err) {
		invalidate_cxt_ctl(cxt->cxt_ctl);
	} else {
		cxt->published = true;
		cxt->update_pending = false;
	}
	return err;
}

/* Invalidate a context. */
static void sdxi_rescind_cxt(struct sdxi_cxt *cxt)
{
	struct sdxi_cxt_L1_table *L1_table;
	struct sdxi_dev *sdxi = cxt->sdxi;
	u16 l2_idx = ID_TO_L2_INDEX(cxt->id);
	u8 l1_idx = ID_TO_L1_INDEX(cxt->id);

	if (!cxt->published)
		return;

	mutex_lock(&sdxi->cxt_lock);
	L1_table = sdxi->L1_tables[l2_idx];
	if (WARN_ON_ONCE(!L1_table))
		goto out_unlock;

	invalidate_L1_entry(&L1_table->entry[l1_idx]);
	if (WARN_ON_ONCE(!sdxi->L1_users[l2_idx]))
		goto out_unlock;

	sdxi->L1_users[l2_idx]--;

out_unlock:
	mutex_unlock(&sdxi->cxt_lock);
	invalidate_cxt_ctl(cxt->cxt_ctl);
	cxt->published = false;
	cxt->update_pending = true;
}

/* Empty L1 tables remain published until the function has stopped. */
static void sdxi_cxt_finish_unpublish(struct sdxi_cxt *cxt,
				      bool function_stopped)
{
	struct sdxi_dev *sdxi = cxt->sdxi;
	u16 l2_idx = ID_TO_L2_INDEX(cxt->id);

	if (!cxt->update_pending)
		return;

	if (function_stopped) {
		mutex_lock(&sdxi->cxt_lock);
		sdxi_put_L1_table(sdxi, l2_idx);
		mutex_unlock(&sdxi->cxt_lock);
	}
	cxt->update_pending = false;
}

static int sdxi_cxt_unpublish(struct sdxi_cxt *cxt)
{
	int err;

	mutex_lock(&cxt->sdxi->admin_lock);
	if (cxt->published)
		sdxi_rescind_cxt(cxt);
	if (!cxt->update_pending) {
		err = 0;
		goto out_unlock;
	}

	err = sdxi_cxt_update_locked(cxt);
	if (!err)
		sdxi_cxt_finish_unpublish(cxt, false);

out_unlock:
	mutex_unlock(&cxt->sdxi->admin_lock);
	return err;
}

/* Hardware has stopped, so no update/sync is needed before freeing tables. */
static void sdxi_cxt_force_unpublish(struct sdxi_cxt *cxt)
{
	if (cxt->published)
		sdxi_rescind_cxt(cxt);
	sdxi_cxt_finish_unpublish(cxt, true);
}

void sdxi_cxt_get(struct sdxi_cxt *cxt)
{
	refcount_inc(&cxt->refs);
}

void sdxi_cxt_put(struct sdxi_cxt *cxt)
{
	if (cxt && refcount_dec_and_test(&cxt->refs))
		sdxi_free_cxt(cxt);
}

struct sdxi_cxt *sdxi_cxt_get_by_id(struct sdxi_dev *sdxi, u16 cxt_id)
{
	struct sdxi_cxt *cxt;

	xa_lock(&sdxi->client_cxts);
	cxt = xa_load(&sdxi->client_cxts, cxt_id);
	if (cxt && !refcount_inc_not_zero(&cxt->refs))
		cxt = NULL;
	xa_unlock(&sdxi->client_cxts);

	return cxt;
}

/* Free resources only after update/sync or after the function has stopped. */
static void sdxi_cxt_release_resources(struct sdxi_cxt *cxt)
{
	struct sdxi_dev *sdxi = cxt->sdxi;

	sdxi_cxt_exit_intr(cxt);

	if (cxt->registered) {
		WARN_ON(xa_erase(&sdxi->client_cxts, cxt->id) != cxt);
		cxt->registered = false;
	}

	if (cxt->cxt_ctl) {
		dma_pool_free(sdxi->cxt_ctl_pool, cxt->cxt_ctl,
			      cxt->cxt_ctl_dma);
		cxt->cxt_ctl = NULL;
		cxt->cxt_ctl_dma = 0;
	}
	if (cxt->akey_table) {
		mutex_lock(&cxt->akey_lock);
		dma_free_coherent(sdxi->dev, sizeof(*cxt->akey_table),
				  cxt->akey_table, cxt->akey_table_dma);
		cxt->akey_table = NULL;
		cxt->akey_table_dma = 0;
		mutex_unlock(&cxt->akey_lock);
	}
	if (cxt->cst_pool) {
		sdxi_cst_pool_destroy(sdxi, cxt->cst_pool);
		cxt->cst_pool = NULL;
	}
	if (cxt->sq) {
		sdxi_sq_free(sdxi, cxt->sq);
		cxt->sq = NULL;
	}
	kfree(cxt->ring_state);
	cxt->ring_state = NULL;
}

static void sdxi_cxt_finish_release(struct sdxi_cxt *cxt,
				    struct sdxi_process *process)
{
	struct iommu_sva *sva = NULL;
	u32 pasid = 0;

	wake_up_poll(&cxt->poll_wq, EPOLLHUP);
	sdxi_cxt_release_resources(cxt);

	if (process) {
		mutex_lock(&process->mutex);
		sva = sdxi_process_detach_sva_locked(process, &pasid);
		mutex_unlock(&process->mutex);

		sdxi_process_unbind_sva(process, sva, pasid);

		/* Keep CREATE_CXT excluded until the old SVA is fully unbound. */
		mutex_lock(&process->mutex);
		if (process->cxt == cxt)
			process->cxt = NULL;
		mutex_unlock(&process->mutex);
		sdxi_process_put(process);
	}

	/* Drop the context's base ownership reference. */
	sdxi_cxt_put(cxt);
}

static bool sdxi_cxt_cleanup_requested(const struct sdxi_cxt *cxt)
{
	return cxt->handle_closed || cxt->mm_dead || READ_ONCE(cxt->fatal);
}

static void sdxi_cxt_queue_cleanup_locked(struct sdxi_cxt *cxt,
					  unsigned long delay)
{
	lockdep_assert_held(&cxt->cleanup_lock);

	if (!cxt->cleanup_stopping && !cxt->resources_released)
		mod_delayed_work(system_percpu_wq, &cxt->cleanup_work, delay);
}

static int sdxi_cxt_quiesce_locked(struct sdxi_cxt *cxt,
				   unsigned int timeout_ms, u32 *cst_flags,
				   bool interruptible)
{
	u32 flags = 0;
	int ret = 0;

	lockdep_assert_held(&cxt->cleanup_lock);

	if (cxt->resources_released)
		return -ENODEV;
	if (cxt->quiesced)
		goto out;

	if (!cxt->started || sdxi_cxt_is_admin(cxt))
		goto quiesced;

	if (!timeout_ms)
		timeout_ms = SDXI_CXT_QUIESCE_TIMEOUT_MS;

	ret = sdxi_adm_stop_cxt_sync(cxt, timeout_ms, &flags,
				     interruptible);
	if (ret)
		return ret;

quiesced:
	cxt->started = false;
	cxt->quiesced = true;
	cxt->quiesce_cst_flags = flags;
out:
	if (cst_flags)
		*cst_flags = cxt->quiesce_cst_flags;
	return 0;
}

static bool sdxi_cxt_cleanup(struct sdxi_cxt *cxt,
			     struct sdxi_process **process_out)
{
	struct sdxi_process *process = NULL;
	bool force_release = false;
	bool destroy = false;
	int ret;

	mutex_lock(&cxt->cleanup_lock);
	if (cxt->resources_released || !sdxi_cxt_cleanup_requested(cxt))
		goto out_unlock;

	if (!cxt->quiesced) {
		ret = sdxi_cxt_quiesce_locked(cxt, 0, NULL, false);
		if (ret) {
			dev_err(cxt->sdxi->dev,
				"failed to quiesce context %u: %d; quiescing function\n",
				cxt->id, ret);
			sdxi_dev_fail(cxt->sdxi);
			cxt->started = false;
			cxt->quiesced = true;
			cxt->quiesce_cst_flags = 0;
			force_release = true;
		}
	}
	if (cxt->vma_refs)
		goto out_unlock;

	if (!force_release) {
		ret = sdxi_cxt_unpublish(cxt);
		if (ret) {
			dev_err(cxt->sdxi->dev,
				"failed to synchronize context %u release: %d; quiescing function\n",
				cxt->id, ret);
			sdxi_dev_fail(cxt->sdxi);
			force_release = true;
		}
	}
	if (force_release)
		sdxi_cxt_force_unpublish(cxt);

	cxt->resources_released = true;
	cxt->cleanup_stopping = true;
	process = cxt->process;
	cxt->process = NULL;
	destroy = true;

out_unlock:
	mutex_unlock(&cxt->cleanup_lock);
	if (!destroy)
		return false;

	*process_out = process;
	return true;
}

static void sdxi_cxt_cleanup_workfn(struct work_struct *work)
{
	struct sdxi_cxt *cxt = container_of(to_delayed_work(work),
					     struct sdxi_cxt, cleanup_work);
	struct sdxi_process *process = NULL;
	struct sdxi_dev *sdxi = cxt->sdxi;
	bool destroy = false;

	down_read(&sdxi->state_lock);
	if (sdxi->online)
		destroy = sdxi_cxt_cleanup(cxt, &process);
	up_read(&sdxi->state_lock);

	if (destroy)
		sdxi_cxt_finish_release(cxt, process);
}

/* Device teardown has already stopped hardware, so force resource release. */
static void sdxi_cxt_force_exit(struct sdxi_cxt *cxt)
{
	struct sdxi_process *process = NULL;
	bool destroy = false;

	if (!cxt || !refcount_inc_not_zero(&cxt->refs))
		return;

	mutex_lock(&cxt->cleanup_lock);
	cxt->cleanup_stopping = true;
	mutex_unlock(&cxt->cleanup_lock);
	cancel_delayed_work_sync(&cxt->cleanup_work);

	mutex_lock(&cxt->cleanup_lock);
	if (!cxt->resources_released) {
		sdxi_cxt_force_unpublish(cxt);
		cxt->started = false;
		cxt->quiesced = true;
		cxt->resources_released = true;
		process = cxt->process;
		cxt->process = NULL;
		destroy = true;
	}
	mutex_unlock(&cxt->cleanup_lock);

	if (destroy)
		sdxi_cxt_finish_release(cxt, process);
	/* Drop the temporary reference acquired above. */
	sdxi_cxt_put(cxt);
}

static int sdxi_cxt_doorbell_offset(const struct sdxi_cxt *cxt,
				    size_t *offset);
static int sdxi_cxt_set_kernel_doorbell(struct sdxi_cxt *cxt);

int sdxi_admin_cxt_init(struct sdxi_dev *sdxi)
{
	struct sdxi_cxt_ctl_cfg ctl_cfg;
	struct sdxi_sq *sq;
	int err;

	struct sdxi_cxt *cxt __free(sdxi_cxt) = sdxi_alloc_cxt(sdxi);
	if (!cxt)
		return -ENOMEM;

	err = sdxi_alloc_kernel_submission(cxt);
	if (err)
		return err;

	sq = cxt->sq;
	/* SDXI 1.0 4.1.8.4.b: Set CXT_STS.state to CXTV_RUN. */
	sq->cxt_sts.state = FIELD_PREP(SDXI_CXT_STS_STATE, CXTV_RUN);
	cxt->id = SDXI_ADMIN_CXT_ID;
	err = sdxi_cxt_set_kernel_doorbell(cxt);
	if (err)
		return err;

	ctl_cfg = (typeof(ctl_cfg)) {
		.se              = 1,
		.csa             = 1,
		.ds_ring_ptr     = sdxi_sq_ring_dma(cxt->sq),
		.ds_ring_sz      = cxt->sq->count,
		.cxt_sts_ptr     = sdxi_sq_cxt_sts_dma(cxt->sq),
		.write_index_ptr = sdxi_sq_write_index_dma(cxt->sq),
	};
	err = sdxi_publish_cxt(cxt, &ctl_cfg);
	if (err)
		return err;

	cxt->started = true;
	sdxi->admin_cxt = no_free_ptr(cxt);

	return 0;
}

void sdxi_admin_cxt_exit(struct sdxi_dev *sdxi)
{
	struct sdxi_cxt *cxt = sdxi->admin_cxt;

	if (!cxt)
		return;

	sdxi->admin_cxt = NULL;
	sdxi_cxt_force_exit(cxt);
}

/*
 * Temporary owner for context id until it can be assigned to a
 * context object; enables scope-based cleanup.
 */
struct sdxi_cxt_id {
	struct sdxi_dev *sdxi;
	u16 index;
};

static void sdxi_cxt_id_dtor(const struct sdxi_cxt_id *cxt_id)
{
	if (cxt_id->index == 0)
		return;
	WARN_ON(xa_erase(&cxt_id->sdxi->client_cxts, cxt_id->index) != NULL);
}

static struct sdxi_cxt_id sdxi_cxt_id_ctor(struct sdxi_dev *sdxi)
{
	struct xa_limit limit = XA_LIMIT(1, sdxi->max_cxtid);
	u32 index;

	return (struct sdxi_cxt_id) {
		.sdxi = sdxi,
		.index = xa_alloc(&sdxi->client_cxts, &index, NULL,
				  limit, GFP_KERNEL) ? 0 : (u16)index,
	};
}

DEFINE_CLASS(sdxi_cxt_id, struct sdxi_cxt_id, sdxi_cxt_id_dtor(&_T),
	     sdxi_cxt_id_ctor(sdxi), struct sdxi_dev *sdxi)

static bool sdxi_cxt_id_valid(const struct sdxi_cxt_id *cxt_id)
{
	return cxt_id->index > 0;
}

static int sdxi_cxt_doorbell_offset(const struct sdxi_cxt *cxt,
				    size_t *offset)
{
	struct sdxi_dev *sdxi = cxt->sdxi;
	size_t value;

	if (check_mul_overflow((size_t)cxt->id, (size_t)sdxi->db_stride,
			       &value) ||
	    value > sdxi->db_size ||
	    sdxi->db_stride > sdxi->db_size - value)
		return -ERANGE;

	if (offset)
		*offset = value;
	return 0;
}

static int sdxi_cxt_set_kernel_doorbell(struct sdxi_cxt *cxt)
{
	size_t offset;
	int err;

	if (WARN_ON_ONCE(!cxt->sq))
		return -EINVAL;
	err = sdxi_cxt_doorbell_offset(cxt, &offset);
	if (err)
		return err;

	cxt->sq->doorbell = cxt->sdxi->dbs + offset;
	return 0;
}

/*
 * Transfer the reserved ID to the context and store its pointer in client_cxts.
 * sdxi_free_cxt() releases the ID.
 */
static void sdxi_cxt_id_assign(struct sdxi_cxt *cxt, struct sdxi_cxt_id *cxt_id)
{
	/* We reserved the space in the constructor so this should not fail. */
	WARN_ON(xa_store(&cxt_id->sdxi->client_cxts,
			 cxt_id->index, cxt, GFP_KERNEL));
	cxt->id = cxt_id->index;
	cxt->registered = true;
	cxt_id->index = 0;
}

static struct sdxi_cxt *sdxi_alloc_client_cxt(struct sdxi_dev *sdxi)
{
	CLASS(sdxi_cxt_id, id)(sdxi);
	struct sdxi_cxt *cxt __free(sdxi_cxt) = NULL;

	if (!sdxi_cxt_id_valid(&id))
		return NULL;

	cxt = sdxi_alloc_cxt(sdxi);
	if (!cxt)
		return NULL;

	sdxi_cxt_id_assign(cxt, &id);
	if (sdxi_cxt_doorbell_offset(cxt, NULL))
		return NULL;
	mutex_lock(&sdxi->cxt_lock);
	cxt->mmap_gen = ++sdxi->mmap_gen;
	if (!cxt->mmap_gen)
		cxt->mmap_gen = ++sdxi->mmap_gen;
	mutex_unlock(&sdxi->cxt_lock);

	return_ptr(cxt);
}

/*
 * Allocate a context for in-kernel use. Starting the context is the
 * caller's responsibility.
 */
struct sdxi_cxt *sdxi_cxt_new(struct sdxi_dev *sdxi)
{
	struct sdxi_cxt_ctl_cfg ctl_cfg;
	struct sdxi_cxt *cxt;
	int err;

	cxt = sdxi_alloc_client_cxt(sdxi);
	if (!cxt)
		return NULL;

	err = sdxi_alloc_kernel_submission(cxt);
	if (err)
		goto put_cxt;
	err = sdxi_cxt_set_kernel_doorbell(cxt);
	if (err)
		goto put_cxt;

	ctl_cfg = (typeof(ctl_cfg)) {
		.se              = 1,
		.csa             = 1,
		.ds_ring_ptr     = sdxi_sq_ring_dma(cxt->sq),
		.ds_ring_sz      = cxt->sq->count,
		.cxt_sts_ptr     = sdxi_sq_cxt_sts_dma(cxt->sq),
		.write_index_ptr = sdxi_sq_write_index_dma(cxt->sq),
	};
	if (sdxi_publish_cxt(cxt, &ctl_cfg))
		goto put_cxt;

	return cxt;

put_cxt:
	sdxi_cxt_put(cxt);
	return NULL;
}

struct sdxi_cxt *sdxi_ucxt_new(struct sdxi_dev *sdxi, u32 ring_entries,
			       u64 ds_ring, u64 write_index, u64 cxt_sts,
			       u32 pasid, u32 opb_000_enb)
{
	struct sdxi_cxt_ctl_cfg ctl_cfg = {
		.ds_ring_ptr = ds_ring,
		.ds_ring_sz = ring_entries,
		.cxt_sts_ptr = cxt_sts,
		.write_index_ptr = write_index,
	};
	struct sdxi_cxt *cxt;

	cxt = sdxi_alloc_client_cxt(sdxi);
	if (!cxt)
		return NULL;

	cxt->pasid_valid = true;
	cxt->pasid = pasid;
	cxt->opb_000_enb = opb_000_enb;

	if (sdxi_publish_cxt(cxt, &ctl_cfg)) {
		sdxi_cxt_put(cxt);
		return NULL;
	}

	return cxt;
}

/*
 * Release all tracked client contexts during device teardown. Hardware access
 * to client resources must have ceased before release.
 */
void sdxi_client_cxts_exit(struct sdxi_dev *sdxi)
{
	struct sdxi_cxt *cxt;
	unsigned long index;
	size_t l2_idx;

	xa_for_each(&sdxi->client_cxts, index, cxt)
		sdxi_cxt_force_exit(cxt);
	xa_destroy(&sdxi->client_cxts);

	/* Reclaim empty pages retained to keep L2 pointers stable at runtime. */
	mutex_lock(&sdxi->cxt_lock);
	for (l2_idx = 0; l2_idx < ARRAY_SIZE(sdxi->L1_tables); l2_idx++)
		sdxi_put_L1_table(sdxi, l2_idx);
	mutex_unlock(&sdxi->cxt_lock);
}

/*
 * Attach a claimed, initialized completion block to a descriptor slot.
 * The descriptor is not published; the caller sets the valid bit (and
 * kicks) once the operation is fully encoded.
 */
void sdxi_cxt_attach_cst(struct sdxi_slot slot,
			 const struct sdxi_completion *comp)
{
	struct sdxi_desc *desc = sdxi_slot_desc(slot);

	/*
	 * We use simple (non-atomic) completion status mode only; set the
	 * descriptor's CSR bit. See SDXI 1.0 4.4.2 Completion-Status Modes.
	 */
	sdxi_desc_set_csr(desc);
	sdxi_desc_set_csb(desc, comp->cst_blk_dma);
}

void sdxi_cxt_submit(struct sdxi_cxt *cxt, struct sdxi_slot slot,
		     const struct sdxi_completion *comp, enum sdxi_submit_flags flags)
{
	struct sdxi_desc *desc = sdxi_slot_desc(slot);

	if (flags & SDXI_CXT_SUBMIT_FENCE)
		sdxi_desc_set_fence(desc);

	if (comp)
		sdxi_cxt_attach_cst(slot, comp);

	sdxi_desc_make_valid(desc);

	if (flags & SDXI_CXT_SUBMIT_KICK)
		sdxi_cxt_kick(cxt);
}

/*
 * Release an unused, stopped client context. On update/sync failure the
 * context remains owned by the device and its resources are retained for
 * cleanup after function shutdown; the caller must not reuse it.
 */
int sdxi_cxt_exit(struct sdxi_cxt *cxt)
{
	struct sdxi_process *process = NULL;
	bool destroy = false;
	int ret = 0;

	if (!cxt)
		return -EINVAL;
	if (WARN_ON(sdxi_cxt_is_admin(cxt)))
		return -EINVAL;
	if (!refcount_inc_not_zero(&cxt->refs))
		return -ENODEV;

	mutex_lock(&cxt->cleanup_lock);
	cxt->cleanup_stopping = true;
	mutex_unlock(&cxt->cleanup_lock);
	cancel_delayed_work_sync(&cxt->cleanup_work);

	mutex_lock(&cxt->cleanup_lock);
	if (cxt->resources_released)
		goto out_unlock;
	if (cxt->vma_refs) {
		ret = -EBUSY;
		goto out_unlock;
	}

	ret = sdxi_cxt_quiesce_locked(cxt, 0, NULL, false);
	if (ret)
		goto out_retain;

	ret = sdxi_cxt_unpublish(cxt);
	if (ret)
		goto out_retain;

	cxt->resources_released = true;
	process = cxt->process;
	cxt->process = NULL;
	destroy = true;
	goto out_unlock;

out_retain:
	dev_err(cxt->sdxi->dev,
		"context %u release failed (%d), retaining resources until function shutdown\n",
		cxt->id, ret);
out_unlock:
	mutex_unlock(&cxt->cleanup_lock);

	if (destroy)
		sdxi_cxt_finish_release(cxt, process);
	/* Drop the temporary reference acquired above. */
	sdxi_cxt_put(cxt);
	return ret;
}

int sdxi_cxt_quiesce(struct sdxi_cxt *cxt, unsigned int timeout_ms,
		     u32 *cst_flags)
{
	int ret;

	if (!cxt)
		return -EINVAL;

	mutex_lock(&cxt->cleanup_lock);
	ret = sdxi_cxt_quiesce_locked(cxt, timeout_ms, cst_flags, true);
	if (!ret && sdxi_cxt_cleanup_requested(cxt))
		sdxi_cxt_queue_cleanup_locked(cxt, 0);
	mutex_unlock(&cxt->cleanup_lock);

	return ret;
}

bool sdxi_cxt_is_user(const struct sdxi_cxt *cxt)
{
	return cxt && cxt->id && READ_ONCE(cxt->pasid_valid) &&
	       READ_ONCE(cxt->process);
}

bool sdxi_cxt_is_fatal(const struct sdxi_cxt *cxt)
{
	return !cxt || READ_ONCE(cxt->fatal);
}

void sdxi_cxt_kill(struct sdxi_cxt *cxt)
{
	if (!cxt)
		return;

	mutex_lock(&cxt->cleanup_lock);
	if (cxt->fatal) {
		mutex_unlock(&cxt->cleanup_lock);
		return;
	}
	cxt->fatal = true;
	if (sdxi_cxt_is_user(cxt))
		sdxi_cxt_queue_cleanup_locked(cxt, 0);
	mutex_unlock(&cxt->cleanup_lock);

	wake_up_poll(&cxt->poll_wq, EPOLLERR);
}

void sdxi_cxt_kill_stopped(struct sdxi_cxt *cxt)
{
	bool newly_fatal;

	if (!cxt)
		return;

	mutex_lock(&cxt->cleanup_lock);
	newly_fatal = !cxt->fatal;
	cxt->fatal = true;
	cxt->started = false;
	cxt->quiesced = true;
	cxt->quiesce_cst_flags = 0;
	if (sdxi_cxt_is_user(cxt))
		sdxi_cxt_queue_cleanup_locked(cxt, 0);
	mutex_unlock(&cxt->cleanup_lock);

	if (newly_fatal)
		wake_up_poll(&cxt->poll_wq, EPOLLERR);
}

void sdxi_cxt_release_user_handle(struct sdxi_cxt *cxt)
{
	if (!cxt)
		return;

	mutex_lock(&cxt->cleanup_lock);
	cxt->handle_closed = true;
	if (!cxt->resources_released)
		sdxi_cxt_queue_cleanup_locked(cxt, 0);
	mutex_unlock(&cxt->cleanup_lock);
}

int sdxi_cxt_notify_mm_release(struct sdxi_cxt *cxt)
{
	struct sdxi_dev *sdxi;
	int ret = 0;

	if (!cxt)
		return -EINVAL;
	sdxi = cxt->sdxi;

	down_read(&sdxi->state_lock);
	mutex_lock(&cxt->cleanup_lock);
	cxt->mm_dead = true;
	if (!cxt->resources_released) {
		if (sdxi->online) {
			ret = sdxi_cxt_quiesce_locked(cxt, 0, NULL, false);
			if (ret) {
				dev_err(cxt->sdxi->dev,
					"failed to quiesce context %u during mm release: %d; quiescing function\n",
					cxt->id, ret);
				sdxi_dev_fail(cxt->sdxi);
				cxt->started = false;
				cxt->quiesced = true;
				cxt->quiesce_cst_flags = 0;
			}
		}
		sdxi_cxt_queue_cleanup_locked(cxt, 0);
	}
	mutex_unlock(&cxt->cleanup_lock);
	up_read(&sdxi->state_lock);

	return ret;
}

void sdxi_cxt_vma_open(struct sdxi_cxt *cxt)
{
	if (!cxt)
		return;

	sdxi_cxt_get(cxt);
	mutex_lock(&cxt->cleanup_lock);
	cxt->vma_refs++;
	mutex_unlock(&cxt->cleanup_lock);
}

void sdxi_cxt_vma_close(struct sdxi_cxt *cxt)
{
	if (!cxt)
		return;

	mutex_lock(&cxt->cleanup_lock);
	if (WARN_ON_ONCE(!cxt->vma_refs))
		goto out_unlock;

	cxt->vma_refs--;
	if (!cxt->resources_released && sdxi_cxt_cleanup_requested(cxt))
		sdxi_cxt_queue_cleanup_locked(cxt, 0);

out_unlock:
	mutex_unlock(&cxt->cleanup_lock);
	sdxi_cxt_put(cxt);
}
