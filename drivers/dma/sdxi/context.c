// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI submission queue (sq) and descriptor management
 *
 * Copyright (C) 2025 Advanced Micro Devices, Inc.
 */

#define pr_fmt(fmt)     "SDXI: " fmt

#include <linux/delay.h>
#include <linux/dma-direction.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/types.h>
#include <linux/wordpart.h>

#include "admin.h"
#include "context.h"
#include "hw.h"
#include "ring.h"
#include "sdxi.h"

/* Alloc sdxi_sq in kernel space */
static struct sdxi_sq *sdxi_sq_alloc(struct sdxi_cxt *cxt, int ring_entries)
{
	struct sdxi_dev *sdxi = cxt->sdxi;
	struct device *dev = sdxi_to_dev(sdxi);
	u64 write_index_ptr;
	struct sdxi_sq *sq;
	u64 ds_ring_ptr;
	u64 cxt_sts_ptr;
	u32 ds_ring_sz;

	/* alloc desc_ring */
	if (ring_entries > sdxi->max_ring_entries) {
		sdxi_err(sdxi, "%d ring entries requested, max is %llu\n",
			ring_entries, sdxi->max_ring_entries);
		return NULL;
	}

	sq = kzalloc(sizeof(*sq), GFP_KERNEL);
	if (!sq)
		return NULL;

	sq->ring_entries = ring_entries;
	sq->ring_size = sizeof(sq->desc_ring[0]) * sq->ring_entries;
	sq->desc_ring = dma_alloc_coherent(dev, sq->ring_size, &sq->ring_dma,
					   GFP_KERNEL);
	if (!sq->desc_ring)
		goto free_sq;

	sq->cxt_sts = dma_pool_zalloc(sdxi->cxt_sts_pool, GFP_KERNEL, &sq->cxt_sts_dma);
	if (!sq->cxt_sts)
		goto free_desc_ring;

	sq->write_index = dma_pool_zalloc(sdxi->write_index_pool, GFP_KERNEL,
					  &sq->write_index_dma);
	if (!sq->write_index)
		goto free_cxt_sts;

	write_index_ptr = FIELD_PREP(SDXI_CXT_CTL_WRITE_INDEX_PTR,
				     sq->write_index_dma >> 3);
	cxt_sts_ptr = FIELD_PREP(SDXI_CXT_CTL_CXT_STS_PTR,
				 sq->cxt_sts_dma >> 4);
	ds_ring_sz = sq->ring_size >> 6;

	cxt->cxt_ctl->write_index_ptr = cpu_to_le64(write_index_ptr);
	cxt->cxt_ctl->cxt_sts_ptr     = cpu_to_le64(cxt_sts_ptr);
	cxt->cxt_ctl->ds_ring_sz      = cpu_to_le32(ds_ring_sz);

	/* turn it on now */
	sq->cxt = cxt;
	cxt->sq = sq;
	ds_ring_ptr = (FIELD_PREP(SDXI_CXT_CTL_DS_RING_PTR, sq->ring_dma >> 6) |
		       FIELD_PREP(SDXI_CXT_CTL_VL, 1));
	dma_wmb();
	WRITE_ONCE(cxt->cxt_ctl->ds_ring_ptr, cpu_to_le64(ds_ring_ptr));

	sdxi_dbg(sdxi, "sq created, id=%d, cxt_ctl=%p\n"
		 "  desc ring addr:   v=0x%p:d=%pad\n"
		 "  write index addr: v=0x%p:d=%pad\n"
		 "  cxt status addr: v=0x%p:d=%pad\n",
		 cxt->id, cxt->cxt_ctl,
		 sq->desc_ring, &sq->ring_dma,
		 sq->write_index, &sq->write_index_dma,
		 sq->cxt_sts, &sq->cxt_sts_dma);

	return sq;

free_cxt_sts:
	dma_pool_free(sdxi->cxt_sts_pool, sq->cxt_sts, sq->cxt_sts_dma);
free_desc_ring:
	dma_free_coherent(dev, sq->ring_size, sq->desc_ring, sq->ring_dma);
free_sq:
	kfree(sq);
	return NULL;
}

static void sdxi_sq_free(struct sdxi_sq *sq)
{
	struct sdxi_cxt *cxt = sq->cxt;
	struct sdxi_dev *sdxi = cxt->sdxi;
	struct device *dev = sdxi_to_dev(sdxi);

	if (!cxt)
		return;

	dma_pool_free(sdxi->write_index_pool, sq->write_index, sq->write_index_dma);
	dma_pool_free(sdxi->cxt_sts_pool, sq->cxt_sts, sq->cxt_sts_dma);
	dma_free_coherent(dev, sq->ring_size, sq->desc_ring, sq->ring_dma);

	cxt->sq = NULL;
	kfree(sq);
}

/* Default size 1024 ==> 64KB descriptor ring, guaranteed */
#define DEFAULT_DESC_RING_ENTRIES	1024
static struct sdxi_sq *sdxi_sq_alloc_default(struct sdxi_cxt *cxt)
{
	return sdxi_sq_alloc(cxt, DEFAULT_DESC_RING_ENTRIES);
}

static void set_cxt_l1_entry(struct sdxi_dev *sdxi,
			     struct sdxi_cxt_l1_ent *l1_entry,
			     struct sdxi_cxt *cxt)
{
	u64 cxt_ctl_ptr;
	u64 akey_ptr;
	u32 misc0;

	cxt_ctl_ptr = (FIELD_PREP(SDXI_CXT_L1_ENT_VL, 1) |
		       FIELD_PREP(SDXI_CXT_L1_ENT_KA, 1) |
		       FIELD_PREP(SDXI_CXT_L1_ENT_CXT_CTL_PTR,
				  cxt->cxt_ctl_dma >> L1_CXT_CTRL_PTR_SHIFT));
	akey_ptr = (FIELD_PREP(SDXI_CXT_L1_ENT_AKEY_SZ,
			       akey_table_order(cxt->akey_table)) |
		    FIELD_PREP(SDXI_CXT_L1_ENT_AKEY_PTR,
			       cxt->akey_table_dma >> L1_CXT_AKEY_PTR_SHIFT));
	misc0 = FIELD_PREP(SDXI_CXT_L1_ENT_MAX_BUFFER, 11);

	*l1_entry = (struct sdxi_cxt_l1_ent) {
		.cxt_ctl_ptr = cpu_to_le64(cxt_ctl_ptr),
		.akey_ptr = cpu_to_le64(akey_ptr),
		.misc0 = cpu_to_le32(misc0),
		.opb_000_enb = cpu_to_le32(sdxi->op_grp_cap),
	};
}

static int config_cxt_tables(struct sdxi_dev *sdxi,
			     struct sdxi_cxt *cxt)
{
	struct sdxi_cxt_l1_ent *l1_entry;
	u8 l1_idx;

	if (WARN_ONCE(cxt->id > sdxi->max_cxtid,
		      "can't install cxt with id %u (limit %u)",
		      cxt->id, sdxi->max_cxtid))
		return -EINVAL;

	l1_idx = ID_TO_L1_INDEX(cxt->id);

	l1_entry = &sdxi->L1_table->entry[l1_idx];
	set_cxt_l1_entry(cxt->sdxi, l1_entry, cxt);
	/* fixme: need to send DSC_CXT_UPD to admin */

	return 0;
}

static void cleanup_cxt_tables(struct sdxi_dev *sdxi,
			       struct sdxi_cxt *cxt)
{
	struct sdxi_cxt_l1_ent *l1_entry;
	u8 l1_idx;

	if (!cxt)
		return;

	l1_idx = ID_TO_L1_INDEX(cxt->id);

	l1_entry = &sdxi->L1_table->entry[l1_idx];
	memset(l1_entry, 0, sizeof(*l1_entry));
	/* fixme: need to send DSC_CXT_UPD to admin */
}

static struct sdxi_cxt *alloc_cxt(struct sdxi_dev *sdxi)
{
	struct xa_limit limit = XA_LIMIT(0, sdxi->max_cxtid);
	u32 id;

	struct sdxi_cxt *cxt __free(kfree) = kzalloc(sizeof(*cxt), GFP_KERNEL);
	if (!cxt)
		return NULL;

	if (xa_alloc(&sdxi->client_cxts, &id, cxt, limit, GFP_KERNEL))
		return NULL;

	cxt->sdxi = sdxi;
	cxt->id = id;
	cxt->db = sdxi->dbs + id * sdxi->db_stride;
	ida_init(&cxt->akey_ida);

	return_ptr(cxt);
}

static void free_cxt(struct sdxi_cxt *cxt)
{
	struct sdxi_dev *sdxi = cxt->sdxi;

	dma_free_coherent(sdxi_to_dev(sdxi), sizeof(*cxt->akey_table),
			  cxt->akey_table, cxt->akey_table_dma);
	kfree(cxt->ring_state);
	ida_destroy(&cxt->akey_ida);
	xa_erase(&sdxi->client_cxts, cxt->id);
	kfree(cxt);
}

/* alloc context resources and populate context table */
static struct sdxi_cxt *sdxi_cxt_alloc(struct sdxi_dev *sdxi)
{
	struct sdxi_cxt *cxt;

	mutex_lock(&sdxi->cxt_lock);

	cxt = alloc_cxt(sdxi);
	if (!cxt)
		goto drop_cxt_lock;

	cxt->akey_table = dma_alloc_coherent(sdxi_to_dev(sdxi),
					     sizeof(*cxt->akey_table),
					     &cxt->akey_table_dma, GFP_KERNEL);
	if (!cxt->akey_table)
		goto release_cxt;

	cxt->cxt_ctl = dma_pool_zalloc(sdxi->cxt_ctl_pool, GFP_KERNEL,
				       &cxt->cxt_ctl_dma);
	if (!cxt->cxt_ctl)
		goto release_akey_table;

	cxt->ring_state = kzalloc(sizeof(*cxt->ring_state), GFP_KERNEL);
	if (!cxt->ring_state)
		goto release_cxt_ctl;

	if (config_cxt_tables(sdxi, cxt))
		goto release_ring_state;

	mutex_unlock(&sdxi->cxt_lock);
	return cxt;

release_ring_state:
	kfree(cxt->ring_state);
release_cxt_ctl:
	dma_pool_free(sdxi->cxt_ctl_pool, cxt->cxt_ctl, cxt->cxt_ctl_dma);
release_akey_table:
	dma_free_coherent(sdxi_to_dev(sdxi), sizeof(*cxt->akey_table),
			  cxt->akey_table, cxt->akey_table_dma);
release_cxt:
	free_cxt(cxt);
drop_cxt_lock:
	mutex_unlock(&sdxi->cxt_lock);
	return NULL;
}

/* clear context table and free context resources */
static void sdxi_cxt_free(struct sdxi_cxt *cxt)
{
	struct sdxi_dev *sdxi = cxt->sdxi;

	mutex_lock(&sdxi->cxt_lock);

	cleanup_cxt_tables(sdxi, cxt);
	dma_pool_free(sdxi->cxt_ctl_pool, cxt->cxt_ctl, cxt->cxt_ctl_dma);
	free_cxt(cxt);

	mutex_unlock(&sdxi->cxt_lock);
}

struct sdxi_cxt *sdxi_admin_cxt_init(struct sdxi_dev *sdxi)
{
	struct sdxi_cxt *cxt;
	struct sdxi_sq *sq;

	cxt = sdxi_cxt_alloc(sdxi);
	if (!cxt) {
		sdxi_err(sdxi, "failed to alloc a new context\n");
		return NULL;
	}

	/* Ensure this is the first context allocated */
	if (WARN(cxt->id != SDXI_ADMIN_CXT_ID, "admin cxt id = %u?\n", cxt->id))
		return NULL;

	sq = sdxi_sq_alloc_default(cxt);
	if (!sq) {
		sdxi_err(sdxi, "failed to alloc a submission queue (sq)\n");
		goto err_sq_alloc;
	}

	sdxi_ring_state_init(cxt->ring_state, &sq->cxt_sts->read_index,
			     sq->write_index, sq->ring_entries, sq->desc_ring);

	return cxt;

err_sq_alloc:
	sdxi_cxt_free(cxt);

	return NULL;
}

/*
 * Allocate a context for in-kernel use. Starting the context is the
 * caller's responsibility.
 */
struct sdxi_cxt *sdxi_kcxt_new(struct sdxi_dev *sdxi)
{
	struct sdxi_cxt *cxt = sdxi_cxt_alloc(sdxi);
	struct sdxi_sq *sq;

	if (!cxt)
		return NULL;

	if (!sdxi_sq_alloc_default(cxt)) {
		sdxi_cxt_free(cxt);
		return NULL;
	}

	sq = cxt->sq;
	sdxi_ring_state_init(cxt->ring_state, &sq->cxt_sts->read_index,
			     sq->write_index, sq->ring_entries, sq->desc_ring);

	return cxt;
}

static const char *cxt_sts_state_str(enum cxt_sts_state state)
{
	static const char *const context_states[] = {
		[CXTV_STOP_SW]  = "stopped (software)",
		[CXTV_RUN]      = "running",
		[CXTV_STOPG_SW] = "stopping (software)",
		[CXTV_STOP_FN]  = "stopped (function)",
		[CXTV_STOPG_FN] = "stopping (function)",
		[CXTV_ERR_FN]   = "error",
	};
	const char *str = "unknown";

	switch (state) {
	case CXTV_STOP_SW:
	case CXTV_RUN:
	case CXTV_STOPG_SW:
	case CXTV_STOP_FN:
	case CXTV_STOPG_FN:
	case CXTV_ERR_FN:
		str = context_states[state];
	}

	return str;
}

void sdxi_working_cxt_exit(struct sdxi_cxt *cxt)
{
	if (!sdxi_cxt_is_admin(cxt))
		sdxi_adm_stop_cxt(cxt);
	sdxi_sq_free(cxt->sq);
	sdxi_cxt_free(cxt);
}

void sdxi_cxt_push_doorbell(struct sdxi_cxt *cxt, u64 index)
{
	enum cxt_sts_state state = sdxi_cxt_sts_state(cxt->sq->cxt_sts);

	/*
	 * To do: cache doorbell values as they're written to
	 * eliminate redundant doorbell writes.
	 */

	/* Ensure write index is visible. */
	dma_wmb();
	sdxi_dbg(cxt->sdxi, "Ringing context %u (state = %s) doorbell: %llu\n",
		 cxt->id, cxt_sts_state_str(state), index);
	iowrite64(index, cxt->db);
}
