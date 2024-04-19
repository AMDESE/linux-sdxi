/*
 * SDXI hardware device driver
 *
 * Copyright (C) 2022 AMD, Inc. All rights reserved.
 *
 * Author: Wei Huang <wei.huang2@amd.com>
 */

#define dev_fmt(fmt)    "SDXI: " fmt

#include <linux/module.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <asm/mmu.h>
#include <linux/ptrace.h>

#include "sdxi.h"
#include "pci.h"
#include "context.h"
#include "process.h"

#define CREATE_TRACE_POINTS
#include "trace.h"

static bool dma_engine;
module_param(dma_engine, bool, 0644);
MODULE_PARM_DESC(dma_engine, "Enable DMA engine interface (default: false)");

LIST_HEAD(sdxi_device_list);

static void set_cxt_l2_entry(struct sdxi_dev *sdxi,
			     struct cxt_l2_entry *l2_entry,
			     struct cxt_l1_entry *l1_table)
{
	struct device *dev = &sdxi->pdev->dev;
	dma_addr_t l1_addr;

	if (l1_table) {
		/* already set, nothing to do. NB: maybe do checking */
		if (l2_entry->vl)
			return;

		l1_addr = dma_map_single(dev, l1_table, L1_TABLE_SIZE,
					 DMA_TO_DEVICE);
		if (dma_mapping_error(dev, l1_addr)) {
			dev_err(dev, "dma_map_single for L1 table failed\n");
			return;
		}

		l2_entry->l1_ptr = l1_addr >> L2_CXT_L1_BASE_SHIFT;
		l2_entry->vl = 1;
	} else {
		memset(l2_entry, 0, sizeof(*l2_entry));
	}
}

static void set_cxt_l1_entry(struct sdxi_dev *sdxi,
			     struct cxt_l1_entry *l1_entry,
			     struct sdxi_cxt *cxt)
{
	struct device *dev = &sdxi->pdev->dev;

	if (cxt) {
		/* NB: More need to be done */
		cxt->cce_addr = dma_map_single(dev, &cxt->cce,
					       sizeof(struct cxt_ctl_entry),
					       DMA_TO_DEVICE);
		if (dma_mapping_error(dev, cxt->cce_addr)) {
			dev_err(dev, "dma_map for cxt ctl addr failed\n");
			return;
		}

		/* akey handling */
		cxt->akey_addr = dma_map_single(dev, cxt->akey,
						cxt->akey_entries * sizeof(struct akey_entry),
						DMA_TO_DEVICE);
		if (dma_mapping_error(dev, cxt->akey_addr))  {
			dev_err(dev, "dma_map for akey table failed\n");
			dma_unmap_single(dev, cxt->cce_addr, sizeof(struct cxt_ctl_entry),
					 DMA_TO_DEVICE);
			return;
		}

		l1_entry->cxt_ctl_ptr = cxt->cce_addr >> L1_CXT_CTL_PTR_SHIFT;
		l1_entry->akey_tbl_ptr = cxt->akey_addr >> L1_CXT_AKEY_PTR_SHIFT;
		l1_entry->akey_tbl_size = (cxt->akey_entries * sizeof(struct akey_entry) >> 12) - 1;
		l1_entry->opb_000_enb = sdxi->op_grp_cap;
		l1_entry->vl = 1;
		l1_entry->ka = 1;
		l1_entry->max_buf = 11;

		cxt->akey[0].vl = 1;
	} else {
		memset(l1_entry, 0, sizeof(*l1_entry));
	}
}

static void config_cxt_table_entries(struct cxt_l2_entry *l2_table,
				     struct cxt_l1_entry *l1_table,
				     struct sdxi_cxt *cxt,
				     bool clear)
{
	u16 id;
	struct cxt_l2_entry *l2_entry;
	struct cxt_l1_entry *l1_entry;
	struct sdxi_dev *sdxi = cxt->sdxi;

	if (!cxt || !l1_table || !l2_table)
		return;

	id = cxt->id;
	l2_entry = l2_table + ID_TO_L2_INDEX(id);
	l1_entry = l1_table + ID_TO_L1_INDEX(id);

	if (!clear) {
		set_cxt_l2_entry(sdxi, l2_entry, l1_table);
		set_cxt_l1_entry(sdxi, l1_entry, cxt);
	} else {
		memset(l1_entry, 0, sizeof(*l1_entry));
	}
}

static int config_cxt_tables(struct sdxi_dev *sdxi,
			     struct sdxi_cxt *cxt)
{
	u16 id, l2_idx, l1_idx;
	struct cxt_l2_entry *l2_table = sdxi->l2_table;
	struct cxt_l1_entry *l1_table;

	if (!cxt)
		return -EINVAL;

	id = cxt->id;
	l2_idx = ID_TO_L2_INDEX(id);
	l1_idx = ID_TO_L1_INDEX(id);

	/* allocate l1 table if needed */
	l1_table = sdxi->l1_table_array[l2_idx];
	if (!l1_table) {
		gfp_t gfp_flags;
		unsigned long order;

		gfp_flags = GFP_KERNEL | __GFP_ZERO;
		order = get_order(L1_TABLE_SIZE);
		l1_table = (struct cxt_l1_entry *)__get_free_pages(gfp_flags,
								   order);

		if (!l1_table)
			return -ENOMEM;

		sdxi->l1_table_array[l2_idx] = l1_table;
	}

	/* configure l2 and l1 entries */
	config_cxt_table_entries(l2_table, l1_table, cxt, false);

	return 0;
}

static void cleanup_cxt_tables(struct sdxi_dev *sdxi,
			       struct sdxi_cxt *cxt)
{
	u16 id, l2_idx, l1_idx;
	struct cxt_l2_entry *l2_table = sdxi->l2_table;
	struct cxt_l1_entry *l1_table;

	if (!cxt)
		return;

	id = cxt->id;
	l2_idx = ID_TO_L2_INDEX(id);
	l1_idx = ID_TO_L1_INDEX(id);

	l1_table = sdxi->l1_table_array[l2_idx];
	/* clear l1 entry */
	config_cxt_table_entries(l2_table, l1_table, cxt, true);
}

static struct sdxi_cxt *alloc_cxt(struct sdxi_dev *sdxi)
{
	struct sdxi_cxt *cxt;
	u16 id, l2_idx, l1_idx;
	struct akey_entry *akey;
	int entries = DEFAULT_AKEY_NUM;

	if (sdxi->cxt_count >= sdxi->max_cxts)
		return NULL;

	if (entries > sdxi->max_akeys)
		return NULL;

	/* search for an empty context slot */
	for (id = 0; id < sdxi->max_cxts; id++) {
		l2_idx = ID_TO_L2_INDEX(id);
		l1_idx = ID_TO_L1_INDEX(id);

		if (sdxi->cxt_array[l2_idx] == NULL) {
			int sz = sizeof(struct sdxi_cxt *) * L1_TABLE_ENTRIES;
			struct sdxi_cxt **ptr = kzalloc(sz, GFP_KERNEL);

			sdxi->cxt_array[l2_idx] = ptr;
			if (!(sdxi->cxt_array[l2_idx]))
				return NULL;
		}

		cxt = (sdxi->cxt_array)[l2_idx][l1_idx];
		/* found one empty slot */
		if (!cxt)
			break;
	}

	/* nothing found, bail... */
	if (id == sdxi->max_cxts)
		return NULL;

	/* alloc context and initialize it */
	cxt = kzalloc(sizeof(struct sdxi_cxt), GFP_KERNEL);
	if (!cxt)
		return NULL;

	akey = kzalloc(entries * sizeof(struct akey_entry), GFP_KERNEL);
	if (!akey) {
		kfree(cxt);
		return NULL;
	}

	INIT_LIST_HEAD(&cxt->list);
	cxt->sdxi = sdxi;
	cxt->id = id;
	cxt->akey_entries = entries;
	cxt->akey = akey;
	cxt->db_base = sdxi->dbs_bar + id * sdxi->db_stride;
	cxt->db = sdxi->dbs + id * sdxi->db_stride;

	sdxi->cxt_array[l2_idx][l1_idx] = cxt;
	list_add(&cxt->list, &sdxi->cxt_list);
	sdxi->cxt_count++;

	return cxt;
}

static void free_cxt(struct sdxi_cxt *cxt)
{
	struct sdxi_dev *sdxi = cxt->sdxi;
	u16 l2_idx, l1_idx;

	trace_sdxi_free_cxt(sdxi, cxt);

	sdxi->cxt_count--;
	list_del(&cxt->list);
	kfree(cxt->akey);
	kfree(cxt);

	l2_idx = ID_TO_L2_INDEX(cxt->id);
	l1_idx = ID_TO_L1_INDEX(cxt->id);
	(sdxi->cxt_array)[l2_idx][l1_idx] = NULL;
}

/* alloc context resources and populate context table */
struct sdxi_cxt *sdxi_cxt_alloc(struct sdxi_dev *sdxi)
{
	struct sdxi_cxt *cxt = NULL;
	unsigned long flags;
	gfp_t gfp_flags;
	struct device *dev = &sdxi->pdev->dev;
	int ret;

	spin_lock_irqsave(&sdxi->cxt_lock, flags);

	cxt = alloc_cxt(sdxi);
	if (!cxt)
		goto err_out;

	gfp_flags = GFP_KERNEL | __GFP_ZERO;
	cxt->dummy_buffer = (void *)__get_free_pages(gfp_flags, 0);
	cxt->dummy_buffer_addr = dma_map_single(dev, cxt->dummy_buffer, 4096,
                                                DMA_FROM_DEVICE);

	ret = config_cxt_tables(sdxi, cxt);
	if (ret) {
		free_cxt(cxt);
		cxt = NULL;
	}

	trace_sdxi_create_cxt(sdxi, cxt);

err_out:
	spin_unlock_irqrestore(&sdxi->cxt_lock, flags);
	return cxt;
}

/* clear context table and free context resources */
void sdxi_cxt_free(struct sdxi_cxt *cxt)
{
	struct sdxi_dev *sdxi = cxt->sdxi;
	unsigned long flags;

	trace_sdxi_free_cxt(sdxi, cxt);

	spin_lock_irqsave(&sdxi->cxt_lock, flags);

	cleanup_cxt_tables(sdxi, cxt);
	free_pages((unsigned long)cxt->dummy_buffer, 0);
	free_cxt(cxt);

	spin_unlock_irqrestore(&sdxi->cxt_lock, flags);
}

/* Main entry point for SDXI device initial configuration */
int sdxi_device_start(struct sdxi_dev *sdxi)
{
	struct sdxi_cxt *admin_cxt, *dma_cxt, *cxt;
	struct sdxi_desc desc;

	/* init admin context */
	cxt = sdxi_cxt_init(sdxi, SDXI_ADMIN_CXT_ID);
	if (!cxt)
		return -EINVAL;

	if (cxt->id != 0)
		goto err_admin_id;

	admin_cxt = cxt;

	/* init DMA context */
	dma_cxt = sdxi_cxt_init(sdxi, SDXI_DMA_CXT_ID);
	if (!dma_cxt)
		goto err_dma_cxt;

	sdxi->admin_cxt = admin_cxt;
	sdxi->dma_cxt = dma_cxt;

	build_admin_start_new(&desc, 0, 0, SDXI_DMA_CXT_ID, SDXI_DMA_CXT_ID, 0);
	sdxi_sq_submit_desc(admin_cxt->sq, &desc, false, 0);

	/* register with DMA engine */
	if (dma_engine)
		sdxi_dma_register(sdxi->dma_cxt);

	return 0;

err_dma_cxt:
err_admin_id:
	sdxi_cxt_exit(admin_cxt);

	return -EINVAL;
}

void sdxi_device_stop(struct sdxi_dev *sdxi)
{
	if (dma_engine)
		sdxi_dma_unregister(sdxi->dma_cxt);

	sdxi_cxt_exit(sdxi->dma_cxt);
	sdxi_cxt_exit(sdxi->admin_cxt);
}

int sdxi_device_init(struct sdxi_dev *sdxi)
{
	gfp_t gfp_flags;
	unsigned long order;
	int entries;

	/* l2 table */
	gfp_flags = GFP_KERNEL | __GFP_ZERO;
	order = get_order(L2_TABLE_SIZE);
	sdxi->l2_table = (void *)__get_free_pages(gfp_flags, order);
	if (!sdxi->l2_table)
		goto err_l2;

	/* rkey */
	entries = min_t(u32, sdxi->max_rkeys, DEFAULT_RKEY_NUM);
	sdxi->rkey = kzalloc(entries * sizeof(struct rkey_ent), GFP_KERNEL);
	if (!sdxi->rkey)
		goto err_rkey;
	sdxi->rkey_num = entries;

	/* error log */
	entries = min_t(u32, sdxi->max_err_logs, DEFAULT_ERR_LOG_NUM);
	sdxi->err_log = kzalloc(entries * sizeof(struct sdxi_err), GFP_KERNEL);
	if (!sdxi->err_log)
		goto err_log;
	sdxi->err_log_num = entries;

	/* misc */
	spin_lock_init(&sdxi->cxt_lock);
	INIT_LIST_HEAD(&sdxi->cxt_list);

	return 0;

err_log:
	kfree(sdxi->rkey);
err_rkey:
	free_pages((unsigned long)sdxi->l2_table, order);
err_l2:
	return -1;
}

void sdxi_device_exit(struct sdxi_dev *sdxi)
{
	kfree(sdxi->err_log);
	kfree(sdxi->rkey);
	free_pages((unsigned long)sdxi->l2_table, get_order(L2_TABLE_SIZE));
}

struct sdxi_dev *sdxi_device_alloc(void)
{
	struct sdxi_dev *sdxi;

	sdxi = kzalloc(sizeof(*sdxi), GFP_KERNEL);
	if (!sdxi)
		goto err;

	list_add_tail(&sdxi->list, &sdxi_device_list);
err:
	return sdxi;
}

void sdxi_device_free(struct sdxi_dev *sdxi)
{
	list_del(&sdxi->list);
	kfree(sdxi);
}
