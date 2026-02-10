/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SDXI device driver header
 *
 * Copyright (C) 2025 Advanced Micro Devices, Inc.
 */

#ifndef __SDXI_H
#define __SDXI_H

#include <linux/dev_printk.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/types.h>

#include "hw.h"
#include "mmio.h"
#include "version.h"

#define SDXI_DRV_NAME		"sdxi"
#define SDXI_DRV_DESC		"SDXI driver"

#define ID_TO_L2_INDEX(id)	(((id) >> 9) & 0x1FF)
#define ID_TO_L1_INDEX(id)	((id) & 0x7F)
#define IS_VF_DEVICE(sdxi)	((sdxi)->is_vf)

#define L2_TABLE_ENTRIES	(1 << 9)
#define L1_TABLE_ENTRIES	(1 << 7)
#define L2_TABLE_SIZE		4096
#define L1_TABLE_SIZE		4096

#define OP_TYPE_ERRLOG          0x7f7

#define DESC_RING_BASE_PTR_SHIFT	6
#define CXT_STATUS_PTR_SHIFT		4
#define WRT_INDEX_PTR_SHIFT		3

#define L1_CXT_CTRL_PTR_SHIFT		6
#define L1_CXT_AKEY_PTR_SHIFT		12

/*
 * The size of the AKey table is flexible, from 4KB to 1MB. Always use
 * the minimum size for now.
 */
struct sdxi_akey_table {
	struct sdxi_akey_ent entry[SZ_4K / sizeof(struct sdxi_akey_ent)];
};

/* For encoding the akey table size in CXT_L1_ENT's akey_sz. */
static inline u8 akey_table_order(const struct sdxi_akey_table *tbl)
{
	static_assert(sizeof(*tbl) == SZ_4K);
	return 0;
}

struct sdxi_dev;

/**
 * struct sdxi_dev_ops - Bus-specific methods for SDXI devices.
 *
 * @irq_init: Allocate MSIs.
 * @supports_privileged_addrspace: Whether the device supports privileged
 *  address spaces, e.g. via PCIe's PASID Privileged Mode.
 */
struct sdxi_dev_ops {
	int (*irq_init)(struct sdxi_dev *sdxi);
	bool (*supports_privileged_addrspace)(struct sdxi_dev *sdxi);
};

struct device;
struct dma_pool;

struct sdxi_dev {
	struct device *dev;
	void __iomem *ctrl_regs;	/* virt addr of ctrl registers */
	void __iomem *dbs;		/* virt addr of doorbells */

	sdxi_version_t sdxi_version;    /* SDXI version implemented by device */

	/* hardware capabilities (from cap0 & cap1) */
	u16 sfunc;			/* function's requester id */
	u32 db_stride;			/* doorbell stride in bytes */
	u64 max_ring_entries;		/* max # of ring entries supported */

	u32 max_akeys;			/* max akey # supported */
	u32 max_cxts;			/* max contexts # supported */
	u32 op_grp_cap;			/* supported operatation group cap */

	/* context management */
	struct mutex cxt_lock;		/* context protection */
	int cxt_count;
	struct sdxi_cxt_l2_table *l2_table;
	dma_addr_t l2_dma;
	/* list of context l1 tables, on-demand, access with [l2_idx] */
	struct sdxi_cxt_l1_table *l1_table_array[L2_TABLE_ENTRIES];
	/* all contexts, on-demand, access with [l2_idx][l1_idx] */
	struct sdxi_cxt **cxt_array[L2_TABLE_ENTRIES];

	struct dma_pool *write_index_pool;
	struct dma_pool *cxt_sts_pool;
	struct dma_pool *cxt_ctl_pool;

	/* error log */
	int error_irq;
	struct sdxi_errlog_hd_ent *err_log;
	dma_addr_t err_log_dma;

	/* special contexts */
	struct sdxi_cxt *admin_cxt;	/* admin context */

	const struct sdxi_dev_ops *dev_ops;
	bool use_privileged_bits:1; /* Whether to set the 'pr' bit
				     * within the portions of the
				     * control structure hierarchy
				     * that should be considered
				     * private to the kernel, not
				     * exposed to user space.
				     */
};

static inline bool sdxi_dev_compatible(const struct sdxi_dev *sdxi,
				       sdxi_version_t v)
{
	return sdxi_version_ge(sdxi->sdxi_version, v);
}


static inline struct device *sdxi_to_dev(const struct sdxi_dev *sdxi)
{
	return sdxi->dev;
}

#define sdxi_dbg(s, fmt, ...) dev_dbg(sdxi_to_dev(s), fmt, ## __VA_ARGS__)
#define sdxi_info(s, fmt, ...) dev_info(sdxi_to_dev(s), fmt, ## __VA_ARGS__)
#define sdxi_err(s, fmt, ...) dev_err(sdxi_to_dev(s), fmt, ## __VA_ARGS__)

static inline bool
sdxi_dev_supports_privileged_address_space(struct sdxi_dev *sdxi)
{
	if (!sdxi_dev_compatible(sdxi, SDXI_VERSION_1_1))
		return false;
	return sdxi->dev_ops->supports_privileged_addrspace ?
		sdxi->dev_ops->supports_privileged_addrspace(sdxi) :
		false;
}

int sdxi_device_init(struct sdxi_dev *sdxi, const struct sdxi_dev_ops *ops);
void sdxi_device_exit(struct sdxi_dev *sdxi);

/* Chardev (IOCTL) */
int sdxi_chardev_init(void);
void sdxi_chardev_exit(void);

static inline u64 sdxi_read64(const struct sdxi_dev *sdxi, enum sdxi_reg reg)
{
	return ioread64(sdxi->ctrl_regs + reg);
}

static inline void sdxi_write64(struct sdxi_dev *sdxi, enum sdxi_reg reg, u64 val)
{
	iowrite64(val, sdxi->ctrl_regs + reg);
}

#endif /* __SDXI_H */
