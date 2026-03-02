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
#include <linux/idr.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <asm/bug.h>

#include "hw.h"
#include "mmio.h"

#define SDXI_DRV_NAME		"sdxi"
#define SDXI_DRV_DESC		"SDXI driver"

#define ID_TO_L2_INDEX(id)	(((id) >> 9) & 0x1FF)
#define ID_TO_L1_INDEX(id)	((id) & 0x7F)
#define IS_VF_DEVICE(sdxi)	((sdxi)->is_vf)

#define L2_TABLE_ENTRIES	(1 << 9)
#define L1_TABLE_ENTRIES	(1 << 7)
#define L2_TABLE_SIZE		4096
#define L1_TABLE_SIZE		4096

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

enum {
	/*
	 * Per SDXI 1.0 3.4 Error Log, the error log interrupt is
	 * always vector 0.
	 */
	SDXI_ERROR_VECTOR = 0,

	/*
	 * The driver requires a minimum of two MSI vectors to operate
	 * correctly: one for the admin context, one for the error
	 * log.
	 */
	SDXI_MIN_VECTORS = 2,
};

struct sdxi_dev;

/**
 * struct sdxi_bus_ops - Bus-specific methods for SDXI devices.
 */
struct sdxi_bus_ops {
	/**
	 * @init: Map control registers and doorbell region, allocate
	 *        IRQ ranges. Invoked before bus-agnostic SDXI
	 *        function initialization.
	 */
	int (*init)(struct sdxi_dev *sdxi);
	/**
	 * @get_irq: Map device interrupt index to Linux IRQ number.
	 */
	int (*get_irq)(struct sdxi_dev *sdxi, unsigned int index);
};

struct device;
struct dma_pool;

struct sdxi_version {
	u8 major;
	u8 minor;
};

struct sdxi_dev {
	struct device *dev;
	resource_size_t dbs_bar;	/* doorbells base (BAR2) */
	void __iomem *ctrl_regs;	/* virt addr of ctrl registers */
	void __iomem *dbs;		/* virt addr of doorbells */

	struct sdxi_version version; /* SDXI version implemented by function */

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

	unsigned int nr_vectors;
	struct ida vectors;

	struct sdxi_cxt *admin_cxt;

	const struct sdxi_bus_ops *bus_ops;
};

static inline struct device *sdxi_to_dev(const struct sdxi_dev *sdxi)
{
	return sdxi->dev;
}

#define sdxi_dbg(s, fmt, ...) dev_dbg(sdxi_to_dev(s), fmt, ## __VA_ARGS__)
#define sdxi_info(s, fmt, ...) dev_info(sdxi_to_dev(s), fmt, ## __VA_ARGS__)
#define sdxi_err(s, fmt, ...) dev_err(sdxi_to_dev(s), fmt, ## __VA_ARGS__)

/**
 * sdxi_alloc_vector() - Allocate an interrupt vector.
 *
 * A vector that will have the same lifetime as the device does not
 * need to be released explicitly. Otherwise the vector must be
 * released with sdxi_free_vector().
 */
static inline int sdxi_alloc_vector(struct sdxi_dev *sdxi)
{
	return ida_alloc_max(&sdxi->vectors, sdxi->nr_vectors - 1,
			     GFP_KERNEL);
}

/**
 * sdxi_free_vector() - Release a previously allocated index.
 */
static inline void sdxi_free_vector(struct sdxi_dev *sdxi, unsigned int nr)
{
	ida_free(&sdxi->vectors, nr);
}

/**
 * sdxi_vector_to_irq() - Translate an allocated interrupt vector to
 *                        Linux IRQ number suitable for passing to
 *                        request_irq() et al.
 */
static inline int sdxi_vector_to_irq(struct sdxi_dev *sdxi, unsigned int nr)
{
	/* Moan if the index isn't currently allocated. */
	WARN_ON_ONCE(!ida_exists(&sdxi->vectors, nr));
	return sdxi->bus_ops->get_irq(sdxi, nr);
}

int sdxi_register(struct device *dev, const struct sdxi_bus_ops *ops);
void sdxi_unregister(struct device *dev);

static inline u64 sdxi_read64(const struct sdxi_dev *sdxi, enum sdxi_reg reg)
{
	return ioread64(sdxi->ctrl_regs + reg);
}

static inline void sdxi_write64(struct sdxi_dev *sdxi, enum sdxi_reg reg, u64 val)
{
	iowrite64(val, sdxi->ctrl_regs + reg);
}

#endif /* __SDXI_H */
