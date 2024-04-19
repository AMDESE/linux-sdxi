/*
 * SDXI device driver header
 *
 * Copyright (C) 2022 AMD, Inc. All rights reserved.
 *
 * Author: Wei Huang <wei.huang2@amd.com>
 */

#ifndef __SDXI_H
#define __SDXI_H

#include <linux/types.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/idr.h>

#include "../virt-dma.h"

#define SDXI_DRV_NAME		"sdxi"
#define SDXI_DRV_DESC		"SDXI driver"

/***************************/
/*        DEFAULTS         */
/***************************/
#define DEFAULT_ERR_LOG_NUM	64
#define DEFAULT_RKEY_NUM	256
#define DEFAULT_AKEY_NUM	256

/***************************/
/*          MACROS         */
/***************************/
extern struct list_head sdxi_device_list;
#define for_each_sdxi(sdxi)					\
	list_for_each_entry((sdxi), &sdxi_device_list, list)
#define for_each_sdxi_safe(sdxi, next)					\
	list_for_each_entry_safe((sdxi), (next), &sdxi_device_list, list)

#define ID_TO_L2_INDEX(id)	(((id) >> 9) & 0x1FF)
#define ID_TO_L1_INDEX(id)	((id) & 0x7F)
#define IS_VF_DEVICE(sdxi)	((sdxi)->is_vf)

/***************************/
/*          CONSTS         */
/***************************/
#define L2_TABLE_ENTRIES	(1 << 9)
#define L1_TABLE_ENTRIES	(1 << 7)
#define L2_TABLE_SIZE		4096
#define L1_TABLE_SIZE		4096

#define OP_TYPE_DMA             0x001
#define OP_TYPE_ADMIN           0x002
#define OP_TYPE_ATOMIC          0x003
#define OP_TYPE_INTR            0x004

#define OP_DMA_NOP		0x01
#define OP_DMA_WRT_IMM		0x02
#define OP_DMA_COPY		0x03
#define OP_DMA_REP_COPY		0x04
#define OP_ADMIN_UPDATE_FUNC	0x00
#define OP_ADMIN_UPDATE_CXT	0x01
#define OP_ADMIN_UPDATE_AKEY	0x02
#define OP_ADMIN_START		0x03
#define OP_ADMIN_STOP		0x04
#define OP_ADMIN_INTR		0x05
#define OP_ADMIN_SYNC		0x06
#define OP_ATOMIC_SWAP		0x01
#define OP_ATOMIC_UADD		0x02
#define OP_ATOMIC_USUB		0x03
#define OP_ATOMIC_AND		0x05
#define OP_ATOMIC_OR		0x06
#define OP_ATOMIC_XOR		0x07
#define OP_ATOMIC_SMIN		0x08
#define OP_ATOMIC_SMAX		0x09
#define OP_ATOMIC_UMIN		0x0A
#define OP_ATOMIC_UMAX		0x0B
#define OP_ATOMIC_UCLAMPI	0x0C
#define OP_ATOMIC_UCLAMPD	0x0D
#define OP_ATOMIC_CMPSWAP	0x0E
#define OP_INTR_INTERRUPT	0x00

#define CXT_STATE_STOPPED	0x0
#define CXT_STATE_RUNNING	0x1
#define CXT_STATE_STOPPING	0x2
#define CXT_STATE_ERR		0xF

#define DESC_RING_BASE_PTR_SHIFT	6
#define CXT_STATUS_PTR_SHIFT		4
#define WRT_INDEX_PTR_SHIFT		3

#define L2_CXT_L1_BASE_SHIFT		12

#define L1_CXT_CTL_PTR_SHIFT		6
#define L1_CXT_AKEY_PTR_SHIFT		12

#define MAX_DMA_COPY_BYTES		(1ULL << 32)

/***************************/
/*         STRUCTS         */
/***************************/
enum sdxi_cxt_id {
	SDXI_ADMIN_CXT_ID = 0,
	SDXI_DMA_CXT_ID = 1,
	SDXI_ANY_CXT_ID,
};

/* context status entry */
struct sdxi_cxt_status {
	u64 state		: 4;	/* QW0 */
	u64 rsvd1		: 4;
	u64 rsh			: 1;
	u64 rsvd2		: 55;
	u64 read_idx;			/* QW1 */
} __packed __aligned(16);

/* Context Control Entry */
struct cxt_ctl_entry {
	u64 vl			: 1;	/* QW0 */
	u64 rsvd1		: 1;
	u64 qos			: 2;
	u64 se			: 1;
	u64 csa			: 1;
	u64 desc_ring_base	: 58;
	u64 desc_ring_size	: 32;	/* QW1 */
	u64 rsvd3		: 32;
	u64 rsvd4		: 4;	/* QW2 */
	u64 cxt_status_ptr	: 60;
	u64 rsvd5		: 3;	/* QW3 */
	u64 wrt_index_ptr	: 61;
	u32 rsvd6[8];			/* QW4+ */
} __packed __aligned(64);

struct sdxi_desc {
	u32 vl			: 1;
	u32 se			: 1;
	u32 fe			: 1;
	u32 ch			: 1;
	u32 csr			: 1;
	u32 rsvd1		: 3;
	u32 subtype		: 8;
	u32 type		: 11;
	u32 rsvd2		: 5;
	u32 body[13];
	u64 csb_ptr;
} __packed;

struct csb {
	volatile u64 signal;		/* QW0 */
	u32 rsvd1		: 31;	/* QW1 */
	u32 er			: 1;
	u32 rsvd2[5];			/* DW3+ */
} __packed;

/* Submission Queue */
struct sdxi_sq {
	struct sdxi_cxt *cxt;		/* owner */

	u32 ring_entries;
	u32 ring_size;
	struct sdxi_desc *desc_ring;
	dma_addr_t ring_dma;
	struct csb *csb;
	dma_addr_t csb_dma;

	u32 write_index_size;
	u64 *write_index;
	dma_addr_t write_index_dma;

	u32 cxt_status_size;
	struct sdxi_cxt_status *cxt_status;
	dma_addr_t cxt_status_dma;

	/* NB: define doorbell here */
};

struct sdxi_tasklet_data {
	struct completion completion;
	struct sdxi_cmd *cmd;
};

struct sdxi_cmd {
	struct list_head entry;
	struct work_struct work;
	struct sdxi_cxt *cxt;
	int ret;
	size_t len;
	u64 src_addr;
	u64 dst_addr;
	u64 index;  //index at descriptor ring
	/* completion callback support */
	void (*sdxi_cmd_callback)(void *data, int err);
	void *data;
};

struct sdxi_dma_desc {
	struct virt_dma_desc vd;
	struct sdxi_cxt *cxt;
	enum dma_status status;
	bool issued_to_hw;
	struct sdxi_cmd sdxi_cmd;
};

struct sdxi_dma_chan {
	struct virt_dma_chan vc;
	struct sdxi_cxt *cxt;
};

struct akey_entry {
	u32 vl			: 1;	/* QW0 */
	u32 iv			: 1;
	u32 pv			: 1;
	u32 ste			: 1;
	u32 intr_num		: 11;
	u32 rsvd1		: 1;
	u32 tgt_sfunc		: 16;
	u32 pasid		: 20;
	u32 rsvd2		: 10;
	u32 ph			: 2;
	u32 stag	       	: 16;	/* QW1 */
	u32 rsvd3		: 16;
	u32 rkey		: 16;
	u32 rsvd4		: 16;
} __packed;

/* Context */
struct sdxi_cxt {
	struct list_head list;
	struct sdxi_dev *sdxi;	/* owner */
	unsigned int id;

	resource_size_t db_base;	/* doorbell MMIO base addr */
	void __iomem *db;		/* doorbell virt addr */

	struct cxt_ctl_entry cce;
	dma_addr_t cce_addr;		/* cce dma addr */

	int akey_entries;
	struct akey_entry *akey;
	dma_addr_t akey_addr;		/* akey dma addr */

	struct sdxi_sq *sq;

	/* NB: might need to move to sdxi_device? */
	struct sdxi_dma_chan sdxi_dma_chan;

	struct sdxi_process *process;	/* process reprsentation */

	/* FOR DEBUG */
	unsigned long *dummy_buffer;
	dma_addr_t dummy_buffer_addr;
};

/* RKey Table Entry */
struct rkey_ent {
	u32 vl			: 1;	/* QW0 */
	u32 iv			: 1;
	u32 pv			: 1;
	u32 ste			: 1;
	u32 intr_num		: 11;
	u32 rsvd1		: 1;
	u32 req_sfunc		: 16;
	u32 pasid		: 20;
	u32 rsvd2		: 10;
	u32 ph			: 2;
	u32 stag		: 16;	/* QW1 */
	u32 rsvd3		: 16;
	u32 rsvd4;
} __packed;

/* Error Log Entry */
struct sdxi_err {
	u32 vl			: 1;	/* QW0 */
	u32 rsvd1		: 7;
	u32 step		: 6;
	u32 rsvd2		: 2;
	u32 type		: 11;
	u32 rsvd3		: 5;
	u32 cv			: 1;
	u32 div			: 1;
	u32 bv			: 1;
	u32 rsvd4		: 1;
	u32 buf			: 3;
	u32 rsvd5		: 1;
	u32 sub_step		: 4;
	u32 re			: 3;
	u32 rsvd6		: 1;
	u32 cxt_num		: 16;
	u64 desc_idx;
	u32 rsvd7[7];
	u32 err_class		: 16;
	u32 rsvd8		: 16;
	u32 vendor[4];
} __packed;

/* L1 Table Entry */
struct cxt_l1_entry {
	u64 vl			: 1;	/* QW0 */
	u64 ka			: 1;
	u64 pv			: 1;
	u64 rsvd1		: 3;
	u64 cxt_ctl_ptr		: 58;
	u64 akey_tbl_size	: 4;	/* QW1 */
	u64 rsvd2		: 8;
	u64 akey_tbl_ptr	: 52;
	u64 cxt_pasid		: 20;	/* QW2 */
	u64 max_buf		: 4;
	u64 rsvd3		: 8;
	u64 opb_000_enb		: 32;
	u64 rsvd4;			/* QW3 */
} __packed;

/* L2 Table Entry */
struct cxt_l2_entry {
	u64 vl			: 1;	/* QW0 */
	u64 rsvd		: 11;
	u64 l1_ptr		: 52;
} __packed;

struct irq_entry {
	int vector;
};

struct sdxi_dev {
	struct list_head list;

	/* physical device */
	struct pci_dev *pdev;
	resource_size_t ctl_regs_bar;	/* ctl registers base (BAR0) */
	resource_size_t dbs_bar;	/* doorbells base (BAR2) */
	void __iomem *ctl_regs;		/* virt addr of ctl registers */
	void __iomem *dbs;		/* virt addr of doorbells */

	/* hardware capabilities (from cap0 & cap1) */
	u16 sfunc;			/* function's requester id */
	bool is_vf;			/* is VF function? */
	u32 db_stride;			/* doorbell stride in bytes */
	u64 max_ring_entries;		/* max # of ring entries supported */
	u32 max_rkeys;			/* max rkey # supported */

	u64 max_buffer;			/* max supported buffer size bytes */
	bool has_rkey;			/* is rkey functionality supported? */
	u32 max_err_logs;		/* max err log entries supported */
	u32 max_akeys;			/* max akey # supported */
	u32 max_cxts;			/* max contexts # supported */
	u32 op_grp_cap;			/* supported operatation group cap */

	/* iommu support */
	bool use_iommu_v2;		/* bound with iommu for pasid? */
	u32 max_pasids;
	u32 pasid_limit;
	struct ida pasid_ida;

	/* MSI */
	unsigned int irq_count;
	struct irq_entry err_irq;
	struct irq_entry *cxt_irqs;	/* NB: convert to a struct */

	/* context management */
	spinlock_t cxt_lock;		/* context protection */
	struct list_head cxt_list;
	int cxt_count;
	/* l2 table, pre-allocated with sdxi_device */
	struct cxt_l2_entry *l2_table;
	/* list of context l1 tables, on-demand, access with [l2_idx] */
	struct cxt_l1_entry *l1_table_array[L2_TABLE_ENTRIES];
	/* all contexts, on-demand, access with [l2_idx][l1_idx] */
	struct sdxi_cxt **cxt_array[L2_TABLE_ENTRIES];

	/* rkey table */
	int rkey_num;
	struct rkey_ent *rkey;

	/* error log */
	u32 err_log_num;
	struct sdxi_err *err_log;

	/* DMA engine */
	struct dma_device dma_dev;
	struct sdxi_dma_chan *sdxi_dma_chan;
	struct kmem_cache *dma_cmd_cache;
	struct kmem_cache *dma_desc_cache;
	struct sdxi_tasklet_data tdata;

	/* special contexts */
	struct sdxi_cxt *admin_cxt;	/* admin context */
	struct sdxi_cxt *dma_cxt;	/* DMA engine context */
};

/***************************/
/*           API           */
/***************************/
/* Device Control */
int sdxi_device_start(struct sdxi_dev *sdxi);
void sdxi_device_stop(struct sdxi_dev *sdxi);
int sdxi_device_init(struct sdxi_dev *sdxi);
void sdxi_device_exit(struct sdxi_dev *sdxi);
struct sdxi_dev *sdxi_device_alloc(void);
void sdxi_device_free(struct sdxi_dev *sdxi);

/* Context Control */
struct sdxi_cxt *sdxi_cxt_alloc(struct sdxi_dev *sdxi);
void sdxi_cxt_free(struct sdxi_cxt *cxt);
struct sdxi_cxt *sdxi_cxt_init(struct sdxi_dev *sdxi,
			       enum sdxi_cxt_id);
void sdxi_cxt_exit(struct sdxi_cxt *cxt);
struct sdxi_cxt *sdxi_working_cxt_alloc(void);

/* Submission Queue */
struct sdxi_sq *sdxi_sq_alloc(struct sdxi_cxt *cxt, int ring_size);
struct sdxi_sq *sdxi_sq_alloc_default(struct sdxi_cxt *cxt);
void sdxi_sq_free(struct sdxi_sq *sq);
int sdxi_submit_desc(struct sdxi_sq *sq, struct sdxi_desc *desc);

/* DMA Engine */
int sdxi_dma_register(struct sdxi_cxt *dma_cxt);
void sdxi_dma_unregister(struct sdxi_cxt *dma_cxt);

/* Chardev (IOCTL) */
int sdxi_chardev_init(void);
void sdxi_chardev_exit(void);

#endif /* __SDXI_H */
