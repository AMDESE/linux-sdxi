/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright Advanced Micro Devices, Inc.
 */

#ifndef DMA_SDXI_CONTEXT_H
#define DMA_SDXI_CONTEXT_H

#include <linux/array_size.h>
#include <linux/dma-mapping.h>
#include <linux/idr.h>
#include <linux/io.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#include "hw.h"
#include "ring.h"
#include "sdxi.h"
#include "submission.h"

struct sdxi_completion;
struct sdxi_cst_pool;
struct sdxi_process;

/* Use a 4 KiB AKey table, the minimum architectural size. */
struct sdxi_akey_table {
	struct sdxi_akey_ent entry[SZ_4K / sizeof(struct sdxi_akey_ent)];
};

struct eventfd_ctx;
struct inode;
struct sdxi_process;

/* For encoding the akey table size in CXT_L1_ENT's akey_sz. */
static inline u8 akey_table_order(const struct sdxi_akey_table *tbl)
{
	static_assert(sizeof(*tbl) == SZ_4K);
	return 0;
}

struct sdxi_cxt {
	struct sdxi_dev *sdxi;
	refcount_t refs;
	struct mutex cleanup_lock;	/* lifetime state serialization */
	wait_queue_head_t poll_wq;
	struct delayed_work cleanup_work;
	u16 id;
	u32 mmap_gen;
	u32 pasid;
	u32 opb_000_enb;
	u32 quiesce_cst_flags;
	unsigned int vma_refs;
	bool pasid_valid;
	bool handle_closed;
	bool mm_dead;
	bool fatal;
	bool quiesced;
	bool cleanup_stopping;
	bool resources_released;
	bool registered;
	bool published;
	bool update_pending;
	bool started;

	struct sdxi_cxt_ctl *cxt_ctl;
	dma_addr_t cxt_ctl_dma;

	struct ida akey_ida;
	struct mutex akey_lock;		/* AKey table serialization */
	struct sdxi_akey_table *akey_table;
	dma_addr_t akey_table_dma;

	struct sdxi_sq *sq;
	struct sdxi_cst_pool *cst_pool;

	struct sdxi_ring_state *ring_state;
	struct sdxi_process *process;
	struct inode *mapping_inode;

	spinlock_t intr_lock;		/* eventfd and interrupt state */
	struct eventfd_ctx *intr_eventfd;
	int intr_vector;
	int intr_irq;
	u16 intr_akey;
	bool intr_armed;
};

int sdxi_admin_cxt_init(struct sdxi_dev *sdxi);
void sdxi_admin_cxt_exit(struct sdxi_dev *sdxi);
struct sdxi_cxt *sdxi_cxt_new(struct sdxi_dev *sdxi);
struct sdxi_cxt *sdxi_ucxt_new(struct sdxi_dev *sdxi, u32 ring_entries,
			       u64 ds_ring, u64 write_index, u64 cxt_sts,
			       u32 pasid, u32 opb_000_enb);
/*
 * Caller must exclude users and stop the client before release. An update or
 * synchronization failure retains the invalidated context for device teardown;
 * the caller must not reuse it.
 */
int sdxi_cxt_exit(struct sdxi_cxt *cxt);
void sdxi_cxt_abort(struct sdxi_cxt *cxt);
void sdxi_client_cxts_exit(struct sdxi_dev *sdxi);
void sdxi_cxt_get(struct sdxi_cxt *cxt);
void sdxi_cxt_put(struct sdxi_cxt *cxt);
struct sdxi_cxt *sdxi_cxt_get_by_id(struct sdxi_dev *sdxi, u16 cxt_id);
int sdxi_cxt_quiesce(struct sdxi_cxt *cxt, unsigned int timeout_ms,
		     u32 *cst_flags);
bool sdxi_cxt_is_user(const struct sdxi_cxt *cxt);
bool sdxi_cxt_is_fatal(const struct sdxi_cxt *cxt);
void sdxi_cxt_kill(struct sdxi_cxt *cxt);
void sdxi_cxt_kill_stopped(struct sdxi_cxt *cxt);
void sdxi_cxt_release_user_handle(struct sdxi_cxt *cxt);
int sdxi_cxt_notify_mm_release(struct sdxi_cxt *cxt);
void sdxi_cxt_vma_open(struct sdxi_cxt *cxt);
int sdxi_cxt_vma_acquire(struct sdxi_cxt *cxt);
void sdxi_cxt_vma_close(struct sdxi_cxt *cxt);

enum sdxi_submit_flags {
	SDXI_CXT_SUBMIT_KICK  = BIT(0),
	SDXI_CXT_SUBMIT_FENCE = BIT(1),
};

void sdxi_cxt_attach_cst(struct sdxi_slot slot,
			 const struct sdxi_completion *comp);
void sdxi_cxt_submit(struct sdxi_cxt *cxt, struct sdxi_slot slot,
		     const struct sdxi_completion *comp, enum sdxi_submit_flags flags);

static inline void sdxi_cxt_kick(struct sdxi_cxt *cxt)
{
	/*
	 * Ring the context's doorbell with its current write index.
	 *
	 * It's OK to locklessly sample the index for this purpose: it
	 * monotonically increases and the implementation is required
	 * to ignore out-of-order doorbell values (SDXI 1.0 5.2.1
	 * Multi-Producer Enqueue).
	 *
	 * writeq() orders the descriptors' valid bits ahead of the
	 * doorbell, so no explicit barrier is needed here.
	 */
	writeq(le64_to_cpu(READ_ONCE(cxt->sq->write_index)), cxt->sq->doorbell);
}

static inline struct sdxi_akey_ent *sdxi_alloc_akey(struct sdxi_cxt *cxt)
{
	unsigned int max = ARRAY_SIZE(cxt->akey_table->entry) - 1;
	int idx = ida_alloc_max(&cxt->akey_ida, max, GFP_KERNEL);

	return idx < 0 ? NULL : &cxt->akey_table->entry[idx];
}

static inline unsigned int sdxi_akey_index(const struct sdxi_cxt *cxt,
					   const struct sdxi_akey_ent *akey)
{
	return akey - &cxt->akey_table->entry[0];
}

static inline void sdxi_free_akey(struct sdxi_cxt *cxt, struct sdxi_akey_ent *akey)
{
	memset(akey, 0, sizeof(*akey));
	ida_free(&cxt->akey_ida, sdxi_akey_index(cxt, akey));
}

#endif /* DMA_SDXI_CONTEXT_H */
