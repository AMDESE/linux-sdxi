// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI dmaengine provider
 *
 * Copyright Advanced Micro Devices, Inc.
 */

#include <kunit/visibility.h>
#include <linux/cleanup.h>
#include <linux/delay.h>
#include <linux/dev_printk.h>
#include <linux/container_of.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/list.h>
#include <linux/lockdep.h>
#include <linux/module.h>
#include <linux/overflow.h>
#include <linux/spinlock.h>

#include "../dmaengine.h"
#include "../virt-dma.h"
#include "completion.h"
#include "context.h"
#include "descriptor.h"
#include "dma.h"
#include "ring.h"
#include "sdxi.h"

VISIBLE_IF_KUNIT void sdxi_dma_reap_locked(struct sdxi_dma_chan *sdchan);

static unsigned short dma_channels = 1;
module_param(dma_channels, ushort, 0644);
MODULE_PARM_DESC(dma_channels, "DMA channels per function (default: 1)");

/*
 * An SDXI context is allocated for each channel configured.
 *
 * Each context has a descriptor ring with a minimum of 1K entries.
 * SDXI supports a variety of primitive operations, e.g. copy,
 * interrupt, nop. A txd -- one dmaengine transaction -- expands into a
 * grouping of SDXI descriptors in that ring.
 *
 * device_prep_dma_memcpy() stores the copy parameters in the txd and
 * validates them with a throwaway encode, but does not touch the ring.
 * tx_submit() (vchan_tx_submit()) assigns a cookie and moves the txd to
 * the submitted list.
 *
 * device_issue_pending() moves submitted txds to a per-channel pending
 * list and drains it in cookie order. Each batch reserves ring slots for
 * copies and a fenced interrupt terminator, encodes the descriptors with
 * individual completion blocks, and publishes their valid bits. A drain
 * rings the doorbell once after publishing all batches that fit. Reserving
 * at issue (rather than at prep) keeps ring order equal to cookie order,
 * which virt-dma's in-order completion model requires. Transactions that
 * do not fit stay pending and are drained by the completion IRQ as ring
 * space frees.
 */

struct sdxi_dma_dev {
	struct dma_device dma_dev;
	size_t nr_channels;
	struct sdxi_dma_chan sdchan[] __counted_by(nr_channels);
};

static struct sdxi_dma_chan *to_sdxi_dma_chan(const struct dma_chan *dma_chan)
{
	const struct virt_dma_chan *vchan;

	vchan = container_of_const(dma_chan, struct virt_dma_chan, chan);
	return container_of(vchan, struct sdxi_dma_chan, vchan);
}

static struct sdxi_dma_txd *
to_sdxi_dma_txd(const struct virt_dma_desc *vdesc)
{
	return container_of(vdesc, struct sdxi_dma_txd, vdesc);
}

static void sdxi_dma_txd_free(struct virt_dma_desc *vdesc)
{
	struct sdxi_dma_txd *txd = to_sdxi_dma_txd(vdesc);

	kfree(txd);
}

static struct dma_async_tx_descriptor *
sdxi_dma_prep_memcpy(struct dma_chan *dma_chan, dma_addr_t dst,
		     dma_addr_t src, size_t len, unsigned long flags)
{
	struct sdxi_dma_chan *sdchan = to_sdxi_dma_chan(dma_chan);
	struct sdxi_cxt *cxt = sdchan->cxt;
	u16 akey_index = sdxi_akey_index(cxt, sdchan->akey);
	struct sdxi_dma_txd *txd;
	struct sdxi_copy copy = {
		.src = src,
		.dst = dst,
		.src_akey = akey_index,
		.dst_akey = akey_index,
		.len = len,
	};

	/*
	 * Validate now, with a throwaway encode onto the stack. The real
	 * encode into the ring happens at issue.
	 */
	if (sdxi_encode_copy(&(struct sdxi_desc){}, &copy))
		return NULL;

	txd = kmalloc_obj(*txd, GFP_NOWAIT);
	if (!txd)
		return NULL;

	*txd = (typeof(*txd)) {
		.copy = copy,
	};

	return vchan_tx_prep(&sdchan->vchan, &txd->vdesc, flags);
}

static enum dma_status sdxi_tx_status(struct dma_chan *chan,
				      dma_cookie_t cookie,
				      struct dma_tx_state *state)
{
	struct sdxi_dma_chan *sdchan = to_sdxi_dma_chan(chan);
	struct virt_dma_desc *vdesc;

	/* Under the lock for a consistent cookie snapshot; the IRQ reaps. */
	guard(spinlock_irqsave)(&sdchan->vchan.lock);

	/* vchan_find_desc() only returns issued txds, which have a cst. */
	vdesc = vchan_find_desc(&sdchan->vchan, cookie);
	if (vdesc) {
		struct sdxi_dma_txd *txd = to_sdxi_dma_txd(vdesc);

		if (sdxi_cst_blk_check(txd->cst) == SDXI_COMPLETION_ERROR)
			return DMA_ERROR;
	}

	return dma_cookie_status(chan, cookie, state);
}

/*
 * Fill capacity with complete, fenced batches in cookie order. Return true
 * if descriptors were published; the caller kicks once with the lock held.
 */
VISIBLE_IF_KUNIT bool sdxi_dma_drain_locked(struct sdxi_dma_chan *sdchan)
{
	struct sdxi_cxt *cxt = sdchan->cxt;
	struct sdxi_ring_state *rs = cxt->ring_state;
	bool pushed = false;

	lockdep_assert_held(&sdchan->vchan.lock);

	while (!list_empty(&sdchan->pending)) {
		struct virt_dma_desc *vdesc;
		struct sdxi_ring_resv resv;
		struct sdxi_desc *desc;
		size_t copies = 0;

		/* Select a prefix, ending just after the first flag boundary. */
		list_for_each_entry(vdesc, &sdchan->pending, node) {
			copies++;
			if (vdesc->tx.flags & (DMA_PREP_INTERRUPT | DMA_PREP_FENCE) ||
			    copies == rs->sq->count - 1)
				break;
		}
		if (sdxi_ring_try_reserve_range(rs, 2, copies + 1, &resv))
			break;

		copies = sdxi_ring_resv_count(&resv) - 1;
		for (size_t i = 0; i < copies; i++) {
			struct sdxi_dma_txd *txd;
			struct sdxi_slot slot = sdxi_ring_resv_slot(&resv, i);

			vdesc = list_first_entry(&sdchan->pending,
						struct virt_dma_desc, node);
			txd = to_sdxi_dma_txd(vdesc);
			desc = sdxi_slot_desc(slot);
			(void)sdxi_encode_copy(desc, &txd->copy); /* validated at prep */
			txd->cst = sdxi_cxt_attach_cst(cxt, slot);
			txd->copy_index = slot.index;
			txd->retire_index = slot.index + 1;
			if (i == copies - 1)
				txd->retire_index++; /* Interrupt has no completion block. */
			sdxi_desc_make_valid(desc);
			list_move_tail(&vdesc->node, &sdchan->vchan.desc_issued);
		}

		/*
		 * FE waits for all copies before notifying and before parsing
		 * subsequent copies (SDXI 1.0a 5.3, steps 7-9). One terminator
		 * satisfies both flags and supplies internal completion IRQs.
		 */
		desc = sdxi_slot_desc(sdxi_ring_resv_slot(&resv, copies));
		sdxi_encode_intr(desc, &(const struct sdxi_intr) {
			.akey = sdxi_akey_index(cxt, sdchan->akey),
		});
		sdxi_desc_set_fence(desc);
		sdxi_desc_make_valid(desc);
		pushed = true;
	}

	return pushed;
}
EXPORT_SYMBOL_IF_KUNIT(sdxi_dma_drain_locked);

static void sdxi_dma_issue_pending(struct dma_chan *dma_chan)
{
	struct sdxi_dma_chan *sdchan = to_sdxi_dma_chan(dma_chan);

	guard(spinlock_irqsave)(&sdchan->vchan.lock);

	list_splice_tail_init(&sdchan->vchan.desc_submitted, &sdchan->pending);
	if (sdxi_dma_drain_locked(sdchan))
		sdxi_cxt_kick(sdchan->cxt);
}

static int sdxi_dma_terminate_all(struct dma_chan *dma_chan)
{
	struct sdxi_dma_chan *sdchan = to_sdxi_dma_chan(dma_chan);
	struct virt_dma_chan *vchan = &sdchan->vchan;
	LIST_HEAD(head);

	/*
	 * Free submitted and pending work only. desc_allocated (prepped, not
	 * yet submitted) is still owned and being written by its caller --
	 * possibly another thread sharing this channel -- so freeing it would
	 * be a use-after-free. desc_issued is in the ring: it runs to
	 * completion and the IRQ reaps it (and retires its completion block).
	 * sdxi_dma_synchronize() waits for the ring to drain.
	 */
	scoped_guard(spinlock_irqsave, &vchan->lock) {
		list_splice_tail_init(&sdchan->pending, &head);
		list_splice_tail_init(&vchan->desc_submitted, &head);
	}
	vchan_dma_desc_free_list(vchan, &head);

	return 0;
}

static void sdxi_dma_synchronize(struct dma_chan *dma_chan)
{
	struct sdxi_dma_chan *sdchan = to_sdxi_dma_chan(dma_chan);
	struct sdxi_cxt *cxt = sdchan->cxt;
	struct sdxi_ring_resv resv;
	struct sdxi_cst_blk *cst;
	struct sdxi_slot nop;
	int err;

	/* Do not overwrite a completion left pending by a previous timeout. */
	scoped_guard(spinlock_irqsave, &sdchan->vchan.lock) {
		sdxi_dma_reap_locked(sdchan);
		if (sdchan->sync_cst)
			return;
	}

	/* Submit a single nop with fence and wait for it to complete. */
	if (sdxi_ring_reserve(cxt->ring_state, 1, &resv))
		return;

	nop = sdxi_ring_resv_slot(&resv, 0);
	scoped_guard(spinlock_irqsave, &sdchan->vchan.lock) {
		sdxi_serialize_nop(sdxi_slot_desc(nop));
		sdchan->sync_index = nop.index;
		sdchan->sync_polling = true;
		sdxi_cxt_submit(cxt, nop, &cst,
				SDXI_CXT_SUBMIT_FENCE | SDXI_CXT_SUBMIT_KICK);
		sdchan->sync_cst = cst;
	}

	err = sdxi_cst_blk_poll(cst);
	WARN_ONCE(err, "got %d polling cst_blk", err);

	/*
	 * The nop poll only proves the device drained the ring. The completion
	 * IRQ that reaps those txds -- and schedules their virt-dma callbacks
	 * via vchan_cookie_complete() -- may still be in flight on another CPU.
	 * Wait for it before vchan_synchronize()'s tasklet_kill(), otherwise a
	 * callback can be scheduled after the flush and run against a txd (or
	 * callback_param) freed once we return.
	 */
	synchronize_irq(sdchan->irq);
	scoped_guard(spinlock_irqsave, &sdchan->vchan.lock) {
		sdchan->sync_polling = false;
		/* Also consume statuses if the final batch IRQ has not arrived. */
		sdxi_dma_reap_locked(sdchan);
	}
	vchan_synchronize(&sdchan->vchan);
}

VISIBLE_IF_KUNIT void sdxi_dma_reap_locked(struct sdxi_dma_chan *sdchan)
{
	struct virt_dma_chan *vchan = &sdchan->vchan;
	struct virt_dma_desc *vdesc;

	lockdep_assert_held(&vchan->lock);

	/*
	 * Reap completed txds in issue (cookie) order. After terminate_all,
	 * desc_issued may be empty; the loop then does nothing.
	 */
	while ((vdesc = vchan_next_desc(vchan))) {
		struct sdxi_dma_txd *txd = to_sdxi_dma_txd(vdesc);
		enum sdxi_completion_state state;

		/* A synchronization NOP may sit between issued batches. */
		if (sdchan->sync_cst && txd->copy_index > sdchan->sync_index) {
			if (sdchan->sync_polling ||
			    sdxi_cst_blk_check(sdchan->sync_cst) == SDXI_COMPLETION_PENDING)
				break;
			sdxi_ring_retire(sdchan->cxt->ring_state, sdchan->sync_index + 1);
			sdchan->sync_cst = NULL;
		}

		state = sdxi_cst_blk_check(txd->cst);
		if (state == SDXI_COMPLETION_PENDING)
			break;

		if (state == SDXI_COMPLETION_ERROR)
			txd->vdesc.tx_result.result = DMA_TRANS_ABORTED;

		list_del(&vdesc->node);
		sdxi_ring_retire(sdchan->cxt->ring_state, txd->retire_index);
		vchan_cookie_complete(&txd->vdesc);
	}

	if (list_empty(&vchan->desc_issued) && sdchan->sync_cst &&
	    !sdchan->sync_polling &&
	    sdxi_cst_blk_check(sdchan->sync_cst) != SDXI_COMPLETION_PENDING) {
		sdxi_ring_retire(sdchan->cxt->ring_state, sdchan->sync_index + 1);
		sdchan->sync_cst = NULL;
	}
}
EXPORT_SYMBOL_IF_KUNIT(sdxi_dma_reap_locked);

static irqreturn_t sdxi_dma_cxt_irq(int irq, void *data)
{
	struct sdxi_dma_chan *sdchan = data;

	guard(spinlock_irqsave)(&sdchan->vchan.lock);

	sdxi_dma_reap_locked(sdchan);
	/* Consumed completion blocks may let stalled pending txds proceed. */
	if (sdxi_dma_drain_locked(sdchan))
		sdxi_cxt_kick(sdchan->cxt);

	return IRQ_HANDLED;
}

static int sdxi_dma_alloc_chan_resources(struct dma_chan *dma_chan)
{
	struct sdxi_dev *sdxi = dev_get_drvdata(dma_chan->device->dev);
	struct sdxi_dma_chan *sdchan = to_sdxi_dma_chan(dma_chan);
	int vector, irq, err;

	sdchan->cxt = sdxi_cxt_new(sdxi);
	if (!sdchan->cxt)
		return -ENOMEM;
	sdxi_ring_track_retirement(sdchan->cxt->ring_state);
	sdchan->sync_cst = NULL;
	sdchan->sync_polling = false;
	/*
	 * This irq and akey setup should perhaps all be pushed into
	 * the context allocation.
	 */
	err = vector = sdxi_alloc_vector(sdxi);
	if (vector < 0)
		goto exit_cxt;

	sdchan->vector = vector;

	err = irq = sdxi_vector_to_irq(sdxi, vector);
	if (irq < 0)
		goto free_vector;

	sdchan->irq = irq;

	/*
	 * Note this akey entry is used for both the completion
	 * interrupt and source and destination access for copies.
	 */
	sdchan->akey = sdxi_alloc_akey(sdchan->cxt);
	if (!sdchan->akey) {
		err = -ENOMEM;
		goto free_vector;
	}

	*sdchan->akey = (typeof(*sdchan->akey)) {
		.intr_num = cpu_to_le16(FIELD_PREP(SDXI_AKEY_ENT_VL, 1) |
					FIELD_PREP(SDXI_AKEY_ENT_IV, 1) |
					FIELD_PREP(SDXI_AKEY_ENT_INTR_NUM,
						   vector)),
	};

	err = request_irq(sdchan->irq, sdxi_dma_cxt_irq,
			  IRQF_TRIGGER_NONE, "SDXI DMAengine", sdchan);
	if (err)
		goto free_akey;

	err = sdxi_start_cxt(sdchan->cxt);
	if (err)
		goto free_irq;

	return 0;
free_irq:
	free_irq(sdchan->irq, sdchan);
free_akey:
	sdxi_free_akey(sdchan->cxt, sdchan->akey);
free_vector:
	sdxi_free_vector(sdxi, vector);
exit_cxt:
	sdxi_cxt_exit(sdchan->cxt);
	return err;
}

static void sdxi_dma_free_chan_resources(struct dma_chan *dma_chan)
{
	struct sdxi_dma_chan *sdchan = to_sdxi_dma_chan(dma_chan);

	sdxi_stop_cxt(sdchan->cxt);
	free_irq(sdchan->irq, sdchan);
	sdxi_free_vector(sdchan->cxt->sdxi, sdchan->vector);
	sdxi_free_akey(sdchan->cxt, sdchan->akey);
	vchan_free_chan_resources(to_virt_chan(dma_chan));
	sdxi_cxt_exit(sdchan->cxt);
}

int sdxi_dma_register(struct sdxi_dev *sdxi)
{
	struct device *dev = sdxi->dev;
	struct sdxi_dma_dev *sddev;
	struct dma_device *dma_dev;
	unsigned int nr_channels = dma_channels; /* writable module param; snapshot it */
	int err;

	if (!nr_channels)
		return 0;
	/*
	 * Note that this code assumes the device supports the
	 * interrupt operation group (IntrGrp), which is optional. See
	 * SDXI 1.0 Table 6-1 SDXI Operation Groups.
	 *
	 * TODO: check sdxi->op_grp_cap for IntrGrp support and error
	 * out if it's missing.
	 */

	sddev = devm_kzalloc(dev, struct_size(sddev, sdchan, nr_channels),
			     GFP_KERNEL);
	if (!sddev)
		return -ENOMEM;

	sddev->nr_channels = nr_channels;

	dma_dev = &sddev->dma_dev;
	*dma_dev = (typeof(*dma_dev)) {
		.dev                 = dev,
		.src_addr_widths     = DMA_SLAVE_BUSWIDTH_64_BYTES,
		.dst_addr_widths     = DMA_SLAVE_BUSWIDTH_64_BYTES,
		.directions          = BIT(DMA_MEM_TO_MEM),
		.residue_granularity = DMA_RESIDUE_GRANULARITY_DESCRIPTOR,

		.device_alloc_chan_resources = sdxi_dma_alloc_chan_resources,
		.device_free_chan_resources  = sdxi_dma_free_chan_resources,

		.device_prep_dma_memcpy = sdxi_dma_prep_memcpy,

		.device_terminate_all = sdxi_dma_terminate_all,
		.device_synchronize = sdxi_dma_synchronize,
		.device_tx_status = sdxi_tx_status,
		.device_issue_pending = sdxi_dma_issue_pending,
	};

	dma_cap_set(DMA_MEMCPY, dma_dev->cap_mask);
	INIT_LIST_HEAD(&dma_dev->channels);

	for (size_t i = 0; i < sddev->nr_channels; ++i) {
		struct sdxi_dma_chan *sdchan = &sddev->sdchan[i];

		sdchan->vchan.desc_free = sdxi_dma_txd_free;
		vchan_init(&sdchan->vchan, &sddev->dma_dev);
		INIT_LIST_HEAD(&sdchan->pending);
	}

	err = dmaenginem_async_device_register(dma_dev);
	if (err)
		return dev_warn_probe(dev, err, "failed to register dma device\n");

	return 0;
}
