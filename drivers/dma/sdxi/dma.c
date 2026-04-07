// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI dmaengine provider
 *
 * Copyright Advanced Micro Devices, Inc.
 */

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

static unsigned short dma_channels = 1;
module_param(dma_channels, ushort, 0644);
MODULE_PARM_DESC(dma_channels, "DMA channels per function (default: 1)");

/*
 * An SDXI context is allocated for each channel configured.
 *
 * Each context has a descriptor ring with a minimum of 1K entries.
 * SDXI supports a variety of primitive operations, e.g. copy,
 * interrupt, nop. Each Linux virtual DMA descriptor is composed of a
 * grouping of SDXI descriptors in the ring.
 *
 * device_prep_dma_memcpy() builds the copy descriptor and a completion
 * block in the vdesc and validates it, but does not touch the ring.
 * tx_submit() (vchan_tx_submit()) assigns a cookie and moves the vdesc to
 * the submitted list.
 *
 * device_issue_pending() moves submitted vdescs to a per-channel pending
 * list and drains it: for each pending vdesc, in cookie order, it reserves
 * ring slots, encodes the descriptors in place, attaches the completion
 * block, sets the valid bits, appends an interrupt terminator, and rings
 * the doorbell. Reserving at issue (rather than at prep) keeps ring order
 * equal to cookie order, which virt-dma's in-order completion model
 * requires. Descriptors that do not fit stay on the pending list and are
 * drained by the completion IRQ as ring space frees.
 */

struct sdxi_dma_chan {
	struct virt_dma_chan vchan;
	struct sdxi_cxt *cxt;
	unsigned int vector;
	unsigned int irq;
	struct sdxi_akey_ent *akey;
	/*
	 * Issued descriptors not yet placed in the ring (it was full).
	 * Drained as completions free ring space. Guarded by vchan.lock.
	 */
	struct list_head pending;
};

struct sdxi_dma_dev {
	struct dma_device dma_dev;
	size_t nr_channels;
	struct sdxi_dma_chan sdchan[] __counted_by(nr_channels);
};

struct sdxi_dma_desc {
	struct virt_dma_desc vdesc;
	/* Copy parameters, built and validated at prep time. */
	struct sdxi_copy copy;
	/*
	 * Completion block, attached to the copy's ring slot at issue time.
	 * Freed with this descriptor.
	 */
	struct sdxi_completion *completion;
};

static struct sdxi_dma_chan *to_sdxi_dma_chan(const struct dma_chan *dma_chan)
{
	const struct virt_dma_chan *vchan;

	vchan = container_of_const(dma_chan, struct virt_dma_chan, chan);
	return container_of(vchan, struct sdxi_dma_chan, vchan);
}

static struct sdxi_dma_desc *
to_sdxi_dma_desc(const struct virt_dma_desc *vdesc)
{
	return container_of(vdesc, struct sdxi_dma_desc, vdesc);
}

static void sdxi_tx_desc_free(struct virt_dma_desc *vdesc)
{
	struct sdxi_dma_desc *sddesc = to_sdxi_dma_desc(vdesc);

	sdxi_completion_free(sddesc->completion);
	kfree(sddesc);
}

static struct dma_async_tx_descriptor *
sdxi_dma_prep_memcpy(struct dma_chan *dma_chan, dma_addr_t dst,
		     dma_addr_t src, size_t len, unsigned long flags)
{
	struct sdxi_dma_chan *sdchan = to_sdxi_dma_chan(dma_chan);
	struct sdxi_cxt *cxt = sdchan->cxt;
	u16 akey_index = sdxi_akey_index(cxt, sdchan->akey);
	struct sdxi_copy copy = {
		.src = src,
		.dst = dst,
		.src_akey = akey_index,
		.dst_akey = akey_index,
		.len = len,
	};

	/*
	 * Validate now, before a ring slot exists, with a throwaway encode
	 * onto the stack. The real encode into the ring happens at issue.
	 */
	if (sdxi_encode_copy(&(struct sdxi_desc){}, &copy))
		return NULL;

	struct sdxi_completion *comp __free(sdxi_completion) =
		sdxi_completion_alloc(cxt->sdxi);
	if (!comp)
		return NULL;

	struct sdxi_dma_desc *sddesc __free(kfree) =
		kzalloc(sizeof(*sddesc), GFP_NOWAIT);
	if (!sddesc)
		return NULL;

	sddesc->copy = copy;
	sddesc->completion = no_free_ptr(comp);

	return vchan_tx_prep(&sdchan->vchan, &no_free_ptr(sddesc)->vdesc, flags);
}

static enum dma_status sdxi_tx_status(struct dma_chan *chan,
				      dma_cookie_t cookie,
				      struct dma_tx_state *state)
{
	struct sdxi_dma_chan *sdchan = to_sdxi_dma_chan(chan);
	struct virt_dma_desc *vdesc;

	/* Under the lock for a consistent cookie snapshot; the IRQ reaps. */
	guard(spinlock_irqsave)(&sdchan->vchan.lock);

	vdesc = vchan_find_desc(&sdchan->vchan, cookie);
	if (vdesc) {
		struct sdxi_dma_desc *sddesc = to_sdxi_dma_desc(vdesc);

		if (sddesc->completion &&
		    sdxi_completion_check(sddesc->completion) == SDXI_COMPLETION_ERROR)
			return DMA_ERROR;
	}

	return dma_cookie_status(chan, cookie, state);
}

/*
 * Place as many pending copies into the ring as fit, each followed by an
 * interrupt terminator. Leftovers stay on the pending list for the next
 * drain (a later issue, or a completion IRQ freeing ring space). Caller
 * holds vchan.lock.
 */
static void sdxi_dma_drain_locked(struct sdxi_dma_chan *sdchan)
{
	struct sdxi_cxt *cxt = sdchan->cxt;
	struct sdxi_ring_state *rs = cxt->ring_state;
	struct virt_dma_desc *vdesc, *tmp;
	bool pushed = false;

	lockdep_assert_held(&sdchan->vchan.lock);

	list_for_each_entry_safe(vdesc, tmp, &sdchan->pending, node) {
		struct sdxi_dma_desc *sddesc = to_sdxi_dma_desc(vdesc);
		struct sdxi_ring_resv resv;
		struct sdxi_desc *slot;

		/*
		 * A copy descriptor plus one interrupt terminator. If they do
		 * not fit, leave this and the remaining pending descriptors for
		 * the next drain. Reserved-but-reclaimed ring slots are vl=0
		 * (the function clears vl as it executes), so advancing the
		 * write index here exposes only invalid slots until make_valid;
		 * the device waits on them.
		 */
		if (sdxi_ring_try_reserve(rs, 2, &resv))
			break;

		slot = sdxi_ring_resv_next(&resv);
		(void)sdxi_encode_copy(slot, &sddesc->copy); /* validated at prep */
		/* Conservatively fence. TODO: relax per DMA_PREP_FENCE. */
		sdxi_desc_set_fence(slot);
		sdxi_completion_attach(slot, sddesc->completion);
		sdxi_desc_make_valid(slot);

		/*
		 * Interrupt terminator: a fenced INTR that raises its IRQ only
		 * once every preceding descriptor has completed, reaping this
		 * operation. It owns no cookie and no completion block, so the
		 * IRQ handler (which walks desc_issued checking completion
		 * blocks) never sees it.
		 */
		slot = sdxi_ring_resv_next(&resv);
		sdxi_encode_intr(slot, &(const struct sdxi_intr) {
			.akey = sdxi_akey_index(cxt, sdchan->akey),
		});
		sdxi_desc_set_fence(slot);
		sdxi_desc_make_valid(slot);

		list_move_tail(&vdesc->node, &sdchan->vchan.desc_issued);
		pushed = true;
	}

	if (pushed)
		sdxi_cxt_kick(cxt);
}

static void sdxi_dma_issue_pending(struct dma_chan *dma_chan)
{
	struct sdxi_dma_chan *sdchan = to_sdxi_dma_chan(dma_chan);

	guard(spinlock_irqsave)(&sdchan->vchan.lock);

	list_splice_tail_init(&sdchan->vchan.desc_submitted, &sdchan->pending);
	sdxi_dma_drain_locked(sdchan);
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
	 * completion and the IRQ reaps it (and frees its completion block).
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
	struct sdxi_desc *nop;
	int err;

	/* Submit a single nop with fence and wait for it to complete. */

	if (sdxi_ring_reserve(cxt->ring_state, 1, &resv))
		return;

	struct sdxi_completion *comp __free(sdxi_completion) = sdxi_completion_alloc(cxt->sdxi);
	if (!comp)
		return;

	nop = sdxi_ring_resv_next(&resv);
	sdxi_serialize_nop(nop);
	sdxi_completion_attach(nop, comp);
	sdxi_desc_set_fence(nop);
	sdxi_desc_make_valid(nop);
	sdxi_cxt_kick(cxt);

	err = sdxi_completion_poll(comp);
	WARN_ONCE(err, "got %d polling cst_blk", err);

	/*
	 * The nop poll only proves the device drained the ring. The completion
	 * IRQ that reaps those descriptors -- and schedules their virt-dma
	 * callbacks via vchan_cookie_complete() -- may still be in flight on
	 * another CPU. Wait for it before vchan_synchronize()'s tasklet_kill(),
	 * otherwise a callback can be scheduled after the flush and run against
	 * a descriptor (or callback_param) freed once we return.
	 */
	synchronize_irq(sdchan->irq);
	vchan_synchronize(&sdchan->vchan);
}

static irqreturn_t sdxi_dma_cxt_irq(int irq, void *data)
{
	struct sdxi_dma_chan *sdchan = data;
	struct virt_dma_chan *vchan = &sdchan->vchan;
	struct virt_dma_desc *vdesc;
	bool completed = false;

	guard(spinlock_irqsave)(&vchan->lock);

	/*
	 * Reap completed descriptors in issue (cookie) order. After
	 * terminate_all, desc_issued may be empty; the loop then does nothing.
	 */
	while ((vdesc = vchan_next_desc(vchan))) {
		struct sdxi_dma_desc *sddesc = to_sdxi_dma_desc(vdesc);
		enum sdxi_completion_state state;

		state = sdxi_completion_check(sddesc->completion);
		if (state == SDXI_COMPLETION_PENDING)
			break;

		if (state == SDXI_COMPLETION_ERROR)
			sddesc->vdesc.tx_result.result = DMA_TRANS_ABORTED;

		list_del(&vdesc->node);
		vchan_cookie_complete(&sddesc->vdesc);
		completed = true;
	}

	/* Freed ring space may let stalled pending descriptors proceed. */
	sdxi_dma_drain_locked(sdchan);

	if (completed)
		sdxi_ring_wake_up(sdchan->cxt->ring_state);

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

		sdchan->vchan.desc_free = sdxi_tx_desc_free;
		vchan_init(&sdchan->vchan, &sddev->dma_dev);
		INIT_LIST_HEAD(&sdchan->pending);
	}

	err = dmaenginem_async_device_register(dma_dev);
	if (err)
		return dev_warn_probe(dev, err, "failed to register dma device\n");

	return 0;
}
