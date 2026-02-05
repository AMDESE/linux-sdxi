// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI dmaengine provider
 *
 * Copyright (C) 2025 Advanced Micro Devices, Inc.
 */

#include <linux/cleanup.h>
#include <linux/delay.h>
#include <linux/dev_printk.h>
#include <linux/container_of.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/spinlock.h>

#include "../dmaengine.h"
#include "../virt-dma.h"
#include "admin.h"
#include "completion.h"
#include "context.h"
#include "descriptor.h"
#include "dma.h"
#include "ring.h"
#include "sdxi.h"

static bool dma_engine;
module_param(dma_engine, bool, 0644);
MODULE_PARM_DESC(dma_engine, "Enable DMA engine interface (default: false)");

/*
 * This provider uses virt_dma_chan / virt_dma_desc.
 *
 * SDXI supports up to 16K submission queues (contexts) per device. One
 * SDXI context is allocated for each virtual DMA channel.
 *
 * Each context has a descriptor ring with a minimum of 1K slots. SDXI
 * supports a variety of primitive operations, e.g. copy, interrupt,
 * nop. Each Linux virtual DMA descriptor may be composed of a
 * grouping of SDXI descriptors in the ring. E.g. two SDXI descriptors
 * (copy, then interrupt) to implement a dma_async_tx_descriptor for
 * memcpy with DMA_PREP_INTERRUPT flag.
 *
 * dma_device->device_prep_dma_* functions reserve space in the
 * descriptor ring and serialize SDXI descriptors implementing the
 * operation to the reserved slots, leaving their valid (vl) bits
 * clear. A single virtual descriptor is added to the allocated list.
 *
 * dma_async_tx_descriptor->tx_submit() invokes vchan_tx_submit(),
 * which merely assigns a cookie and moves the txd to the submitted
 * list without entering the SDXI provider code.
 *
 * dma_device->device_issue_pending (sdxi_dma_issue_pending()) sets vl
 * on each SDXI descriptor reachable from the submitted list, then
 * rings the doorbell. The submitted txds are moved to the issued list
 * via vchan_issue_pending().
 */

struct sdxi_dma_chan {
	struct virt_dma_chan vchan;
	struct sdxi_cxt *cxt;
	int irq;
	u16 intr_akey;
};

struct sdxi_dma_dev {
	struct dma_device dma_dev;
	struct sdxi_dma_chan sdchan;
};

/*
 * A virtual descriptor can correspond to a group of SDXI hardware descriptors.
 */
struct sdxi_dma_desc {
	struct virt_dma_desc vdesc;
	struct sdxi_ring_resv resv;
	struct sdxi_completion *completion; // Should this be optional? Maybe there should always be one completion per txd.
};

static struct sdxi_dma_chan *to_sdxi_dma_chan(const struct dma_chan *dma_chan)
{
	const struct virt_dma_chan *vchan;

	vchan = container_of_const(dma_chan, struct virt_dma_chan, chan);
	return container_of(vchan, struct sdxi_dma_chan, vchan);
}

static struct sdxi_dma_dev *to_sdxi_dma_dev(const struct dma_device *dma_dev)
{
	return container_of(dma_dev, struct sdxi_dma_dev, dma_dev);
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
	kfree(to_sdxi_dma_desc(vdesc));
}

static struct sdxi_dma_desc *
prep_memcpy_intr(struct dma_chan *dma_chan, const struct sdxi_copy *params)
{
	struct sdxi_cxt *cxt = to_sdxi_dma_chan(dma_chan)->cxt;
	struct sdxi_completion *completion __free(sdxi_completion) = NULL;
	struct sdxi_dma_desc *sddesc __free(kfree) = NULL;
	struct sdxi_desc *copy, *intr;

	completion = sdxi_completion_alloc(cxt->sdxi);
	if (!completion)
		return NULL;

	sddesc = kzalloc(sizeof(*sddesc), GFP_NOWAIT);
	if (!sddesc)
		return NULL;

	if (sdxi_ring_try_reserve(cxt->ring_state, 2, &sddesc->resv))
		return NULL;

	copy = sdxi_ring_resv_next(&sddesc->resv);
	(void)sdxi_encode_copy(copy, params); /* Caller checked validity. */
	sdxi_desc_set_fence(copy); /* Conservatively fence every descriptor. */
	sdxi_completion_attach(copy, completion);

	sddesc->completion = no_free_ptr(completion);

	intr = sdxi_ring_resv_next(&sddesc->resv);
	sdxi_encode_intr(intr, &(const struct sdxi_intr) {
			.akey = to_sdxi_dma_chan(dma_chan)->intr_akey,
		});
	/* Raise the interrupt only after the copy has completed. */
	sdxi_desc_set_fence(intr);
	return_ptr(sddesc);
}

static struct sdxi_dma_desc *
prep_memcpy_polled(struct dma_chan *dma_chan, const struct sdxi_copy *params)
{
	struct sdxi_cxt *cxt = to_sdxi_dma_chan(dma_chan)->cxt;
	struct sdxi_completion *completion __free(sdxi_completion) = NULL;
	struct sdxi_dma_desc *sddesc __free(kfree) = NULL;
	struct sdxi_desc *copy;

	completion = sdxi_completion_alloc(cxt->sdxi);
	if (!completion)
		return NULL;

	sddesc = kzalloc(sizeof(*sddesc), GFP_NOWAIT);
	if (!sddesc)
		return NULL;

	if (sdxi_ring_try_reserve(cxt->ring_state, 1, &sddesc->resv))
		return NULL;

	copy = sdxi_ring_resv_next(&sddesc->resv);
	(void)sdxi_encode_copy(copy, params); /* Caller checked validity. */
	sdxi_completion_attach(copy, completion);

	sddesc->completion = no_free_ptr(completion);
	return_ptr(sddesc);
}

static struct dma_async_tx_descriptor *
sdxi_dma_prep_memcpy(struct dma_chan *dma_chan, dma_addr_t dst,
		     dma_addr_t src, size_t len, unsigned long flags)
{
	bool always_interrupt;
	struct sdxi_dma_desc *sddesc;
	struct sdxi_copy copy = {
		.src = src,
		.dst = dst,
		.src_akey = 0,
		.dst_akey = 0,
		.len = len,
	};

	/*
	 * temp hack: perform a trial encode to a dummy descriptor on
	 * the stack so we can reject bad inputs without touching the
	 * ring state.
	 */
	if (sdxi_encode_copy(&(struct sdxi_desc){}, &copy))
		return NULL;
	/*
	 * No attempt to batch/coalesce for now; raise an interrupt
	 * for each descriptor completion.
	 */
	always_interrupt = true;

	sddesc = ((flags & DMA_PREP_INTERRUPT) || always_interrupt) ?
		prep_memcpy_intr(dma_chan, &copy) :
		prep_memcpy_polled(dma_chan, &copy);

	return vchan_tx_prep(to_virt_chan(dma_chan), &sddesc->vdesc, flags);
}

static enum dma_status sdxi_tx_status(struct dma_chan *chan,
				      dma_cookie_t cookie,
				      struct dma_tx_state *state)
{
	struct sdxi_dma_chan *sdchan = to_sdxi_dma_chan(chan);
	struct sdxi_dma_desc *sddesc;
	enum dma_status status;
	struct virt_dma_desc *vdesc;

	status = dma_cookie_status(chan, cookie, state);
	if (status == DMA_COMPLETE)
		return status;

	guard(spinlock_irqsave)(&sdchan->vchan.lock);

	vdesc = vchan_find_desc(&sdchan->vchan, cookie);
	if (!vdesc)
		return status;

	sddesc = to_sdxi_dma_desc(vdesc);

	if (WARN_ON_ONCE(!sddesc->completion))
		return DMA_ERROR;

	if (!sdxi_completion_signaled(sddesc->completion))
		return DMA_IN_PROGRESS;

	if (sdxi_completion_errored(sddesc->completion))
		return DMA_ERROR;

	list_del(&vdesc->node);
	vchan_cookie_complete(vdesc);

	return dma_cookie_status(chan, cookie, state);
}

static void sdxi_dma_issue_pending(struct dma_chan *dma_chan)
{
	struct virt_dma_chan *vchan = to_virt_chan(dma_chan);
	struct virt_dma_desc *vdesc;
	u64 dbval = 0;

	scoped_guard(spinlock_irqsave, &vchan->lock) {
		/*
		 * This can happen with racing submitters. We could
		 * speculatively check this without taking the lock?
		 */
		if (list_empty(&vchan->desc_submitted))
			return;

		list_for_each_entry(vdesc, &vchan->desc_submitted, node) {
			struct sdxi_dma_desc *sddesc = to_sdxi_dma_desc(vdesc);
			struct sdxi_desc *hwdesc;

			sdxi_ring_resv_foreach(&sddesc->resv, hwdesc)
				sdxi_desc_make_valid(hwdesc);
			/*
			 * The reservations ought to be ordered
			 * ascending, but use umax() just in case.
			 */
			dbval = umax(sdxi_ring_resv_dbval(&sddesc->resv), dbval);
		}

		vchan_issue_pending(vchan);
	}

	/*
	 * The implementation is required to handle out-of-order
	 * doorbell updates; we can do this after dropping the
	 * lock.
	 */
	sdxi_cxt_push_doorbell(to_sdxi_dma_chan(dma_chan)->cxt, dbval);
}

static int sdxi_dma_terminate_all(struct dma_chan *dma_chan)
{
	struct virt_dma_chan *vchan = to_virt_chan(dma_chan);
	u64 dbval = 0;

	/*
	 * Allocated and submitted txds are in the ring but not valid
	 * yet. Overwrite them with nops and then set their valid
	 * bits.
	 *
	 * The implementation may start consuming these as soon as the
	 * valid bits flip. sdxi_dma_synchronize() will ensure they're
	 * all done.
	 */
	scoped_guard(spinlock_irqsave, &vchan->lock) {
		struct virt_dma_desc *vdesc;
		LIST_HEAD(head);

		list_splice_tail_init(&vchan->desc_allocated, &head);
		list_splice_tail_init(&vchan->desc_submitted, &head);

		if (list_empty(&head))
			return 0;

		list_for_each_entry(vdesc, &head, node) {
			struct sdxi_dma_desc *sddesc = to_sdxi_dma_desc(vdesc);
			struct sdxi_desc *hwdesc;

			sdxi_ring_resv_foreach(&sddesc->resv, hwdesc) {
				sdxi_serialize_nop(hwdesc);
				sdxi_desc_make_valid(hwdesc);
			}

			dbval = umax(sdxi_ring_resv_dbval(&sddesc->resv), dbval);
		}

		list_splice_tail(&head, &vchan->desc_terminated);
	}

	sdxi_cxt_push_doorbell(to_sdxi_dma_chan(dma_chan)->cxt, dbval);

	return 0;
}

static void sdxi_dma_synchronize(struct dma_chan *dma_chan)
{
	struct sdxi_cxt *cxt = to_sdxi_dma_chan(dma_chan)->cxt;
	struct sdxi_ring_resv resv;
	struct sdxi_desc *nop;

	/* Submit a single nop with fence and wait for it to complete. */

	if (sdxi_ring_reserve(cxt->ring_state, 1, &resv))
		return;

	struct sdxi_completion *sc = sdxi_completion_alloc(cxt->sdxi);
	if (!sc)
		return;

	nop = sdxi_ring_resv_next(&resv);
	sdxi_serialize_nop(nop);
	sdxi_completion_attach(nop, sc);
	sdxi_desc_set_fence(nop);
	sdxi_desc_make_valid(nop);
	sdxi_cxt_push_doorbell(cxt, sdxi_ring_resv_dbval(&resv));
	sdxi_completion_poll(sc);
	sdxi_completion_free(sc);

	vchan_synchronize(to_virt_chan(dma_chan));
}

static irqreturn_t sdxi_dma_cxt_irq(int irq, void *data)
{
	struct sdxi_dma_chan *sdchan = data;
	struct virt_dma_chan *vchan = &sdchan->vchan;
	struct virt_dma_desc *vdesc;
	bool completed = false;

	guard(spinlock_irqsave)(&vchan->lock);

	while ((vdesc = vchan_next_desc(vchan))) {
		struct sdxi_dma_desc *sddesc = to_sdxi_dma_desc(vdesc);

		if (!sdxi_completion_signaled(sddesc->completion))
			break;

		list_del(&vdesc->node);
		vchan_cookie_complete(&sddesc->vdesc);
		completed = true;
	}

	if (completed)
		sdxi_ring_wake_up(sdchan->cxt->ring_state);

	return IRQ_HANDLED;
}

static int sdxi_dma_alloc_chan_resources(struct dma_chan *dma_chan)
{
	return sdxi_adm_start_cxt(to_sdxi_dma_chan(dma_chan)->cxt);
}

static void sdxi_dma_free_chan_resources(struct dma_chan *dma_chan)
{
	sdxi_adm_stop_cxt(to_sdxi_dma_chan(dma_chan)->cxt);
	vchan_free_chan_resources(to_virt_chan(dma_chan));
}

#define BAD_HARDCODED_MSG 1
#define BAD_HARDCODED_AKEY_IDX 1

static int add_channel(struct sdxi_dma_dev *sddev, struct sdxi_dma_chan *sdchan)
{
	struct sdxi_dev *sdxi = dev_get_drvdata(sddev->dma_dev.dev);
	struct sdxi_cxt *cxt;
	int err;

	sdchan->vchan.desc_free = sdxi_tx_desc_free;
	vchan_init(&sdchan->vchan, &sddev->dma_dev);

	err = -ENOMEM;
	cxt = sdxi_kcxt_new(sdxi);
	if (!cxt)
		return err;

	sdchan->cxt = cxt;

	/* FIXME: Add an akey allocation API, don't hardcode the index. */
	sdchan->intr_akey = BAD_HARDCODED_AKEY_IDX;
	sdchan->cxt->akey_table->entry[BAD_HARDCODED_AKEY_IDX] = (struct sdxi_akey_ent) {
		.intr_num = cpu_to_le16(FIELD_PREP(SDXI_AKEY_ENT_VL, 1) |
					FIELD_PREP(SDXI_AKEY_ENT_IV, 1) |
					FIELD_PREP(SDXI_AKEY_ENT_INTR_NUM,
						   BAD_HARDCODED_MSG)),
	};

	/* FIXME: remove PCI dependency and hardcoded MSI index */
	sdchan->irq = pci_irq_vector(to_pci_dev(sdxi_to_dev(sdxi)),
				     BAD_HARDCODED_MSG);
	err = request_irq(sdchan->irq, sdxi_dma_cxt_irq,
			  IRQF_TRIGGER_NONE, "SDXI DMAengine", sdchan);
	if (err)
		goto exit_cxt;

	return 0;

exit_cxt:
	sdxi_working_cxt_exit(cxt);
	return err;
}

static void sdxi_dma_release(struct dma_device *dma_dev)
{
	struct sdxi_dma_dev *sddev = to_sdxi_dma_dev(dma_dev);

	sdxi_info(dev_get_drvdata(sddev->dma_dev.dev), "releasing irq %d\n",
		  sddev->sdchan.irq);

	free_irq(sddev->sdchan.irq, &sddev->sdchan);
}

int sdxi_dma_register(struct sdxi_dev *sdxi)
{
	struct device *dev = sdxi_to_dev(sdxi);
	struct sdxi_dma_dev *sddev;
	struct dma_device *dma_dev;
	int err;

	if (!dma_engine)
		return 0;
	/*
	 * FIXME: This code assumes the device supports the interrupt
	 * operation group. It's probably not a bad assumption, but
	 * IntrGrp is optional in the spec. We should probe the
	 * device's opgroups and bail if IntrGrp isn't implemented.
	 */

	sddev = devm_kzalloc(dev, sizeof(*sddev), GFP_KERNEL);
	if (!sddev)
		return -ENOMEM;

	dma_dev = &sddev->dma_dev;
	*dma_dev = (typeof(*dma_dev)) {
		.dev                 = sdxi_to_dev(sdxi),
		.src_addr_widths     = DMA_SLAVE_BUSWIDTH_64_BYTES,
		.dst_addr_widths     = DMA_SLAVE_BUSWIDTH_64_BYTES,
		.directions          = BIT(DMA_MEM_TO_MEM),
		.residue_granularity = DMA_RESIDUE_GRANULARITY_DESCRIPTOR,

		.device_alloc_chan_resources = sdxi_dma_alloc_chan_resources,
		.device_free_chan_resources  = sdxi_dma_free_chan_resources,

		.device_prep_dma_memcpy = sdxi_dma_prep_memcpy,

		.device_pause = NULL, /* fixme */
		.device_resume = NULL, /* fixme */
		.device_terminate_all = sdxi_dma_terminate_all,
		.device_synchronize = sdxi_dma_synchronize,
		.device_tx_status = sdxi_tx_status,
		.device_issue_pending = sdxi_dma_issue_pending,
		.device_release = sdxi_dma_release,
	};

	dma_cap_set(DMA_MEMCPY, dma_dev->cap_mask);
	dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));
	INIT_LIST_HEAD(&dma_dev->channels);

	if ((err = add_channel(sddev, &sddev->sdchan)))
		return dev_warn_probe(dev, err, "failed channel setup\n");

	return dmaenginem_async_device_register(dma_dev);
}
