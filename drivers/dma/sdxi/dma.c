/*
 * SDXI DMA engine implementation
 *   Derived from ptdma code
 *
 * Copyright (C) 2022 AMD, Inc. All rights reserved.
 *
 * Author: Wei Huang <wei.huang2@amd.com>
 * Author: Sanjay R Mehta <sanju.mehta@amd.com>
 *
 */

#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>

#include "../dmaengine.h"
#include "sdxi.h"
#include "context.h"

static inline struct sdxi_dma_chan *to_sdxi_dma_chan(struct dma_chan *dma_chan)
{
	return container_of(dma_chan, struct sdxi_dma_chan, vc.chan);
}

static inline struct sdxi_dma_desc *to_sdxi_dma_desc(struct virt_dma_desc *vd)
{
	return container_of(vd, struct sdxi_dma_desc, vd);
}

static void sdxi_dma_free_chan_resources(struct dma_chan *dma_chan)
{
	struct sdxi_dma_chan *chan = to_sdxi_dma_chan(dma_chan);

	vchan_free_chan_resources(&chan->vc);
	/* NB: more configure with sdxi_cxt? */
}

static void sdxi_dma_synchronize(struct dma_chan *c)
{
	struct sdxi_dma_chan *chan = to_sdxi_dma_chan(c);

	vchan_synchronize(&chan->vc);
}

static void sdxi_do_cleanup(struct virt_dma_desc *vd)
{
	struct sdxi_dma_desc *desc = to_sdxi_dma_desc(vd);
	struct sdxi_dev *sdxi = desc->cxt->sdxi;

	kmem_cache_free(sdxi->dma_desc_cache, desc);
}

static int sdxi_dma_start_desc(struct sdxi_dma_desc *dma_desc)
{
	struct sdxi_dev *sdxi;
	struct sdxi_cmd *sdxi_cmd;
	struct sdxi_cxt *cxt;
	struct sdxi_sq *sq;
	struct sdxi_desc desc;


	dma_desc->issued_to_hw = 1;

	sdxi_cmd = &dma_desc->sdxi_cmd;
	sdxi = sdxi_cmd->cxt->sdxi;


	sdxi->tdata.cmd = sdxi_cmd;

	/* submit to sdxi context */
	cxt = dma_desc->cxt;
	memset(cxt->dummy_buffer, 0, 4096);
	((int *)cxt->dummy_buffer)[0] = 1;
	sq = cxt->sq;

	if (sdxi_cmd->len > MAX_DMA_COPY_BYTES)
		return 1;

	build_dma_copy(&desc, sdxi_cmd->len, 0, 0, 0, 0, sdxi_cmd->src_addr,
		       sdxi_cmd->dst_addr, cxt->dummy_buffer_addr);

	/* Submit the command */
	sdxi_cmd->index = sdxi_sq_submit_desc(sq, &desc, true, 0xFF);
	sdxi_cmd->ret = 0; // TODO: get desc submit status & update ret value

	return 0;
}

static struct sdxi_dma_desc *sdxi_next_dma_desc(struct sdxi_dma_chan *chan)
{
	/* Get the next DMA descriptor on the active list */
	struct virt_dma_desc *vd = vchan_next_desc(&chan->vc);

	return vd ? to_sdxi_dma_desc(vd) : NULL;
}

static struct sdxi_dma_desc *sdxi_handle_active_desc(struct sdxi_dma_chan *chan,
						     struct sdxi_dma_desc *desc)
{
	struct dma_async_tx_descriptor *tx_desc;
	struct virt_dma_desc *vd;
	unsigned long flags;

	/* Loop over descriptors until one is found with commands */
	do {
		if (desc) {
			if (!desc->issued_to_hw) {
				/* No errors, keep going */
				if (desc->status != DMA_ERROR)
					return desc;
			}

			tx_desc = &desc->vd.tx;
			vd = &desc->vd;
		} else {
			tx_desc = NULL;
		}

		spin_lock_irqsave(&chan->vc.lock, flags);

		if (desc) {

			if (desc->status != DMA_COMPLETE) {
				if (desc->status != DMA_ERROR)
					desc->status = DMA_COMPLETE;

				dma_cookie_complete(tx_desc);
				dma_descriptor_unmap(tx_desc);
				list_del(&desc->vd.node);
			} else {
				/* Don't handle it twice */
				tx_desc = NULL;
			}
		}

		desc = sdxi_next_dma_desc(chan);

		spin_unlock_irqrestore(&chan->vc.lock, flags);

		if (tx_desc) {
			dmaengine_desc_get_callback_invoke(tx_desc, NULL);
			dma_run_dependencies(tx_desc);
			vchan_vdesc_fini(vd);
		}
	} while (desc);

	return NULL;
}

static void sdxi_cmd_callback(void *data, int err)
{
	struct sdxi_dma_desc *desc = data;
	struct dma_chan *dma_chan;
	struct sdxi_dma_chan *chan;
	int ret;

	if (err == -EINPROGRESS)
		return;

	dma_chan = desc->vd.tx.chan;
	chan = to_sdxi_dma_chan(dma_chan);

	if (err)
		desc->status = DMA_ERROR;

	while (true) {
		/* Check for DMA descriptor completion */
		desc = sdxi_handle_active_desc(chan, desc);

		/* Don't submit cmd if no descriptor or DMA is paused */
		if (!desc)
			break;

		ret = sdxi_dma_start_desc(desc);
		if (!ret)
			break;

		desc->status = DMA_ERROR;
	}
}

static struct sdxi_dma_desc *sdxi_dma_alloc_dma_desc(struct sdxi_dma_chan *chan,
						     unsigned long flags)
{
	struct sdxi_dma_desc *desc;

	desc = kmem_cache_zalloc(chan->cxt->sdxi->dma_desc_cache, GFP_NOWAIT);
	if (!desc)
		return NULL;

	desc->cxt = chan->cxt;

	vchan_tx_prep(&chan->vc, &desc->vd, flags);

	desc->cxt->sdxi = chan->cxt->sdxi;
	desc->issued_to_hw = 0;
	desc->status = DMA_IN_PROGRESS;

	return desc;
}

static struct sdxi_dma_desc *sdxi_dma_create_desc(struct dma_chan *dma_chan,
						  dma_addr_t dst,
						  dma_addr_t src,
						  unsigned int len,
						  unsigned long flags)
{
	struct sdxi_dma_chan *chan = to_sdxi_dma_chan(dma_chan);
	struct sdxi_dma_desc *desc;
	struct sdxi_cmd *sdxi_cmd;

	desc = sdxi_dma_alloc_dma_desc(chan, flags);
	if (!desc)
		return NULL;

	sdxi_cmd = &desc->sdxi_cmd;
	sdxi_cmd->cxt = chan->cxt;
	sdxi_cmd->cxt->sdxi = chan->cxt->sdxi;
	sdxi_cmd->src_addr = src;
	sdxi_cmd->dst_addr = dst;
	sdxi_cmd->len = len;
	sdxi_cmd->sdxi_cmd_callback = sdxi_cmd_callback;
	sdxi_cmd->data = desc;

	return desc;
}

static struct dma_async_tx_descriptor *
sdxi_dma_prep_memcpy(struct dma_chan *dma_chan, dma_addr_t dst,
		     dma_addr_t src, size_t len, unsigned long flags)
{
	struct sdxi_dma_desc *desc;

	desc = sdxi_dma_create_desc(dma_chan, dst, src, len, flags);
	if (!desc)
		return NULL;

	return &desc->vd.tx;
}

static struct dma_async_tx_descriptor *
sdxi_prep_dma_interrupt(struct dma_chan *dma_chan, unsigned long flags)
{
	struct sdxi_dma_chan *chan = to_sdxi_dma_chan(dma_chan);
	struct sdxi_dma_desc *desc;

	desc = sdxi_dma_alloc_dma_desc(chan, flags);
	if (!desc)
		return NULL;

	return &desc->vd.tx;
}

static void sdxi_dma_issue_pending(struct dma_chan *dma_chan)
{
	struct sdxi_dma_chan *chan = to_sdxi_dma_chan(dma_chan);
	struct sdxi_dma_desc *desc;
	unsigned long flags;
	bool engine_is_idle = true;

	spin_lock_irqsave(&chan->vc.lock, flags);

	desc = sdxi_next_dma_desc(chan);
	if (desc)
		engine_is_idle = false;

	vchan_issue_pending(&chan->vc);

	desc = sdxi_next_dma_desc(chan);

	spin_unlock_irqrestore(&chan->vc.lock, flags);

	/* If there was nothing active, start processing */
	if (engine_is_idle)
		sdxi_cmd_callback(desc, 0);
}

static void sdxi_check_trans_status(struct sdxi_dma_chan *chan)
{
	struct sdxi_cxt *cxt = chan->cxt;
	struct sdxi_sq *sq;
	struct sdxi_cmd *cmd;

	if (!cxt)
		return;

	sq = cxt->sq;
	cmd = cxt->sdxi->tdata.cmd;

	if (sq->csb[cmd->index].signal == 0xFE)
		sdxi_cmd_callback(cmd->data, cmd->ret);
}

static enum dma_status sdxi_tx_status(struct dma_chan *dma_chan, dma_cookie_t cookie,
				      struct dma_tx_state *tx_state)
{
	struct sdxi_dma_chan *chan = to_sdxi_dma_chan(dma_chan);

	sdxi_check_trans_status(chan);

	return dma_cookie_status(dma_chan, cookie, tx_state);
}

static int sdxi_dma_pause(struct dma_chan *dma_chan)
{
	struct sdxi_dma_chan *chan = to_sdxi_dma_chan(dma_chan);
	unsigned long flags;

	spin_lock_irqsave(&chan->vc.lock, flags);
	// TODO
	spin_unlock_irqrestore(&chan->vc.lock, flags);

	return 0;
}

static int sdxi_dma_resume(struct dma_chan *dma_chan)
{
	struct sdxi_dma_chan *chan = to_sdxi_dma_chan(dma_chan);
	struct sdxi_dma_desc *desc = NULL;
	unsigned long flags;

	spin_lock_irqsave(&chan->vc.lock, flags);
	// TODO
	desc = sdxi_next_dma_desc(chan);
	spin_unlock_irqrestore(&chan->vc.lock, flags);

	/* If there was something active, re-start */
	if (desc)
		sdxi_cmd_callback(desc, 0);

	return 0;
}

static int sdxi_dma_terminate_all(struct dma_chan *dma_chan)
{
	struct sdxi_dma_chan *chan = to_sdxi_dma_chan(dma_chan);
	unsigned long flags;
	LIST_HEAD(head);

	spin_lock_irqsave(&chan->vc.lock, flags);
	vchan_get_all_descriptors(&chan->vc, &head);
	spin_unlock_irqrestore(&chan->vc.lock, flags);

	vchan_dma_desc_free_list(&chan->vc, &head);
	vchan_free_chan_resources(&chan->vc);

	return 0;
}

int sdxi_dma_register(struct sdxi_cxt *dma_cxt)
{
	struct sdxi_dma_chan *chan;
	struct sdxi_dev *sdxi = dma_cxt->sdxi;
	struct device *dev;
	struct dma_device *dma_dev = &sdxi->dma_dev;
	char *cmd_cache_name;
	char *desc_cache_name;
	int ret = 0;

	if (!dma_cxt)
		return 0;

	sdxi = dma_cxt->sdxi;
	dev = &sdxi->pdev->dev;

	sdxi->sdxi_dma_chan = devm_kzalloc(dev, sizeof(*sdxi->sdxi_dma_chan),
					   GFP_KERNEL);
	if (!sdxi->sdxi_dma_chan)
		return -ENOMEM;

	sdxi->sdxi_dma_chan->cxt = dma_cxt;

	cmd_cache_name = devm_kasprintf(dev, GFP_KERNEL,
					"%s-dmaengine-cmd-cache",
					dev_name(dev));
	if (!cmd_cache_name)
		return -ENOMEM;

	desc_cache_name = devm_kasprintf(dev, GFP_KERNEL,
					 "%s-dmaengine-desc-cache",
					 dev_name(dev));
	if (!desc_cache_name) {
		ret = -ENOMEM;
		goto err_cache;
	}

	sdxi->dma_desc_cache = kmem_cache_create(desc_cache_name,
						 sizeof(struct sdxi_dma_desc), 0,
						 SLAB_HWCACHE_ALIGN, NULL);
	if (!sdxi->dma_desc_cache) {
		ret = -ENOMEM;
		goto err_cache;
	}

	dma_dev->dev = dev;
	dma_dev->src_addr_widths = DMA_SLAVE_BUSWIDTH_64_BYTES;
	dma_dev->dst_addr_widths = DMA_SLAVE_BUSWIDTH_64_BYTES;
	dma_dev->directions = DMA_MEM_TO_MEM;
	dma_dev->residue_granularity = DMA_RESIDUE_GRANULARITY_DESCRIPTOR;
	dma_cap_set(DMA_MEMCPY, dma_dev->cap_mask);
	dma_cap_set(DMA_INTERRUPT, dma_dev->cap_mask);

	dma_cap_set(DMA_PRIVATE, dma_dev->cap_mask);

	INIT_LIST_HEAD(&dma_dev->channels);

	chan = sdxi->sdxi_dma_chan;
	chan->cxt->sdxi = sdxi;

	/* Set base and prep routines */
	dma_dev->device_free_chan_resources = sdxi_dma_free_chan_resources;
	dma_dev->device_prep_dma_memcpy = sdxi_dma_prep_memcpy;
	dma_dev->device_prep_dma_interrupt = sdxi_prep_dma_interrupt;
	dma_dev->device_issue_pending = sdxi_dma_issue_pending;
	dma_dev->device_tx_status = sdxi_tx_status;
	dma_dev->device_pause = sdxi_dma_pause;
	dma_dev->device_resume = sdxi_dma_resume;
	dma_dev->device_terminate_all = sdxi_dma_terminate_all;
	dma_dev->device_synchronize = sdxi_dma_synchronize;

	chan->vc.desc_free = sdxi_do_cleanup;
	vchan_init(&chan->vc, dma_dev);

	dma_set_mask_and_coherent(dev, DMA_BIT_MASK(64));

	ret = dma_async_device_register(dma_dev);
	if (ret)
		goto err_reg;

	return 0;

err_reg:
	kmem_cache_destroy(sdxi->dma_desc_cache);

err_cache:
	kmem_cache_destroy(sdxi->dma_cmd_cache);

	return ret;
}

void sdxi_dma_unregister(struct sdxi_cxt *dma_cxt)
{
	dma_async_device_unregister(&dma_cxt->sdxi->dma_dev);

	kmem_cache_destroy(dma_cxt->sdxi->dma_desc_cache);
	kmem_cache_destroy(dma_cxt->sdxi->dma_cmd_cache);
}
