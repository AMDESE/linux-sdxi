// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI administrative command submission.
 *
 * Copyright Advanced Micro Devices, Inc.
 */

#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/types.h>

#include "admin.h"
#include "completion.h"
#include "descriptor.h"
#include "ring.h"

#define SDXI_ADMIN_DEFAULT_TIMEOUT_MS	5000U
#define SDXI_ADMIN_DRAIN_TIMEOUT_MS	1000U

static int sdxi_adm_submit(struct sdxi_cxt *adm,
			   const struct sdxi_desc *descs, size_t nr_descs,
			   unsigned int timeout_ms, u32 *cst_flags,
			   bool interruptible)
{
	struct sdxi_ring_resv resv;
	struct sdxi_completion comp;
	struct sdxi_slot slot;
	bool completed = false;
	int wait_ret;
	size_t i;
	int ret;

	if (!adm || !sdxi_cxt_is_admin(adm) || !adm->ring_state)
		return -ENODEV;
	if (!nr_descs)
		return -EINVAL;

	/* Keep reservations from becoming visible before they are populated. */
	mutex_lock(&adm->sdxi->admin_lock);
	if (adm->sdxi->admin_dead) {
		ret = -EIO;
		goto out_unlock;
	}
	ret = sdxi_cst_pool_get_wait(adm->cst_pool, &comp);
	if (ret)
		goto out_unlock;
	ret = sdxi_ring_reserve(adm->ring_state, nr_descs, &resv);
	if (ret) {
		sdxi_cst_pool_put(adm->cst_pool, comp.cst_blk);
		goto out_unlock;
	}

	for (i = 0; i < nr_descs; i++) {
		slot = sdxi_ring_resv_slot(&resv, i);
		*sdxi_slot_desc(slot) = descs[i];
		if (i + 1 == nr_descs)
			sdxi_cxt_submit(adm, slot, &comp, SDXI_CXT_SUBMIT_KICK);
		else
			sdxi_cxt_submit(adm, slot, NULL, 0);
	}

	ret = sdxi_cst_blk_wait_timeout(comp.cst_blk, timeout_ms, interruptible);
	if (ret == -ETIMEDOUT || ret == -ERESTARTSYS) {
		/*
		 * The descriptor can still access caller-owned DMA memory after
		 * a timed or interrupted wait. Drain it before returning so the
		 * caller can safely release any associated mappings.
		 */
		wait_ret = sdxi_cst_blk_wait_timeout(comp.cst_blk,
						 SDXI_ADMIN_DRAIN_TIMEOUT_MS,
						 false);
		if (wait_ret == 0 || wait_ret == -EIO) {
			completed = true;
			if (cst_flags)
				*cst_flags = sdxi_cst_blk_flags(comp.cst_blk);
		}
		if (wait_ret == -ETIMEDOUT) {
			adm->sdxi->admin_dead = true;
			dev_err(adm->sdxi->dev,
				"admin command did not drain; quiescing function\n");
			sdxi_dev_force_quiesce(adm->sdxi);
		}
	}
	if (!ret || ret == -EIO) {
		completed = true;
		if (cst_flags)
			*cst_flags = sdxi_cst_blk_flags(comp.cst_blk);
	}
	if (completed)
		sdxi_cst_pool_put(adm->cst_pool, comp.cst_blk);
	sdxi_ring_wake_up(adm->ring_state);

out_unlock:
	mutex_unlock(&adm->sdxi->admin_lock);
	return ret;
}

int sdxi_adm_update_cxt(struct sdxi_cxt *cxt)
{
	struct sdxi_desc descs[2] = {};
	int ret;

	if (!cxt || sdxi_cxt_is_admin(cxt))
		return -EINVAL;

	ret = sdxi_encode_cxt_upd(&descs[0], &(const struct sdxi_cxt_upd) {
			.level = SDXI_CXT_UPD_LVL_L1,
			.range = sdxi_cxt_range_single(cxt->id),
		});
	if (ret)
		return ret;

	ret = sdxi_encode_sync(&descs[1], &(const struct sdxi_sync) {
			.filter = SDXI_SYNC_FLT_CXT,
			.range = sdxi_cxt_range_single(cxt->id),
		});
	if (ret)
		return ret;

	return sdxi_adm_submit(to_admin_cxt(cxt), descs, ARRAY_SIZE(descs),
			       SDXI_ADMIN_DEFAULT_TIMEOUT_MS, NULL, false);
}

int sdxi_adm_start_cxt_sync(struct sdxi_cxt *cxt, unsigned int timeout_ms,
			    u32 *cst_flags, bool interruptible)
{
	struct sdxi_desc descs[2] = {};
	int ret;

	if (!cxt || sdxi_cxt_is_admin(cxt))
		return -EINVAL;

	ret = sdxi_encode_cxt_start(&descs[0], &(const struct sdxi_cxt_start) {
			.range = sdxi_cxt_range_single(cxt->id),
		});
	if (ret)
		return ret;

	ret = sdxi_encode_sync(&descs[1], &(const struct sdxi_sync) {
			.filter = SDXI_SYNC_FLT_CXT,
			.range = sdxi_cxt_range_single(cxt->id),
		});
	if (ret)
		return ret;

	/* A failed or interrupted wait can leave the context running. */
	WRITE_ONCE(cxt->quiesced, false);
	WRITE_ONCE(cxt->started, true);
	ret = sdxi_adm_submit(to_admin_cxt(cxt), descs, ARRAY_SIZE(descs),
			      timeout_ms, cst_flags, interruptible);

	return ret;
}

int sdxi_adm_stop_cxt_sync(struct sdxi_cxt *cxt, unsigned int timeout_ms,
			   u32 *cst_flags, bool interruptible)
{
	struct sdxi_desc descs[2] = {};
	int ret;

	if (!cxt || sdxi_cxt_is_admin(cxt))
		return -EINVAL;

	ret = sdxi_encode_cxt_stop(&descs[0], &(const struct sdxi_cxt_stop) {
			.range = sdxi_cxt_range_single(cxt->id),
		});
	if (ret)
		return ret;

	ret = sdxi_encode_sync(&descs[1], &(const struct sdxi_sync) {
			.filter = SDXI_SYNC_FLT_STOP,
			.range = sdxi_cxt_range_single(cxt->id),
		});
	if (ret)
		return ret;

	ret = sdxi_adm_submit(to_admin_cxt(cxt), descs, ARRAY_SIZE(descs),
			      timeout_ms, cst_flags, interruptible);
	if (!ret)
		WRITE_ONCE(cxt->started, false);

	return ret;
}

int sdxi_adm_rkey_update_sync(struct sdxi_dev *sdxi, u16 rkey_start,
			      u16 rkey_end, unsigned int timeout_ms,
			      u32 *cst_flags)
{
	struct sdxi_desc descs[2] = {};
	int ret;

	if (!sdxi)
		return -ENODEV;

	ret = sdxi_encode_rkey_upd(&descs[0], &(const struct sdxi_rkey_upd) {
			.rkey_start = rkey_start,
			.rkey_end = rkey_end,
		});
	if (ret)
		return ret;

	ret = sdxi_encode_sync(&descs[1], &(const struct sdxi_sync) {
			.filter = SDXI_SYNC_FLT_RKEY,
			.key_start = rkey_start,
			.key_end = rkey_end,
		});
	if (ret)
		return ret;

	return sdxi_adm_submit(sdxi->admin_cxt, descs, ARRAY_SIZE(descs),
			       timeout_ms, cst_flags, false);
}

int sdxi_adm_akey_update_sync(struct sdxi_dev *sdxi, u16 cxt_start,
			      u16 cxt_end, u16 akey_start, u16 akey_end,
			      unsigned int timeout_ms, u32 *cst_flags)
{
	struct sdxi_cxt_range range = {
		.cxt_start = cxt_start,
		.cxt_end = cxt_end,
	};
	struct sdxi_desc descs[2] = {};
	int ret;

	if (!sdxi)
		return -ENODEV;

	ret = sdxi_encode_akey_upd(&descs[0], &(const struct sdxi_akey_upd) {
			.range = range,
			.akey_start = akey_start,
			.akey_end = akey_end,
		});
	if (ret)
		return ret;

	ret = sdxi_encode_sync(&descs[1], &(const struct sdxi_sync) {
			.filter = SDXI_SYNC_FLT_AKEY,
			.range = range,
			.key_start = akey_start,
			.key_end = akey_end,
		});
	if (ret)
		return ret;

	return sdxi_adm_submit(sdxi->admin_cxt, descs, ARRAY_SIZE(descs),
			       timeout_ms, cst_flags, false);
}

int sdxi_adm_disc(struct sdxi_dev *sdxi, u16 index_start, u16 index_end,
		  dma_addr_t addr, unsigned int timeout_ms, u32 *cst_flags)
{
	struct sdxi_desc desc = {};
	int ret;

	if (!sdxi)
		return -ENODEV;

	ret = sdxi_encode_disc(&desc, &(const struct sdxi_disc) {
			.index_start = index_start,
			.index_end = index_end,
			.addr = addr,
		});
	if (ret)
		return ret;

	return sdxi_adm_submit(sdxi->admin_cxt, &desc, 1, timeout_ms,
			       cst_flags, false);
}

int sdxi_adm_submit_desc(struct sdxi_cxt *adm, const struct sdxi_desc *desc,
			 unsigned int timeout_ms, u32 *cst_flags)
{
	if (!desc)
		return -EINVAL;

	return sdxi_adm_submit(adm, desc, 1, timeout_ms, cst_flags, false);
}
EXPORT_SYMBOL_NS_GPL(sdxi_adm_submit_desc, "SDXI");

int sdxi_adm_start_cxt(struct sdxi_cxt *cxt)
{
	return sdxi_adm_start_cxt_sync(cxt, SDXI_ADMIN_DEFAULT_TIMEOUT_MS,
				       NULL, false);
}

int sdxi_adm_stop_cxt(struct sdxi_cxt *cxt)
{
	return sdxi_adm_stop_cxt_sync(cxt, SDXI_ADMIN_DEFAULT_TIMEOUT_MS,
				      NULL, false);
}
