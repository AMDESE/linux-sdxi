// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI error log handling.
 *
 * Copyright Advanced Micro Devices, Inc.
 */

#include <linux/bitfield.h>
#include <linux/device/devres.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/log2.h>
#include <linux/packing.h>
#include <linux/sizes.h>
#include <linux/string.h>

#include "context.h"
#include "error.h"
#include "hw.h"
#include "mmio.h"
#include "sdxi.h"

#define SDXI_ERRLOG_TYPE	0x7f7
#define SDXI_ERRLOG_ENTRIES	64
#define SDXI_ERRLOG_SIZE	(SDXI_ERRLOG_ENTRIES * \
				 sizeof(struct sdxi_errlog_hd_ent))

struct sdxi_errlog_entry {
	u64 dsc_index;
	u16 cxt_num;
	u16 err_class;
	u16 type;
	u8 step;
	u8 buf;
	u8 sub_step;
	u8 reaction;
	bool vl;
	bool cv;
	bool div;
	bool bv;
};

#define ERRLOG_FIELD(_high, _low, _member) \
	PACKED_FIELD(_high, _low, struct sdxi_errlog_entry, _member)

static const struct packed_field_u16 sdxi_errlog_fields[] = {
	ERRLOG_FIELD(0, 0, vl),
	ERRLOG_FIELD(13, 8, step),
	ERRLOG_FIELD(26, 16, type),
	ERRLOG_FIELD(32, 32, cv),
	ERRLOG_FIELD(33, 33, div),
	ERRLOG_FIELD(34, 34, bv),
	ERRLOG_FIELD(38, 36, buf),
	ERRLOG_FIELD(43, 40, sub_step),
	ERRLOG_FIELD(46, 44, reaction),
	ERRLOG_FIELD(63, 48, cxt_num),
	ERRLOG_FIELD(127, 64, dsc_index),
	ERRLOG_FIELD(367, 352, err_class),
};

enum {
	SDXI_PACKING_QUIRKS = QUIRK_LITTLE_ENDIAN | QUIRK_LSW32_IS_FIRST,
};

enum sdxi_errlog_reaction {
	SDXI_ERRLOG_REACTION_CXT_STOP = 1,
	SDXI_ERRLOG_REACTION_FN_STOP = 2,
};

static const char *const sdxi_err_steps[] = {
	[1] = "internal",
	[2] = "context L2",
	[3] = "context L1",
	[4] = "context control",
	[5] = "context status",
	[6] = "write index",
	[7] = "descriptor",
	[8] = "completion status",
	[9] = "atomic return data",
	[10] = "descriptor buffer",
	[11] = "AKey lookup",
	[12] = "RKey lookup",
};

static const char *sdxi_err_step_name(u8 step)
{
	if (step < ARRAY_SIZE(sdxi_err_steps) && sdxi_err_steps[step])
		return sdxi_err_steps[step];

	return "reserved";
}

static bool sdxi_errlog_decode(struct sdxi_dev *sdxi,
			       const struct sdxi_errlog_hd_ent *raw,
			       struct sdxi_errlog_entry *entry)
{
	unpack_fields(raw, sizeof(*raw), entry, sdxi_errlog_fields,
		      SDXI_PACKING_QUIRKS);

	if (!entry->vl) {
		dev_err_ratelimited(sdxi->dev,
				    "ignoring error log entry with vl=0\n");
		return false;
	}
	if (entry->type != SDXI_ERRLOG_TYPE) {
		dev_err_ratelimited(sdxi->dev,
				    "ignoring error log type %#x\n",
				    entry->type);
		return false;
	}

	return true;
}

static void sdxi_errlog_report(struct sdxi_dev *sdxi, u64 read_index,
			       const struct sdxi_errlog_entry *entry)
{
	dev_err(sdxi->dev,
		"error log[%zu]: class=%#x step=%u (%s) substep=%u reaction=%u\n",
		(size_t)(read_index % SDXI_ERRLOG_ENTRIES), entry->err_class,
		entry->step, sdxi_err_step_name(entry->step), entry->sub_step,
		entry->reaction);

	if (entry->cv)
		dev_err(sdxi->dev, "  context=%u\n", entry->cxt_num);
	if (entry->div)
		dev_err(sdxi->dev, "  descriptor index=%#llx\n",
			entry->dsc_index);
	if (entry->bv)
		dev_err(sdxi->dev, "  buffer=%u\n", entry->buf);
}

static bool sdxi_errlog_handle_reaction(struct sdxi_dev *sdxi,
					const struct sdxi_errlog_entry *entry)
{
	struct sdxi_cxt *cxt;

	if (entry->reaction == SDXI_ERRLOG_REACTION_FN_STOP)
		return true;
	if (entry->reaction != SDXI_ERRLOG_REACTION_CXT_STOP ||
	    !entry->cv || !entry->cxt_num)
		return false;

	cxt = sdxi_cxt_get_by_id(sdxi, entry->cxt_num);
	if (!cxt)
		return false;

	if (sdxi_cxt_is_user(cxt))
		sdxi_cxt_kill_stopped(cxt);
	sdxi_cxt_put(cxt);
	return false;
}

static void sdxi_error_handle_function(struct sdxi_dev *sdxi)
{
	struct sdxi_cxt *cxt;
	u32 cxt_id;

	dev_err(sdxi->dev, "function stopped after hardware error\n");
	sdxi_dev_fail(sdxi);

	for (cxt_id = 1; cxt_id <= sdxi->max_cxtid; cxt_id++) {
		cxt = sdxi_cxt_get_by_id(sdxi, cxt_id);
		if (!cxt)
			continue;
		sdxi_cxt_kill_stopped(cxt);
		sdxi_cxt_put(cxt);
	}
}

static irqreturn_t sdxi_error_irq_thread(int irq, void *data)
{
	struct sdxi_dev *sdxi = data;
	u64 ack_mask = SDXI_MMIO_ERR_STS_STS_BIT |
		       SDXI_MMIO_ERR_STS_OVF_BIT |
		       SDXI_MMIO_ERR_STS_ERR_BIT;
	u64 write_index;
	u64 read_index;
	u64 status;
	u64 count;
	bool function_stopped;

	status = sdxi_read64(sdxi, SDXI_MMIO_ERR_STS);
	function_stopped = sdxi_dev_in_error(sdxi);
	if (!(status & ack_mask)) {
		if (!function_stopped)
			return IRQ_NONE;
		sdxi_error_handle_function(sdxi);
		return IRQ_HANDLED;
	}

	if (status & SDXI_MMIO_ERR_STS_ERR_BIT)
		dev_err(sdxi->dev, "hardware could not write the error log\n");
	if (status & SDXI_MMIO_ERR_STS_OVF_BIT)
		dev_err(sdxi->dev, "error log overflowed\n");
	if (!(status & SDXI_MMIO_ERR_STS_STS_BIT)) {
		sdxi_write64(sdxi, SDXI_MMIO_ERR_STS, status & ack_mask);
		if (function_stopped)
			sdxi_error_handle_function(sdxi);
		return IRQ_HANDLED;
	}

	read_index = sdxi_read64(sdxi, SDXI_MMIO_ERR_RD);
	sdxi_write64(sdxi, SDXI_MMIO_ERR_STS, status & ack_mask);
	write_index = sdxi_read64(sdxi, SDXI_MMIO_ERR_WRT);
	dma_rmb();

	if (write_index < read_index) {
		dev_err(sdxi->dev,
			"error log index mismatch: read=%#llx write=%#llx\n",
			read_index, write_index);
		read_index = write_index;
	}

	count = write_index - read_index;
	if (count > SDXI_ERRLOG_ENTRIES)
		read_index = write_index - SDXI_ERRLOG_ENTRIES;

	while (read_index < write_index) {
		struct sdxi_errlog_entry entry = {};
		struct sdxi_errlog_hd_ent raw;
		size_t index = read_index % SDXI_ERRLOG_ENTRIES;

		memcpy(&raw, &sdxi->err_log[index], sizeof(raw));
		if (sdxi_errlog_decode(sdxi, &raw, &entry)) {
			sdxi_errlog_report(sdxi, read_index, &entry);
			function_stopped |=
				sdxi_errlog_handle_reaction(sdxi, &entry);
		}
		read_index++;
	}

	sdxi_write64(sdxi, SDXI_MMIO_ERR_RD, read_index);
	if (function_stopped)
		sdxi_error_handle_function(sdxi);
	return IRQ_HANDLED;
}

int sdxi_error_init(struct sdxi_dev *sdxi)
{
	unsigned int size_order;
	u64 reg;
	int ret;

	sdxi_write64(sdxi, SDXI_MMIO_ERR_CFG, 0);
	sdxi_write64(sdxi, SDXI_MMIO_ERR_STS,
		     SDXI_MMIO_ERR_STS_STS_BIT |
		     SDXI_MMIO_ERR_STS_OVF_BIT |
		     SDXI_MMIO_ERR_STS_ERR_BIT);

	sdxi->err_log = dmam_alloc_coherent(sdxi->dev, SDXI_ERRLOG_SIZE,
					    &sdxi->err_log_dma, GFP_KERNEL);
	if (!sdxi->err_log)
		return -ENOMEM;
	memset(sdxi->err_log, 0, SDXI_ERRLOG_SIZE);

	sdxi->error_irq = sdxi->bus_ops->get_irq(sdxi, SDXI_ERROR_VECTOR);
	if (sdxi->error_irq < 0)
		return sdxi->error_irq;

	ret = devm_request_threaded_irq(sdxi->dev, sdxi->error_irq, NULL,
					sdxi_error_irq_thread,
					IRQF_TRIGGER_NONE, "sdxi-error", sdxi);
	if (ret)
		return ret;

	sdxi_write64(sdxi, SDXI_MMIO_ERR_WRT, 0);
	sdxi_write64(sdxi, SDXI_MMIO_ERR_RD, 0);

	reg = sdxi_read64(sdxi, SDXI_MMIO_ERR_CTL);
	FIELD_MODIFY(SDXI_MMIO_ERR_CTL_EN, &reg, 1);
	sdxi_write64(sdxi, SDXI_MMIO_ERR_CTL, reg);

	reg = sdxi_read64(sdxi, SDXI_MMIO_CTL0);
	FIELD_MODIFY(SDXI_MMIO_CTL0_FN_ERR_INTR_EN, &reg, 1);
	sdxi_write64(sdxi, SDXI_MMIO_CTL0, reg);

	size_order = ilog2(SDXI_ERRLOG_SIZE) - ilog2(SZ_4K);
	reg = FIELD_PREP(SDXI_MMIO_ERR_CFG_PTR,
			 sdxi->err_log_dma >> ilog2(SZ_4K)) |
	      FIELD_PREP(SDXI_MMIO_ERR_CFG_SZ, size_order) |
	      SDXI_MMIO_ERR_CFG_EN;
	sdxi_write64(sdxi, SDXI_MMIO_ERR_CFG, reg);

	return 0;
}

void sdxi_error_exit(struct sdxi_dev *sdxi)
{
	u64 reg;

	if (!sdxi->err_log)
		return;

	sdxi_write64(sdxi, SDXI_MMIO_ERR_CFG, 0);

	reg = sdxi_read64(sdxi, SDXI_MMIO_ERR_CTL);
	FIELD_MODIFY(SDXI_MMIO_ERR_CTL_EN, &reg, 0);
	sdxi_write64(sdxi, SDXI_MMIO_ERR_CTL, reg);

	reg = sdxi_read64(sdxi, SDXI_MMIO_CTL0);
	FIELD_MODIFY(SDXI_MMIO_CTL0_FN_ERR_INTR_EN, &reg, 0);
	sdxi_write64(sdxi, SDXI_MMIO_CTL0, reg);

	if (sdxi->error_irq >= 0)
		devm_free_irq(sdxi->dev, sdxi->error_irq, sdxi);

	sdxi->error_irq = -1;
	sdxi->err_log = NULL;
	sdxi->err_log_dma = 0;
}
