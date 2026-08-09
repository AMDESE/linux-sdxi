// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI key table management.
 *
 * Copyright Advanced Micro Devices, Inc.
 */

#include <linux/bitfield.h>
#include <linux/device/devres.h>
#include <linux/dma-mapping.h>
#include <linux/log2.h>
#include <linux/sizes.h>
#include <linux/string.h>

#include "hw.h"
#include "keys.h"
#include "mmio.h"
#include "sdxi.h"

static void sdxi_keys_release(void *data)
{
	sdxi_keys_exit(data);
}

int sdxi_keys_init(struct sdxi_dev *sdxi, u64 cap1)
{
	size_t table_size;
	u64 reg;
	int ret;

	sdxi->rkey_cap = FIELD_GET(SDXI_MMIO_CAP1_RKEY_CAP, cap1);
	if (!sdxi->rkey_cap)
		return 0;

	sdxi->rkey_order = 0;
	table_size = SZ_4K << sdxi->rkey_order;
	sdxi->rkey_entries = table_size / sizeof(*sdxi->rkey_table);

	sdxi->rkey_table = dmam_alloc_coherent(sdxi->dev, table_size,
					       &sdxi->rkey_table_dma,
					       GFP_KERNEL);
	if (!sdxi->rkey_table)
		return -ENOMEM;
	memset(sdxi->rkey_table, 0, table_size);

	reg = FIELD_PREP(SDXI_MMIO_RKEY_PTR,
			 sdxi->rkey_table_dma >> ilog2(SZ_4K)) |
	      FIELD_PREP(SDXI_MMIO_RKEY_SZ, sdxi->rkey_order) |
	      SDXI_MMIO_RKEY_EN;
	sdxi_write64(sdxi, SDXI_MMIO_RKEY, reg);

	ret = devm_add_action_or_reset(sdxi->dev, sdxi_keys_release, sdxi);
	if (ret)
		return ret;

	return 0;
}

void sdxi_keys_exit(struct sdxi_dev *sdxi)
{
	if (!sdxi->rkey_cap)
		return;

	sdxi_write64(sdxi, SDXI_MMIO_RKEY, 0);
	sdxi->rkey_table = NULL;
	sdxi->rkey_table_dma = 0;
	sdxi->rkey_entries = 0;
	sdxi->rkey_order = 0;
	sdxi->rkey_cap = false;
}
