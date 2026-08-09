/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SDXI key table management.
 *
 * Copyright Advanced Micro Devices, Inc.
 */

#ifndef DMA_SDXI_KEYS_H
#define DMA_SDXI_KEYS_H

#include <linux/types.h>

struct sdxi_dev;

int sdxi_keys_init(struct sdxi_dev *sdxi, u64 cap1);
void sdxi_keys_exit(struct sdxi_dev *sdxi);

#endif /* DMA_SDXI_KEYS_H */
