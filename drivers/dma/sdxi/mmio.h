/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * SDXI MMIO register offsets and layouts.
 *
 * Copyright Advanced Micro Devices, Inc.
 */

#ifndef DMA_SDXI_MMIO_H
#define DMA_SDXI_MMIO_H

#include <linux/bits.h>

enum sdxi_reg {
	/* SDXI 1.0 9.1 General Control and Status Registers */
	SDXI_MMIO_CAP1       = 0x00208,
};

/* SDXI 1.0 Table 9-7: MMIO_CAP1 */
#define SDXI_MMIO_CAP1_MMIO64 BIT_ULL(6)

#endif  /* DMA_SDXI_MMIO_H */
