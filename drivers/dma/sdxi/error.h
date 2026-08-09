/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SDXI error log handling.
 *
 * Copyright Advanced Micro Devices, Inc.
 */

#ifndef DMA_SDXI_ERROR_H
#define DMA_SDXI_ERROR_H

struct sdxi_dev;

int sdxi_error_init(struct sdxi_dev *sdxi);
void sdxi_error_exit(struct sdxi_dev *sdxi);

#endif /* DMA_SDXI_ERROR_H */
