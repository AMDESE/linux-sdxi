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
struct file;
struct sdxi_file;

int sdxi_keys_init(struct sdxi_dev *sdxi, u64 cap1);
void sdxi_keys_exit(struct sdxi_dev *sdxi);
int sdxi_ioctl_get_rkey_list(struct file *file, struct sdxi_file *sf,
			     void *data);
int sdxi_ioctl_get_rkeys(struct file *file, struct sdxi_file *sf, void *data);
int sdxi_ioctl_set_rkeys(struct file *file, struct sdxi_file *sf, void *data);
int sdxi_ioctl_get_akey_list(struct file *file, struct sdxi_file *sf,
			     void *data);
int sdxi_ioctl_get_akeys(struct file *file, struct sdxi_file *sf, void *data);
int sdxi_ioctl_set_akeys(struct file *file, struct sdxi_file *sf, void *data);

#endif /* DMA_SDXI_KEYS_H */
