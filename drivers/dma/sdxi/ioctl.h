/*
 * IOCTL related header
 *
 * Copyright (C) 2022 AMD, Inc. All rights reserved.
 *
 * Author: Wei Huang <wei.huang2@amd.com>
 *
 */

#ifndef __SDXI_IOCTL_H
#define __SDXI_IOCTL_H

#include <linux/mmu_notifier.h>
#include <linux/mutex.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/workqueue.h>

#include "sdxi.h"
#include "process.h"

#define SDXI_IOCTL_MAJOR_VER 1
#define SDXI_IOCTL_MINOR_VER 0

typedef int sdxi_ioctl_t(struct file *filep, struct sdxi_process *p, void *data);

struct sdxi_ioctl_desc {
	unsigned int cmd;
	int flags;
	sdxi_ioctl_t *func;
	unsigned int cmd_drv;
	const char *name;
};

/* Use upper bits of mmap offset to access context specific information.
 * BITS[42:40] - Encode MMAP types
 *     01 : Descriptor ring
 *     02 : Write index
 *     03 : Context status
 *     04 : Doorbell
 */
#define SDXI_MMAP_TYPE_SHIFT         40
#define SDXI_MMAP_TYPE_DESC_RING     (0x1ULL << SDXI_MMAP_TYPE_SHIFT)
#define SDXI_MMAP_TYPE_WRITE_INDEX   (0x2ULL << SDXI_MMAP_TYPE_SHIFT)
#define SDXI_MMAP_TYPE_CXT_STATUS    (0x3ULL << SDXI_MMAP_TYPE_SHIFT)
#define SDXI_MMAP_TYPE_DOORBELL      (0x4ULL << SDXI_MMAP_TYPE_SHIFT)
#define SDXI_MMAP_TYPE_MASK          (0x7ULL << SDXI_MMAP_TYPE_SHIFT)

#endif /* __SDXI_IOCTL_H */
