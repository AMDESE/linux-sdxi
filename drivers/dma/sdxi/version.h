/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SDXI version constants and comparison helpers.
 *
 * Copyright Advanced Micro Devices, Inc.
 */

#ifndef DMA_SDXI_VERSION_H
#define DMA_SDXI_VERSION_H

#include <linux/types.h>

struct sdxi_version {
	u8 major;
	u8 minor;
};

#define SDXI_VERSION_1_0 ((struct sdxi_version){ .major = 1, .minor = 0 })
#define SDXI_VERSION_1_1 ((struct sdxi_version){ .major = 1, .minor = 1 })

static inline u16 sdxi_version_as_u16(struct sdxi_version version)
{
	return (version.major << 8) | version.minor;
}

static inline bool sdxi_version_ge(struct sdxi_version version,
				   struct sdxi_version minimum)
{
	return sdxi_version_as_u16(version) >= sdxi_version_as_u16(minimum);
}

#endif /* DMA_SDXI_VERSION_H */
