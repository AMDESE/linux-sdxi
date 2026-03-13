/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DMA_SDXI_ADMIN_H
#define DMA_SDXI_ADMIN_H

#include "context.h"
#include "sdxi.h"

int sdxi_start_cxt(struct sdxi_cxt *cxt);
void sdxi_stop_cxt(struct sdxi_cxt *cxt);

static inline struct sdxi_cxt *to_admin_cxt(const struct sdxi_cxt *cxt)
{
	return cxt->sdxi->admin_cxt;
}


static inline bool sdxi_cxt_is_admin(const struct sdxi_cxt *cxt)
{
	return cxt == to_admin_cxt(cxt);
}

#endif /* DMA_SDXI_ADMIN_H */
