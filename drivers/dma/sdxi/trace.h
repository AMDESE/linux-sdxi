/*
 * SDXI tracepoints header
 *
 * Copyright (c) 2022 AMD, Inc. All rights reserved.
 *
 * Author: Wei Huang <wei.huang2@amd.com>
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM sdxi
#define TRACE_INCLUDE_FILE trace

#if !defined(_TRACE_SDXI_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SDXI_H

#include <linux/tracepoint.h>
#include <linux/trace_seq.h>

#include "sdxi.h"

TRACE_EVENT(sdxi_create_cxt,
	    TP_PROTO(struct sdxi_dev *sdxi, struct sdxi_cxt *cxt),
	    TP_ARGS(sdxi, cxt),
	    TP_STRUCT__entry(
		    __field(u16, sfunc)
		    __field(uint, cxt_id)
		    __field(void *, cce)
		    __field(u64, cce_dma_addr)
		    __field(void *, akey)
		    __field(u64, akey_dma_addr)
		    ),
	    TP_fast_assign(
		    __entry->sfunc = sdxi->sfunc;
		    __entry->cxt_id = cxt->id;
		    __entry->cce = &(cxt->cce);
		    __entry->cce_dma_addr = cxt->cce_addr;
		    __entry->akey = cxt->akey;
		    __entry->akey_dma_addr = cxt->akey_addr;
		    ),
	    TP_printk("cxt %d created (dev=0x%04x)\n"
		      "  cce addr:  v=0x%p:d=0x%llx\n"
		      "  akey addr: v=0x%p:d=0x%llx\n",
		      __entry->cxt_id, __entry->sfunc, __entry->cce,
		      __entry->cce_dma_addr, __entry->akey, __entry->akey_dma_addr)
	);

TRACE_EVENT(sdxi_free_cxt,
	    TP_PROTO(struct sdxi_dev *sdxi, struct sdxi_cxt *cxt),
	    TP_ARGS(sdxi, cxt),
	    TP_STRUCT__entry(
		    __field(u16, sfunc)
		    __field(uint, cxt_id)
		    ),
	    TP_fast_assign(
		    __entry->sfunc = sdxi->sfunc;
		    __entry->cxt_id = cxt->id;
		    ),
	    TP_printk("cxt %d freed (dev=0x%04x)\n",
		      __entry->cxt_id, __entry->sfunc)
	);

TRACE_EVENT(sdxi_create_sq,
	    TP_PROTO(struct sdxi_cxt *cxt, struct sdxi_sq *sq),
	    TP_ARGS(cxt, sq),
	    TP_STRUCT__entry(
		    __field(u16, sfunc)
		    __field(uint, cxt_id)
		    __field(void *, desc_ring)
		    __field(u64, desc_ring_addr)
		    __field(void *, write_index)
		    __field(u64, write_index_addr)
		    __field(void *, cxt_status)
		    __field(u64, cxt_status_addr)
		    ),
	    TP_fast_assign(
		    __entry->sfunc = cxt->sdxi->sfunc;
		    __entry->cxt_id = cxt->id;
		    __entry->desc_ring = sq->desc_ring;
		    __entry->desc_ring_addr = sq->ring_dma;
		    __entry->write_index = sq->write_index;
		    __entry->write_index_addr = sq->write_index_dma;
		    __entry->cxt_status = sq->cxt_status;
		    __entry->cxt_status_addr = sq->cxt_status_dma;
		    ),
	    TP_printk("sq created (cxt=%d, dev=0x%04x)\n"
		      "  desc ring addr:   v=0x%p:d=0x%llx\n"
		      "  write index addr: v=0x%p:d=0x%llx\n"
		      "  cxt status addr: v=0x%p:d=0x%llx\n",
		      __entry->cxt_id, __entry->sfunc, __entry->desc_ring,
		      __entry->desc_ring_addr, __entry->write_index,
		      __entry->write_index_addr, __entry->cxt_status,
		      __entry->cxt_status_addr)
	);

TRACE_EVENT(sdxi_free_sq,
	    TP_PROTO(struct sdxi_cxt *cxt, struct sdxi_sq *sq),
	    TP_ARGS(cxt, sq),
	    TP_STRUCT__entry(
		    __field(u16, sfunc)
		    __field(uint, cxt_id)
		    ),
	    TP_fast_assign(
		    __entry->sfunc = cxt->sdxi->sfunc;
		    __entry->cxt_id = cxt->id;
		    ),
	    TP_printk("sq created (cxt=%d, dev=0x%04x)\n",
		      __entry->cxt_id, __entry->sfunc)
	);

TRACE_EVENT(sdxi_bind_process,
	    TP_PROTO(const struct sdxi_dev *sdxi, u32 pasid),
	    TP_ARGS(sdxi, pasid),
	    TP_STRUCT__entry(
		    __string(devname, dev_name(&sdxi->pdev->dev))
		    __field(u32, pasid)
		    ),
	    TP_fast_assign(
		    __assign_str(devname, dev_name(&sdxi->pdev->dev));
		    __entry->pasid = pasid;
		    ),
	    TP_printk("bind process (pasid=%d) to device=%s",
		      __entry->pasid, __get_str(devname)
		    )
	);

TRACE_EVENT(sdxi_unbind_process,
	    TP_PROTO(const struct sdxi_dev *sdxi, u32 pasid),
	    TP_ARGS(sdxi, pasid),
	    TP_STRUCT__entry(
		    __string(devname, dev_name(&sdxi->pdev->dev))
		    __field(u32, pasid)
		    ),
	    TP_fast_assign(
		    __assign_str(devname, dev_name(&sdxi->pdev->dev));
		    __entry->pasid = pasid;
		    ),
	    TP_printk("unbind process (pasid=%d) to device=%s",
		      __entry->pasid, __get_str(devname)
		    )
	);

#endif /* _TRACE_SDXI_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../../drivers/dma/sdxi/

#include <trace/define_trace.h>
