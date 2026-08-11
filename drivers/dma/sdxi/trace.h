/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SDXI tracepoints.
 *
 * Copyright Advanced Micro Devices, Inc.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM sdxi

#if !defined(_TRACE_SDXI_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SDXI_H

#include <linux/tracepoint.h>

#include "context.h"

TRACE_EVENT(sdxi_create_cxt,
	    TP_PROTO(struct sdxi_dev *sdxi, struct sdxi_cxt *cxt),
	    TP_ARGS(sdxi, cxt),
	    TP_STRUCT__entry(
		    __field(u16, sfunc)
		    __field(unsigned int, cxt_id)
		    __field(void *, cce)
		    __field(u64, cce_dma_addr)
		    __field(void *, akey)
		    __field(u64, akey_dma_addr)
	    ),
	    TP_fast_assign(
		    __entry->sfunc = sdxi->sfunc;
		    __entry->cxt_id = cxt->id;
		    __entry->cce = cxt->cxt_ctl;
		    __entry->cce_dma_addr = cxt->cxt_ctl_dma;
		    __entry->akey = cxt->akey_table;
		    __entry->akey_dma_addr = cxt->akey_table_dma;
	    ),
	    TP_printk("cxt=%u sfunc=%#x cxt_ctl=%p cxt_ctl_dma=%#llx akey=%p akey_dma=%#llx",
		      __entry->cxt_id, __entry->sfunc, __entry->cce,
		      __entry->cce_dma_addr, __entry->akey,
		      __entry->akey_dma_addr)
);

TRACE_EVENT(sdxi_free_cxt,
	    TP_PROTO(struct sdxi_dev *sdxi, struct sdxi_cxt *cxt),
	    TP_ARGS(sdxi, cxt),
	    TP_STRUCT__entry(
		    __field(u16, sfunc)
		    __field(unsigned int, cxt_id)
	    ),
	    TP_fast_assign(
		    __entry->sfunc = sdxi->sfunc;
		    __entry->cxt_id = cxt->id;
	    ),
	    TP_printk("cxt=%u sfunc=%#x", __entry->cxt_id, __entry->sfunc)
);

TRACE_EVENT(sdxi_create_sq,
	    TP_PROTO(struct sdxi_cxt *cxt, struct sdxi_sq *sq),
	    TP_ARGS(cxt, sq),
	    TP_STRUCT__entry(
		    __field(u16, sfunc)
		    __field(unsigned int, cxt_id)
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
		    __entry->desc_ring = sq->ring;
		    __entry->desc_ring_addr = sdxi_sq_ring_dma(sq);
		    __entry->write_index = &sq->write_index;
		    __entry->write_index_addr = sdxi_sq_write_index_dma(sq);
		    __entry->cxt_status = &sq->cxt_sts;
		    __entry->cxt_status_addr = sdxi_sq_cxt_sts_dma(sq);
	    ),
	    TP_printk("cxt=%u sfunc=%#x ring=%p/%#llx widx=%p/%#llx sts=%p/%#llx",
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
		    __field(unsigned int, cxt_id)
	    ),
	    TP_fast_assign(
		    __entry->sfunc = cxt->sdxi->sfunc;
		    __entry->cxt_id = cxt->id;
	    ),
	    TP_printk("cxt=%u sfunc=%#x", __entry->cxt_id, __entry->sfunc)
);

TRACE_EVENT(sdxi_bind_process,
	    TP_PROTO(const struct sdxi_dev *sdxi, u32 pasid),
	    TP_ARGS(sdxi, pasid),
	    TP_STRUCT__entry(
		    __string(devname, dev_name(sdxi_to_dev(sdxi)))
		    __field(u32, pasid)
	    ),
	    TP_fast_assign(
		    __assign_str(devname);
		    __entry->pasid = pasid;
	    ),
	    TP_printk("device=%s pasid=%u", __get_str(devname), __entry->pasid)
);

TRACE_EVENT(sdxi_unbind_process,
	    TP_PROTO(const struct sdxi_dev *sdxi, u32 pasid),
	    TP_ARGS(sdxi, pasid),
	    TP_STRUCT__entry(
		    __string(devname, dev_name(sdxi_to_dev(sdxi)))
		    __field(u32, pasid)
	    ),
	    TP_fast_assign(
		    __assign_str(devname);
		    __entry->pasid = pasid;
	    ),
	    TP_printk("device=%s pasid=%u", __get_str(devname), __entry->pasid)
);

#endif /* _TRACE_SDXI_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../drivers/dma/sdxi

#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

#include <trace/define_trace.h>
