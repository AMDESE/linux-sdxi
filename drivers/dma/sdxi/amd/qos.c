// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD SDXI QoS vendor-command handling.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#include <linux/capability.h>
#include <linux/dma-mapping.h>
#include <linux/export.h>
#include <kunit/visibility.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/unaligned.h>
#include <linux/uaccess.h>
#include <uapi/linux/sdxi.h>

#include "../admin.h"
#include "../sdxi.h"
#include "../vendor.h"
#include "qos.h"

#define SDXI_AMD_QOS_CAP_BYTES			48U
#define SDXI_AMD_QOS_TEL_FIXED_BYTES		48U
#define SDXI_AMD_QOS_TEL_HDR_BYTES		48U
#define SDXI_AMD_QOS_POOL_REPORT_ENTRY_BYTES	132U
#define SDXI_AMD_QOS_MAX_TEL_BYTES		SZ_1M

struct sdxi_amd_qos_cap_info {
	u16 feature_flags;
	u16 max_pools;
	u32 device_maxbw_cap;
	u32 granularity_bw;
};

struct sdxi_amd_qos_dev_info {
	u32 device_maxbw;
	u32 total_allocated_bw;
};

struct sdxi_amd_qos_pool_info {
	u32 pool_minbw;
	u32 pool_maxbw;
	u16 assigned_functions;
	u16 assigned_contexts;
};

/*
 * SDXI DSC_DISC uses RFC4122-like GUIDs, but with time_low/time_mid/time_hi
 * stored in little-endian order.
 */
static const u8 sdxi_amd_guid_qos[16] = {
	0x0b, 0x61, 0xb7, 0xf5, 0xc6, 0x0d, 0x03, 0x4c,
	0xab, 0x79, 0x65, 0xf1, 0xf4, 0xef, 0xcf, 0x4c,
};

static int
sdxi_amd_qos_copy_input(const struct sdxi_admin_vendor_args *args,
			void *dst, size_t size)
{
	void __user *ubuf;

	if (!size) {
		if (args->in_size || args->in_uptr)
			return -EINVAL;
		return 0;
	}

	if (args->in_size != size || !args->in_uptr)
		return -EINVAL;

	ubuf = u64_to_user_ptr(args->in_uptr);
	if (!access_ok(ubuf, size))
		return -EFAULT;
	if (copy_from_user(dst, ubuf, size))
		return -EFAULT;
	if (args->op == SDXI_AMD_QOS_ADMIN_OP_FNUPD &&
	    size == sizeof(struct sdxi_amd_qos_fnupd_req)) {
		struct sdxi_amd_qos_fnupd_req *req = dst;

		if (!(req->flags & SDXI_AMD_QOS_TARGET_F_VF))
			req->vf_num = 0;
		if (!(req->flags & SDXI_AMD_QOS_TARGET_F_CXT)) {
			req->cxt_start = 0;
			req->cxt_end = 0;
		}
	}

	return 0;
}

static int
sdxi_amd_qos_require_no_output(struct sdxi_admin_vendor_args *args)
{
	if (args->out_size || args->out_uptr)
		return -EINVAL;

	args->out_size = 0;

	return 0;
}

static int
sdxi_amd_qos_prepare_output(struct sdxi_admin_vendor_args *args,
			    size_t required, void __user **ubuf)
{
	u32 available = args->out_size;

	if (required > U32_MAX)
		return -EOVERFLOW;

	args->out_size = (u32)required;
	if (available < required)
		return -ENOSPC;
	if (!args->out_uptr)
		return -EINVAL;

	*ubuf = u64_to_user_ptr(args->out_uptr);
	if (!access_ok(*ubuf, required))
		return -EFAULT;

	return 0;
}

static int sdxi_amd_qos_admin_ready(const struct sdxi_cxt *adm)
{
	if (!adm || !adm->sq || !adm->ring_state || !adm->sq->cxt_sts)
		return -ENODEV;
	if (sdxi_cxt_sts_state(adm->sq->cxt_sts) != CXTV_RUN)
		return -EIO;

	return 0;
}

u64 sdxi_amd_qos_query_selector(u16 cxt_num, u8 query_type)
{
	return FIELD_PREP(GENMASK_ULL(15, 0), cxt_num) |
	       FIELD_PREP(GENMASK_ULL(18, 16), query_type);
}
EXPORT_SYMBOL_IF_KUNIT(sdxi_amd_qos_query_selector);

u32 sdxi_amd_qos_align_bw(u32 bw, u32 granularity)
{
	if (!granularity)
		return bw;

	return (bw / granularity) * granularity;
}
EXPORT_SYMBOL_IF_KUNIT(sdxi_amd_qos_align_bw);

int sdxi_amd_qos_validate_devupd_req(u32 device_maxbw, u32 device_maxbw_cap,
				     u32 total_allocated_bw, u32 granularity_bw)
{
	if (device_maxbw > device_maxbw_cap)
		return -EINVAL;

	if (sdxi_amd_qos_align_bw(device_maxbw, granularity_bw) <
	    total_allocated_bw)
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(sdxi_amd_qos_validate_devupd_req);

int sdxi_amd_qos_validate_poolupd_req(const struct sdxi_amd_qos_poolupd_req *req,
				      u16 max_pools, u32 granularity_bw)
{
	u32 min_bw;
	u32 max_bw;

	if (!req || !max_pools)
		return -EINVAL;
	if (req->rsvd0)
		return -EINVAL;
	if (req->pool_num >= max_pools)
		return -EINVAL;
	if (req->pool_operation > SDXI_AMD_QOS_POOL_OP_DESTROY)
		return -EINVAL;
	if ((req->pool_operation == SDXI_AMD_QOS_POOL_OP_CREATE ||
	     req->pool_operation == SDXI_AMD_QOS_POOL_OP_DESTROY) &&
	    !req->pool_num)
		return -EINVAL;
	if (req->pool_operation == SDXI_AMD_QOS_POOL_OP_DESTROY)
		return 0;
	if (req->pool_minbw > req->pool_maxbw)
		return -EINVAL;

	min_bw = sdxi_amd_qos_align_bw(req->pool_minbw, granularity_bw);
	max_bw = sdxi_amd_qos_align_bw(req->pool_maxbw, granularity_bw);
	if (min_bw > max_bw)
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(sdxi_amd_qos_validate_poolupd_req);

int sdxi_amd_qos_validate_fnupd_req(const struct sdxi_amd_qos_fnupd_req *req,
				    u16 max_pools, u16 max_vfs, u32 max_cxts,
				    u16 feature_flags)
{
	if (!req || !max_pools)
		return -EINVAL;
	if (req->rsvd0)
		return -EINVAL;
	if (req->pool_num >= max_pools)
		return -EINVAL;
	if (req->flags & ~(SDXI_AMD_QOS_TARGET_F_CXT |
			   SDXI_AMD_QOS_TARGET_F_VF))
		return -EINVAL;
	if (req->flags & SDXI_AMD_QOS_TARGET_F_VF) {
		if (!max_vfs || req->vf_num >= max_vfs)
			return -EINVAL;
	}

	if (!(req->flags & SDXI_AMD_QOS_TARGET_F_CXT))
		return 0;

	(void)feature_flags;
	if (req->cxt_start > req->cxt_end)
		return -EINVAL;
	if (req->cxt_start >= max_cxts || req->cxt_end >= max_cxts)
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(sdxi_amd_qos_validate_fnupd_req);

int sdxi_amd_qos_validate_tel_req(const struct sdxi_amd_qos_tel_req *req,
				  u16 max_pools, u16 max_vfs, u32 max_cxts,
				  u16 feature_flags)
{
	if (!req)
		return -EINVAL;
	if (req->rsvd0[0] || req->rsvd0[1] || req->rsvd0[2])
		return -EINVAL;

	switch (req->query_type) {
	case SDXI_AMD_QOS_TEL_QTYPE_DEVICE:
	case SDXI_AMD_QOS_TEL_QTYPE_ACTIVE_POOLS:
		return 0;
	case SDXI_AMD_QOS_TEL_QTYPE_POOL_CONFIG:
	case SDXI_AMD_QOS_TEL_QTYPE_POOL_REPORT:
	case SDXI_AMD_QOS_TEL_QTYPE_POOL_VARIANCE:
		if (!max_pools || req->pool_num >= max_pools)
			return -EINVAL;
		return 0;
	case SDXI_AMD_QOS_TEL_QTYPE_POOL_ASSIGN:
		if (req->flags & SDXI_AMD_QOS_TARGET_F_VF) {
			if (!max_vfs || req->vf_num >= max_vfs)
				return -EINVAL;
		}
		if (!(req->flags & SDXI_AMD_QOS_TARGET_F_CXT))
			return 0;
		if (!(feature_flags & SDXI_AMD_QOS_FEATURE_FLEXIBLE_POOL_SCOPE))
			return -EOPNOTSUPP;
		if (req->cxt_num >= max_cxts)
			return -EINVAL;
		return 0;
	default:
		return -EINVAL;
	}
}
EXPORT_SYMBOL_IF_KUNIT(sdxi_amd_qos_validate_tel_req);
