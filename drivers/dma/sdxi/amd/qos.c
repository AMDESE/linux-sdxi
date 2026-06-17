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

static void sdxi_amd_qos_desc_init(struct sdxi_desc *desc, u16 opcode_type,
				   u8 subtype)
{
	memset(desc, 0, sizeof(*desc));
	desc->opcode = cpu_to_le32(FIELD_PREP(SDXI_DSC_SUBTYPE, subtype) |
				   FIELD_PREP(SDXI_DSC_TYPE, opcode_type));
	desc->csb_ptr = cpu_to_le64(FIELD_PREP(SDXI_DSC_NP, 1));
}

static int sdxi_amd_qos_target_scope(u16 pool_num, u16 flags, u16 vf_num,
				     u32 *target_scope)
{
	u32 value;

	if (pool_num > 0x0fff)
		return -EINVAL;
	if (flags & ~(SDXI_AMD_QOS_TARGET_F_CXT | SDXI_AMD_QOS_TARGET_F_VF))
		return -EINVAL;
	if (!(flags & SDXI_AMD_QOS_TARGET_F_VF) && vf_num)
		return -EINVAL;

	value = pool_num;
	if (flags & SDXI_AMD_QOS_TARGET_F_CXT)
		value |= BIT(12);
	if (flags & SDXI_AMD_QOS_TARGET_F_VF)
		value |= BIT(15);
	value |= (u32)vf_num << 16;

	*target_scope = value;
	return 0;
}

static u16 sdxi_amd_qos_max_vfs(struct sdxi_dev *sdxi)
{
	struct pci_dev *pdev;
	unsigned int totalvfs;

	if (!sdxi || sdxi_fn_reports_vf(sdxi))
		return 0;

	pdev = to_pci_dev(sdxi_to_dev(sdxi));
	totalvfs = pci_sriov_get_totalvfs(pdev);
	if (totalvfs > U16_MAX)
		return U16_MAX;

	return (u16)totalvfs;
}

static bool sdxi_amd_qos_pool_active(const u8 *bitmap, u16 pool_num)
{
	if (!bitmap)
		return false;

	return bitmap[pool_num / 8] & BIT(pool_num % 8);
}

static int sdxi_amd_qos_get_cap_info(struct sdxi_dev *sdxi,
				     struct sdxi_cxt *adm,
				     u16 opcode_type,
				     unsigned int timeout_ms,
				     struct sdxi_amd_qos_cap_info *cap)
{
	struct sdxi_desc desc = {};
	dma_addr_t dma;
	u8 *buf;
	int err;

	if (!cap)
		return -EINVAL;

	err = sdxi_amd_qos_admin_ready(adm);
	if (err)
		return err;

	buf = dma_alloc_coherent(sdxi_to_dev(sdxi), SDXI_AMD_QOS_CAP_BYTES, &dma,
				 GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memset(buf, 0, SDXI_AMD_QOS_CAP_BYTES);

	if (!IS_ALIGNED(dma, SZ_4K)) {
		err = -EIO;
		goto out_free;
	}

	sdxi_amd_qos_desc_init(&desc, opcode_type,
			       SDXI_AMD_QOS_DSC_SUBTYPE_CAP);

	/* capability_ptr is descriptor bits[127:64], starting at byte offset 8. */
	put_unaligned_le64(dma, &desc.generic.operation[4]);

	err = sdxi_adm_submit_desc(adm, &desc, timeout_ms, NULL);
	if (err)
		goto out_free;

	dma_rmb();
	cap->feature_flags = get_unaligned_le16(buf + 2);
	cap->device_maxbw_cap = get_unaligned_le32(buf + 4);
	cap->max_pools = (u16)(get_unaligned_le32(buf + 8) & 0x0fff);
	cap->granularity_bw = get_unaligned_le32(buf + 12);
	if (!cap->max_pools)
		err = -EIO;

out_free:
	dma_free_coherent(sdxi_to_dev(sdxi), SDXI_AMD_QOS_CAP_BYTES, buf, dma);
	return err;
}

static int sdxi_amd_qos_get_dev_info(struct sdxi_dev *sdxi,
				     struct sdxi_cxt *adm,
				     u16 opcode_type,
				     unsigned int timeout_ms,
				     struct sdxi_amd_qos_dev_info *info)
{
	struct sdxi_desc desc = {};
	dma_addr_t dma;
	u8 *buf;
	int err;

	if (!info)
		return -EINVAL;

	err = sdxi_amd_qos_admin_ready(adm);
	if (err)
		return err;

	buf = dma_alloc_coherent(sdxi_to_dev(sdxi), SDXI_AMD_QOS_TEL_FIXED_BYTES,
				 &dma, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memset(buf, 0, SDXI_AMD_QOS_TEL_FIXED_BYTES);

	if (!IS_ALIGNED(dma, SZ_4K)) {
		err = -EIO;
		goto out_free_dev;
	}

	sdxi_amd_qos_desc_init(&desc, opcode_type,
			       SDXI_AMD_QOS_DSC_SUBTYPE_TEL);
	put_unaligned_le64(sdxi_amd_qos_query_selector(0,
						       SDXI_AMD_QOS_TEL_QTYPE_DEVICE),
			   &desc.generic.operation[4]);
	put_unaligned_le64(dma, &desc.generic.operation[12]);

	err = sdxi_adm_submit_desc(adm, &desc, timeout_ms, NULL);
	if (err)
		goto out_free_dev;

	dma_rmb();
	info->device_maxbw = get_unaligned_le32(buf + 4);
	info->total_allocated_bw = get_unaligned_le32(buf + 12);

out_free_dev:
	dma_free_coherent(sdxi_to_dev(sdxi), SDXI_AMD_QOS_TEL_FIXED_BYTES,
			  buf, dma);
	return err;
}

static int sdxi_amd_qos_get_pool_info(struct sdxi_dev *sdxi,
				      struct sdxi_cxt *adm,
				      u16 opcode_type, u16 pool_num,
				      unsigned int timeout_ms,
				      struct sdxi_amd_qos_pool_info *info)
{
	struct sdxi_desc desc = {};
	dma_addr_t dma;
	u8 *buf;
	u32 target_scope;
	int err;

	if (!info)
		return -EINVAL;

	err = sdxi_amd_qos_admin_ready(adm);
	if (err)
		return err;

	buf = dma_alloc_coherent(sdxi_to_dev(sdxi), SDXI_AMD_QOS_TEL_FIXED_BYTES,
				 &dma, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memset(buf, 0, SDXI_AMD_QOS_TEL_FIXED_BYTES);

	if (!IS_ALIGNED(dma, SZ_4K)) {
		err = -EIO;
		goto out_free_pool;
	}

	sdxi_amd_qos_desc_init(&desc, opcode_type,
			       SDXI_AMD_QOS_DSC_SUBTYPE_TEL);
	target_scope = FIELD_PREP(GENMASK(11, 0), pool_num);
	put_unaligned_le32(target_scope, &desc.generic.operation[0]);
	put_unaligned_le64(sdxi_amd_qos_query_selector(0,
						       SDXI_AMD_QOS_TEL_QTYPE_POOL_CONFIG),
			   &desc.generic.operation[4]);
	put_unaligned_le64(dma, &desc.generic.operation[12]);

	err = sdxi_adm_submit_desc(adm, &desc, timeout_ms, NULL);
	if (err)
		goto out_free_pool;

	dma_rmb();
	info->pool_minbw = get_unaligned_le32(buf + 8);
	info->pool_maxbw = get_unaligned_le32(buf + 12);
	info->assigned_functions = get_unaligned_le16(buf + 16);
	info->assigned_contexts = get_unaligned_le16(buf + 18);

out_free_pool:
	dma_free_coherent(sdxi_to_dev(sdxi), SDXI_AMD_QOS_TEL_FIXED_BYTES,
			  buf, dma);
	return err;
}

static int sdxi_amd_qos_get_active_pools(struct sdxi_dev *sdxi,
					 struct sdxi_cxt *adm,
					 u16 opcode_type,
					 unsigned int timeout_ms,
					 u16 max_pools, u8 *bitmap)
{
	struct sdxi_desc desc = {};
	dma_addr_t dma;
	u8 *buf;
	size_t bytes;
	int err;

	if (!bitmap || !max_pools)
		return -EINVAL;

	err = sdxi_amd_qos_admin_ready(adm);
	if (err)
		return err;

	bytes = (size_t)(max_pools + 7U) / 8U;
	buf = dma_alloc_coherent(sdxi_to_dev(sdxi), SDXI_AMD_QOS_TEL_HDR_BYTES + bytes,
				 &dma, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memset(buf, 0, SDXI_AMD_QOS_TEL_HDR_BYTES + bytes);

	if (!IS_ALIGNED(dma, SZ_4K)) {
		err = -EIO;
		goto out_free_active;
	}

	sdxi_amd_qos_desc_init(&desc, opcode_type,
			       SDXI_AMD_QOS_DSC_SUBTYPE_TEL);
	put_unaligned_le64(sdxi_amd_qos_query_selector(0,
						       SDXI_AMD_QOS_TEL_QTYPE_ACTIVE_POOLS),
			   &desc.generic.operation[4]);
	put_unaligned_le64(dma, &desc.generic.operation[12]);

	err = sdxi_adm_submit_desc(adm, &desc, timeout_ms, NULL);
	if (err)
		goto out_free_active;

	dma_rmb();
	memcpy(bitmap, buf + SDXI_AMD_QOS_TEL_HDR_BYTES, bytes);

out_free_active:
	dma_free_coherent(sdxi_to_dev(sdxi), SDXI_AMD_QOS_TEL_HDR_BYTES + bytes,
			  buf, dma);
	return err;
}

static int sdxi_amd_qos_get_assigned_functions(struct sdxi_dev *sdxi,
					       struct sdxi_cxt *adm,
					       u16 opcode_type, u16 pool_num,
					       unsigned int timeout_ms,
					       u16 *assigned_functions)
{
	struct sdxi_desc desc = {};
	dma_addr_t dma;
	u8 *buf;
	u32 counts;
	u32 target_scope;
	int err;

	if (!assigned_functions)
		return -EINVAL;

	err = sdxi_amd_qos_admin_ready(adm);
	if (err)
		return err;

	buf = dma_alloc_coherent(sdxi_to_dev(sdxi), SDXI_AMD_QOS_TEL_FIXED_BYTES,
				 &dma, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memset(buf, 0, SDXI_AMD_QOS_TEL_FIXED_BYTES);

	if (!IS_ALIGNED(dma, SZ_4K)) {
		err = -EIO;
		goto out_free;
	}

	sdxi_amd_qos_desc_init(&desc, opcode_type,
			       SDXI_AMD_QOS_DSC_SUBTYPE_TEL);

	target_scope = FIELD_PREP(GENMASK(11, 0), pool_num);
	put_unaligned_le32(target_scope, &desc.generic.operation[0]);
	put_unaligned_le64(sdxi_amd_qos_query_selector(0,
						       SDXI_AMD_QOS_TEL_QTYPE_POOL_CONFIG),
			   &desc.generic.operation[4]);

	/* telemetry_ptr is descriptor bits[191:128], starting at byte offset 16. */
	put_unaligned_le64(dma, &desc.generic.operation[12]);

	err = sdxi_adm_submit_desc(adm, &desc, timeout_ms, NULL);
	if (err)
		goto out_free;

	dma_rmb();
	counts = get_unaligned_le32(buf + 16);
	*assigned_functions = (u16)(counts & 0xffff);

out_free:
	dma_free_coherent(sdxi_to_dev(sdxi), SDXI_AMD_QOS_TEL_FIXED_BYTES,
			  buf, dma);
	return err;
}
