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

/* One PF entry plus all 10-bit VF-number entries. */
#define SDXI_AMD_QOS_POOL_REPORT_MAX_FUNCTIONS	1025U
#define SDXI_AMD_QOS_POOL_REPORT_MAX_BYTES				\
	(SDXI_AMD_QOS_TEL_HDR_BYTES +					\
	 SDXI_AMD_QOS_POOL_REPORT_MAX_FUNCTIONS *			\
	 SDXI_AMD_QOS_POOL_REPORT_ENTRY_BYTES)

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

static int sdxi_amd_qos_prevalidate_poolupd(struct sdxi_dev *sdxi,
					    struct sdxi_cxt *adm,
					    u16 opcode_type,
					    unsigned int timeout_ms,
					    const struct sdxi_amd_qos_cap_info *cap,
					    const struct sdxi_amd_qos_poolupd_req *req)
{
	struct sdxi_amd_qos_dev_info dev_info;
	struct sdxi_amd_qos_pool_info pool_info;
	u32 new_minbw;
	u32 total_minbw;
	size_t bytes;
	u8 *bitmap;
	bool pool_known;
	int err;

	err = sdxi_amd_qos_validate_poolupd_req(req, cap->max_pools,
						cap->granularity_bw);
	if (err)
		return err;

	err = sdxi_amd_qos_get_dev_info(sdxi, adm, opcode_type, timeout_ms,
					&dev_info);
	if (err)
		return err;

	bytes = (size_t)(cap->max_pools + 7U) / 8U;
	bitmap = kcalloc(bytes, sizeof(*bitmap), GFP_KERNEL);
	if (!bitmap)
		return -ENOMEM;

	err = sdxi_amd_qos_get_active_pools(sdxi, adm, opcode_type,
					    timeout_ms, cap->max_pools,
					    bitmap);
	if (err) {
		kfree(bitmap);
		return err;
	}

	pool_known = !req->pool_num ||
		     sdxi_amd_qos_pool_active(bitmap, req->pool_num);

	switch (req->pool_operation) {
	case SDXI_AMD_QOS_POOL_OP_CREATE:
		if (sdxi_amd_qos_pool_active(bitmap, req->pool_num))
			err = -EEXIST;
		kfree(bitmap);
		if (err)
			return err;

		new_minbw = sdxi_amd_qos_align_bw(req->pool_minbw,
						  cap->granularity_bw);
		if (dev_info.total_allocated_bw > dev_info.device_maxbw)
			return -EIO;
		if (new_minbw > dev_info.device_maxbw - dev_info.total_allocated_bw)
			return -EINVAL;
		return 0;
	case SDXI_AMD_QOS_POOL_OP_UPDATE:
		kfree(bitmap);
		if (!pool_known)
			return -ENOENT;
		err = sdxi_amd_qos_get_pool_info(sdxi, adm, opcode_type,
						 req->pool_num, timeout_ms,
						 &pool_info);
		if (err)
			return err;

		if (pool_info.pool_minbw > dev_info.total_allocated_bw)
			return -EIO;
		if (dev_info.total_allocated_bw > dev_info.device_maxbw)
			return -EIO;

		new_minbw = sdxi_amd_qos_align_bw(req->pool_minbw,
						  cap->granularity_bw);
		total_minbw = dev_info.total_allocated_bw - pool_info.pool_minbw;
		if (new_minbw > dev_info.device_maxbw - total_minbw)
			return -EINVAL;
		return 0;
	case SDXI_AMD_QOS_POOL_OP_DESTROY:
		kfree(bitmap);
		if (!pool_known)
			return -ENOENT;
		err = sdxi_amd_qos_get_pool_info(sdxi, adm, opcode_type,
						 req->pool_num, timeout_ms,
						 &pool_info);
		if (err)
			return err;

		return 0;
	default:
		kfree(bitmap);
		return -EINVAL;
	}
}

static int sdxi_amd_qos_prevalidate_fnupd(struct sdxi_dev *sdxi,
					  struct sdxi_cxt *adm,
					  u16 opcode_type,
					  unsigned int timeout_ms,
					  const struct sdxi_amd_qos_cap_info *cap,
					  const struct sdxi_amd_qos_fnupd_req *req)
{
	size_t bytes;
	u8 *bitmap;
	int err;

	err = sdxi_amd_qos_validate_fnupd_req(req, cap->max_pools,
					      sdxi_amd_qos_max_vfs(sdxi),
					      sdxi->max_cxts,
					      cap->feature_flags);
	if (err)
		return err;

	if (!req->pool_num)
		return 0;

	bytes = (size_t)(cap->max_pools + 7U) / 8U;
	bitmap = kcalloc(bytes, sizeof(*bitmap), GFP_KERNEL);
	if (!bitmap)
		return -ENOMEM;

	err = sdxi_amd_qos_get_active_pools(sdxi, adm, opcode_type, timeout_ms,
					    cap->max_pools, bitmap);
	if (!err && !sdxi_amd_qos_pool_active(bitmap, req->pool_num))
		err = -ENOENT;
	kfree(bitmap);
	if (err)
		return err;

	return 0;
}

static int sdxi_amd_qos_prevalidate_tel(struct sdxi_dev *sdxi,
					struct sdxi_cxt *adm,
					u16 opcode_type,
					unsigned int timeout_ms,
					const struct sdxi_amd_qos_cap_info *cap,
					const struct sdxi_amd_qos_tel_req *req)
{
	size_t bytes;
	u8 *bitmap;
	int err;

	err = sdxi_amd_qos_validate_tel_req(req, cap->max_pools,
					    sdxi_amd_qos_max_vfs(sdxi),
					    sdxi->max_cxts,
					    cap->feature_flags);
	if (err)
		return err;

	switch (req->query_type) {
	case SDXI_AMD_QOS_TEL_QTYPE_POOL_CONFIG:
	case SDXI_AMD_QOS_TEL_QTYPE_POOL_REPORT:
	case SDXI_AMD_QOS_TEL_QTYPE_POOL_VARIANCE:
		if (!req->pool_num)
			return 0;

		bytes = (size_t)(cap->max_pools + 7U) / 8U;
		bitmap = kcalloc(bytes, sizeof(*bitmap), GFP_KERNEL);
		if (!bitmap)
			return -ENOMEM;

		err = sdxi_amd_qos_get_active_pools(sdxi, adm, opcode_type,
						    timeout_ms, cap->max_pools,
						    bitmap);
		if (!err && !sdxi_amd_qos_pool_active(bitmap, req->pool_num))
			err = -ENOENT;
		kfree(bitmap);
		return err;
	default:
		return 0;
	}
}

static size_t sdxi_amd_qos_tel_bytes_active_pools(u16 max_pools)
{
	return SDXI_AMD_QOS_TEL_HDR_BYTES + (size_t)(max_pools + 7U) / 8U;
}

static int sdxi_amd_qos_pool_report_bytes(u16 assigned_functions,
					  size_t *bytes)
{
	if (assigned_functions > SDXI_AMD_QOS_POOL_REPORT_MAX_FUNCTIONS)
		return -E2BIG;

	*bytes = SDXI_AMD_QOS_TEL_HDR_BYTES +
		 (size_t)assigned_functions *
		 SDXI_AMD_QOS_POOL_REPORT_ENTRY_BYTES;
	return 0;
}

static int sdxi_amd_qos_exec(struct sdxi_dev *sdxi, u16 opcode_type,
			     struct sdxi_admin_vendor_args *args,
			     unsigned int timeout_ms)
{
	struct sdxi_cxt *adm = sdxi->admin_cxt;
	struct sdxi_amd_qos_cap_info cap;
	struct sdxi_desc desc;
	void *buf = NULL;
	dma_addr_t buf_dma = 0;
	size_t dma_size = 0;
	size_t required = 0;
	void __user *ubuf = NULL;
	u32 output_available = args->out_size;
	bool pool_report = false;
	int err;

	err = sdxi_amd_qos_admin_ready(adm);
	if (err)
		return err;

	switch (args->op) {
	case SDXI_AMD_QOS_ADMIN_OP_CAP:
		err = sdxi_amd_qos_copy_input(args, NULL, 0);
		if (err)
			return err;

		required = SDXI_AMD_QOS_CAP_BYTES;
		err = sdxi_amd_qos_prepare_output(args, required, &ubuf);
		if (err)
			return err;

		sdxi_amd_qos_desc_init(&desc, opcode_type,
				       SDXI_AMD_QOS_DSC_SUBTYPE_CAP);
		break;
	case SDXI_AMD_QOS_ADMIN_OP_DEVUPD: {
		struct sdxi_amd_qos_devupd_req req;
		struct sdxi_amd_qos_dev_info info;

		err = sdxi_amd_qos_copy_input(args, &req, sizeof(req));
		if (err)
			return err;
		err = sdxi_amd_qos_get_cap_info(sdxi, adm, opcode_type,
						timeout_ms, &cap);
		if (err)
			return err;
		err = sdxi_amd_qos_get_dev_info(sdxi, adm, opcode_type,
						timeout_ms, &info);
		if (err)
			return err;
		err = sdxi_amd_qos_validate_devupd_req(req.device_maxbw,
						       cap.device_maxbw_cap,
						       info.total_allocated_bw,
						       cap.granularity_bw);
		if (err)
			return err;

		err = sdxi_amd_qos_require_no_output(args);
		if (err)
			return err;

		sdxi_amd_qos_desc_init(&desc, opcode_type,
				       SDXI_AMD_QOS_DSC_SUBTYPE_DEVUPD);
		put_unaligned_le32(req.device_maxbw, &desc.generic.operation[4]);

		return sdxi_adm_submit_desc(adm, &desc, timeout_ms,
					    &args->cst_flags);
	}
	case SDXI_AMD_QOS_ADMIN_OP_POOLUPD: {
		struct sdxi_amd_qos_poolupd_req req;
		u32 pool_ctl;

		err = sdxi_amd_qos_copy_input(args, &req, sizeof(req));
		if (err)
			return err;
		err = sdxi_amd_qos_get_cap_info(sdxi, adm, opcode_type,
						timeout_ms, &cap);
		if (err)
			return err;
		err = sdxi_amd_qos_prevalidate_poolupd(sdxi, adm, opcode_type,
						       timeout_ms, &cap, &req);
		if (err)
			return err;

		err = sdxi_amd_qos_require_no_output(args);
		if (err)
			return err;

		pool_ctl = FIELD_PREP(GENMASK(11, 0), req.pool_num) |
			   FIELD_PREP(GENMASK(13, 12), req.pool_operation);

		sdxi_amd_qos_desc_init(&desc, opcode_type,
				       SDXI_AMD_QOS_DSC_SUBTYPE_POOLUPD);
		put_unaligned_le32(pool_ctl, &desc.generic.operation[0]);
		put_unaligned_le32(req.pool_maxbw, &desc.generic.operation[4]);
		put_unaligned_le32(req.pool_minbw, &desc.generic.operation[8]);

		return sdxi_adm_submit_desc(adm, &desc, timeout_ms,
					    &args->cst_flags);
	}
	case SDXI_AMD_QOS_ADMIN_OP_FNUPD: {
		struct sdxi_amd_qos_fnupd_req req;
		u32 target_scope;
		u32 cxt_range;

		err = sdxi_amd_qos_copy_input(args, &req, sizeof(req));
		if (err)
			return err;
		err = sdxi_amd_qos_get_cap_info(sdxi, adm, opcode_type,
						timeout_ms, &cap);
		if (err)
			return err;
		err = sdxi_amd_qos_prevalidate_fnupd(sdxi, adm, opcode_type,
						     timeout_ms, &cap, &req);
		if (err)
			return err;

		err = sdxi_amd_qos_target_scope(req.pool_num, req.flags,
						req.vf_num, &target_scope);
		if (err)
			return err;

		err = sdxi_amd_qos_require_no_output(args);
		if (err)
			return err;

		cxt_range = FIELD_PREP(GENMASK(15, 0), req.cxt_start) |
			    ((u32)req.cxt_end << 16);

		sdxi_amd_qos_desc_init(&desc, opcode_type,
				       SDXI_AMD_QOS_DSC_SUBTYPE_FNUPD);
		put_unaligned_le32(target_scope, &desc.generic.operation[0]);
		put_unaligned_le32(cxt_range, &desc.generic.operation[4]);

		return sdxi_adm_submit_desc(adm, &desc, timeout_ms,
					    &args->cst_flags);
	}
	case SDXI_AMD_QOS_ADMIN_OP_TEL: {
		struct sdxi_amd_qos_tel_req req;
		u32 target_scope;
		u64 query_selector;
		u16 assigned_functions;

		err = sdxi_amd_qos_copy_input(args, &req, sizeof(req));
		if (err)
			return err;
		err = sdxi_amd_qos_get_cap_info(sdxi, adm, opcode_type,
						timeout_ms, &cap);
		if (err)
			return err;
		err = sdxi_amd_qos_prevalidate_tel(sdxi, adm, opcode_type,
						   timeout_ms, &cap, &req);
		if (err)
			return err;

		switch (req.query_type) {
		case SDXI_AMD_QOS_TEL_QTYPE_DEVICE:
			target_scope = 0;
			query_selector = sdxi_amd_qos_query_selector(0,
								     req.query_type);
			required = SDXI_AMD_QOS_TEL_FIXED_BYTES;
			break;
		case SDXI_AMD_QOS_TEL_QTYPE_POOL_CONFIG:
			target_scope = FIELD_PREP(GENMASK(11, 0),
						  req.pool_num);
			query_selector = sdxi_amd_qos_query_selector(0,
								     req.query_type);
			required = SDXI_AMD_QOS_TEL_FIXED_BYTES;
			break;
		case SDXI_AMD_QOS_TEL_QTYPE_POOL_ASSIGN:
			err = sdxi_amd_qos_target_scope(0, req.flags,
							req.vf_num,
							&target_scope);
			if (err)
				return err;
			if (!(req.flags & SDXI_AMD_QOS_TARGET_F_CXT))
				req.cxt_num = 0;
			query_selector = sdxi_amd_qos_query_selector(req.cxt_num,
								     req.query_type);
			required = SDXI_AMD_QOS_TEL_FIXED_BYTES;
			break;
		case SDXI_AMD_QOS_TEL_QTYPE_ACTIVE_POOLS:
			target_scope = 0;
			query_selector = sdxi_amd_qos_query_selector(0,
								     req.query_type);
			required =
				sdxi_amd_qos_tel_bytes_active_pools(cap.max_pools);
			break;
		case SDXI_AMD_QOS_TEL_QTYPE_POOL_REPORT:
			target_scope = FIELD_PREP(GENMASK(11, 0),
						  req.pool_num);
			query_selector = sdxi_amd_qos_query_selector(0,
								     req.query_type);
			err = sdxi_amd_qos_get_assigned_functions(sdxi, adm,
								  opcode_type,
								  req.pool_num,
								  timeout_ms,
								  &assigned_functions);
			if (err)
				return err;

			err = sdxi_amd_qos_pool_report_bytes(assigned_functions,
							     &required);
			if (err)
				return err;
			dma_size = SDXI_AMD_QOS_POOL_REPORT_MAX_BYTES;
			pool_report = true;
			break;
		case SDXI_AMD_QOS_TEL_QTYPE_POOL_VARIANCE:
			target_scope = FIELD_PREP(GENMASK(11, 0),
						  req.pool_num);
			query_selector = sdxi_amd_qos_query_selector(0,
								     req.query_type);
			required = SDXI_AMD_QOS_TEL_FIXED_BYTES;
			break;
		default:
			return -EINVAL;
		}

		err = sdxi_amd_qos_prepare_output(args, required, &ubuf);
		if (err)
			return err;

		sdxi_amd_qos_desc_init(&desc, opcode_type,
				       SDXI_AMD_QOS_DSC_SUBTYPE_TEL);
		put_unaligned_le32(target_scope, &desc.generic.operation[0]);
		put_unaligned_le64(query_selector, &desc.generic.operation[4]);
		break;
	}
	default:
		return -EOPNOTSUPP;
	}

	if (!dma_size)
		dma_size = required;

	buf = dma_alloc_coherent(sdxi_to_dev(sdxi), dma_size, &buf_dma,
				 GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	memset(buf, 0, dma_size);

	if (!IS_ALIGNED(buf_dma, SZ_4K)) {
		err = -EIO;
		goto out_free_submit;
	}

	switch (args->op) {
	case SDXI_AMD_QOS_ADMIN_OP_CAP:
		put_unaligned_le64(buf_dma, &desc.generic.operation[4]);
		break;
	case SDXI_AMD_QOS_ADMIN_OP_TEL:
		put_unaligned_le64(buf_dma, &desc.generic.operation[12]);
		break;
	default:
		err = -EINVAL;
		goto out_free_submit;
	}

	err = sdxi_adm_submit_desc(adm, &desc, timeout_ms, &args->cst_flags);
	if (err)
		goto out_free_submit;

	dma_rmb();
	if (pool_report) {
		size_t actual_required;
		u32 data_length = get_unaligned_le32(buf + 20);
		u16 assigned_functions = get_unaligned_le16(buf + 16);

		err = sdxi_amd_qos_pool_report_bytes(assigned_functions,
						     &actual_required);
		if (err || data_length !=
		    actual_required - SDXI_AMD_QOS_TEL_HDR_BYTES) {
			err = -EIO;
			goto out_free_submit;
		}

		args->out_size = actual_required;
		if (output_available < actual_required) {
			err = -ENOSPC;
			goto out_free_submit;
		}
		if (!access_ok(ubuf, actual_required)) {
			err = -EFAULT;
			goto out_free_submit;
		}
		required = actual_required;
	}
	if (copy_to_user(ubuf, buf, required))
		err = -EFAULT;

out_free_submit:
	dma_free_coherent(sdxi_to_dev(sdxi), dma_size, buf, buf_dma);
	return err;
}
