/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AMD SDXI QoS internal definitions.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#ifndef __DMA_SDXI_AMD_QOS_H
#define __DMA_SDXI_AMD_QOS_H

#include <linux/bits.h>
#include <linux/types.h>

enum sdxi_amd_qos_admin_vendor_op {
	SDXI_AMD_QOS_ADMIN_OP_CAP = 1,
	SDXI_AMD_QOS_ADMIN_OP_DEVUPD = 2,
	SDXI_AMD_QOS_ADMIN_OP_POOLUPD = 3,
	SDXI_AMD_QOS_ADMIN_OP_FNUPD = 4,
	SDXI_AMD_QOS_ADMIN_OP_TEL = 5,
};

enum sdxi_amd_qos_admin_target_flags {
	SDXI_AMD_QOS_TARGET_F_CXT = BIT(0),
	SDXI_AMD_QOS_TARGET_F_VF = BIT(1),
};

enum sdxi_amd_qos_feature_flags {
	SDXI_AMD_QOS_FEATURE_DYNAMIC_POOL_RECONFIG = BIT(0),
	SDXI_AMD_QOS_FEATURE_DYNAMIC_POOL_REASSIGN = BIT(1),
	SDXI_AMD_QOS_FEATURE_TEL_TIMESTAMPS = BIT(2),
	SDXI_AMD_QOS_FEATURE_FLEXIBLE_POOL_SCOPE = BIT(3),
};

struct sdxi_amd_qos_devupd_req {
	u32 device_maxbw;
};

struct sdxi_amd_qos_poolupd_req {
	u16 pool_num;
	u8 pool_operation;
	u8 rsvd0;
	u32 pool_maxbw;
	u32 pool_minbw;
};

struct sdxi_amd_qos_fnupd_req {
	u16 pool_num;
	u16 flags;
	u16 vf_num;
	u16 cxt_start;
	u16 cxt_end;
	u16 rsvd0;
};

struct sdxi_amd_qos_tel_req {
	u16 pool_num;
	u16 flags;
	u16 vf_num;
	u16 cxt_num;
	u8 query_type;
	u8 rsvd0[3];
};

/* AMD SDXI Quality-of-Service Extensions (ASQOSE). */
#define SDXI_AMD_QOS_DSC_SUBTYPE_CAP		0x00
#define SDXI_AMD_QOS_DSC_SUBTYPE_DEVUPD		0x01
#define SDXI_AMD_QOS_DSC_SUBTYPE_POOLUPD	0x02
#define SDXI_AMD_QOS_DSC_SUBTYPE_FNUPD		0x03
#define SDXI_AMD_QOS_DSC_SUBTYPE_TEL		0x04

#define SDXI_AMD_QOS_TEL_QTYPE_DEVICE		0x0
#define SDXI_AMD_QOS_TEL_QTYPE_POOL_CONFIG	0x1
#define SDXI_AMD_QOS_TEL_QTYPE_POOL_ASSIGN	0x2
#define SDXI_AMD_QOS_TEL_QTYPE_ACTIVE_POOLS	0x3
#define SDXI_AMD_QOS_TEL_QTYPE_POOL_REPORT	0x4
#define SDXI_AMD_QOS_TEL_QTYPE_POOL_VARIANCE	0x5

#define SDXI_AMD_QOS_POOL_OP_CREATE		0x0
#define SDXI_AMD_QOS_POOL_OP_UPDATE		0x1
#define SDXI_AMD_QOS_POOL_OP_DESTROY		0x2

u64 sdxi_amd_qos_query_selector(u16 cxt_num, u8 query_type);
u32 sdxi_amd_qos_align_bw(u32 bw, u32 granularity);
int sdxi_amd_qos_validate_devupd_req(u32 device_maxbw, u32 device_maxbw_cap,
				     u32 total_allocated_bw, u32 granularity_bw);
int sdxi_amd_qos_validate_poolupd_req(const struct sdxi_amd_qos_poolupd_req *req,
				      u16 max_pools, u32 granularity_bw);
int sdxi_amd_qos_validate_fnupd_req(const struct sdxi_amd_qos_fnupd_req *req,
				    u16 max_pools, u16 max_vfs, u32 max_cxts,
				    u16 feature_flags);
int sdxi_amd_qos_validate_tel_req(const struct sdxi_amd_qos_tel_req *req,
				  u16 max_pools, u16 max_vfs, u32 max_cxts,
				  u16 feature_flags);

#endif /* __DMA_SDXI_AMD_QOS_H */
