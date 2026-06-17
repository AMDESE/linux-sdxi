// SPDX-License-Identifier: GPL-2.0-only
/*
 * AMD SDXI QoS helper tests.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#include <kunit/test.h>
#include <linux/bitfield.h>
#include <linux/module.h>

#include "qos.h"

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

static void sdxi_kunit_qos_query_selector(struct kunit *t)
{
	u64 query_selector =
		sdxi_amd_qos_query_selector(0x1234,
					    SDXI_AMD_QOS_TEL_QTYPE_POOL_CONFIG);

	KUNIT_EXPECT_EQ(t, (u16)0x1234,
			(u16)FIELD_GET(GENMASK_ULL(15, 0), query_selector));
	KUNIT_EXPECT_EQ(t, (u8)SDXI_AMD_QOS_TEL_QTYPE_POOL_CONFIG,
			(u8)FIELD_GET(GENMASK_ULL(18, 16), query_selector));
	KUNIT_EXPECT_EQ(t, 0U,
			(u32)FIELD_GET(GENMASK_ULL(31, 19),
					query_selector));
}

static void sdxi_kunit_qos_align_bw(struct kunit *t)
{
	KUNIT_EXPECT_EQ(t, 0U, sdxi_amd_qos_align_bw(39, 40));
	KUNIT_EXPECT_EQ(t, 40U, sdxi_amd_qos_align_bw(40, 40));
	KUNIT_EXPECT_EQ(t, 40U, sdxi_amd_qos_align_bw(79, 40));
	KUNIT_EXPECT_EQ(t, 80U, sdxi_amd_qos_align_bw(80, 40));
}

static void sdxi_kunit_qos_validate_devupd(struct kunit *t)
{
	KUNIT_EXPECT_EQ(t, 0,
			sdxi_amd_qos_validate_devupd_req(119, 120, 80, 40));
	KUNIT_EXPECT_EQ(t, -EINVAL,
			sdxi_amd_qos_validate_devupd_req(121, 120, 80, 40));
	KUNIT_EXPECT_EQ(t, -EINVAL,
			sdxi_amd_qos_validate_devupd_req(79, 120, 80, 40));
}

static void sdxi_kunit_qos_validate_poolupd(struct kunit *t)
{
	const struct sdxi_amd_qos_poolupd_req create = {
		.pool_num = 1,
		.pool_operation = SDXI_AMD_QOS_POOL_OP_CREATE,
		.pool_minbw = 41,
		.pool_maxbw = 79,
	};
	const struct sdxi_amd_qos_poolupd_req invalid_bw = {
		.pool_num = 1,
		.pool_operation = SDXI_AMD_QOS_POOL_OP_UPDATE,
		.pool_minbw = 79,
		.pool_maxbw = 41,
	};
	const struct sdxi_amd_qos_poolupd_req create_pool0 = {
		.pool_operation = SDXI_AMD_QOS_POOL_OP_CREATE,
	};
	const struct sdxi_amd_qos_poolupd_req destroy_pool0 = {
		.pool_operation = SDXI_AMD_QOS_POOL_OP_DESTROY,
	};

	KUNIT_EXPECT_EQ(t, 0,
			sdxi_amd_qos_validate_poolupd_req(&create, 8, 40));
	KUNIT_EXPECT_EQ(t, -EINVAL,
			sdxi_amd_qos_validate_poolupd_req(&invalid_bw, 8, 40));
	KUNIT_EXPECT_EQ(t, -EINVAL,
			sdxi_amd_qos_validate_poolupd_req(&create_pool0, 8, 40));
	KUNIT_EXPECT_EQ(t, -EINVAL,
			sdxi_amd_qos_validate_poolupd_req(&destroy_pool0, 8, 40));
}

static void sdxi_kunit_qos_validate_fnupd(struct kunit *t)
{
	const struct sdxi_amd_qos_fnupd_req function = {
		.pool_num = 1,
		.vf_num = 4,
		.cxt_start = 16,
		.cxt_end = 16,
	};
	const struct sdxi_amd_qos_fnupd_req context = {
		.pool_num = 1,
		.flags = SDXI_AMD_QOS_TARGET_F_CXT,
		.cxt_start = 1,
		.cxt_end = 1,
	};
	const struct sdxi_amd_qos_fnupd_req invalid_context = {
		.pool_num = 1,
		.flags = SDXI_AMD_QOS_TARGET_F_CXT,
		.cxt_start = 16,
		.cxt_end = 16,
	};
	const struct sdxi_amd_qos_fnupd_req invalid_vf = {
		.pool_num = 1,
		.flags = SDXI_AMD_QOS_TARGET_F_VF,
		.vf_num = 4,
	};
	const u16 features = SDXI_AMD_QOS_FEATURE_FLEXIBLE_POOL_SCOPE;
	int ret;

	KUNIT_EXPECT_EQ(t, 0,
			sdxi_amd_qos_validate_fnupd_req(&function, 8, 0, 16, 0));
	KUNIT_EXPECT_EQ(t, 0,
			sdxi_amd_qos_validate_fnupd_req(&context, 8, 0, 16, 0));
	ret = sdxi_amd_qos_validate_fnupd_req(&invalid_context, 8, 0, 16, features);
	KUNIT_EXPECT_EQ(t, -EINVAL, ret);

	ret = sdxi_amd_qos_validate_fnupd_req(&invalid_vf, 8, 4, 16, 0);
	KUNIT_EXPECT_EQ(t, -EINVAL, ret);
}

static void sdxi_kunit_qos_validate_tel(struct kunit *t)
{
	const struct sdxi_amd_qos_tel_req device = {
		.query_type = SDXI_AMD_QOS_TEL_QTYPE_DEVICE,
	};
	const struct sdxi_amd_qos_tel_req pool = {
		.pool_num = 7,
		.flags = SDXI_AMD_QOS_TARGET_F_VF,
		.vf_num = 99,
		.cxt_num = 99,
		.query_type = SDXI_AMD_QOS_TEL_QTYPE_POOL_CONFIG,
	};
	const struct sdxi_amd_qos_tel_req unsupported = {
		.flags = SDXI_AMD_QOS_TARGET_F_CXT,
		.cxt_num = 1,
		.query_type = SDXI_AMD_QOS_TEL_QTYPE_POOL_ASSIGN,
	};
	const struct sdxi_amd_qos_tel_req invalid_context = {
		.flags = SDXI_AMD_QOS_TARGET_F_CXT,
		.cxt_num = 16,
		.query_type = SDXI_AMD_QOS_TEL_QTYPE_POOL_ASSIGN,
	};
	const struct sdxi_amd_qos_tel_req invalid_query = {
		.query_type = 6,
	};
	const u16 features = SDXI_AMD_QOS_FEATURE_FLEXIBLE_POOL_SCOPE;
	int ret;

	KUNIT_EXPECT_EQ(t, 0,
			sdxi_amd_qos_validate_tel_req(&device, 8, 4, 16, 0));
	KUNIT_EXPECT_EQ(t, 0,
			sdxi_amd_qos_validate_tel_req(&pool, 8, 4, 16, 0));
	ret = sdxi_amd_qos_validate_tel_req(&unsupported, 8, 4, 16, 0);
	KUNIT_EXPECT_EQ(t, -EOPNOTSUPP, ret);

	ret = sdxi_amd_qos_validate_tel_req(&invalid_context, 8, 4, 16, features);
	KUNIT_EXPECT_EQ(t, -EINVAL, ret);

	ret = sdxi_amd_qos_validate_tel_req(&invalid_query, 8, 4, 16, 0);
	KUNIT_EXPECT_EQ(t, -EINVAL, ret);
}

static struct kunit_case sdxi_qos_cases[] = {
	KUNIT_CASE(sdxi_kunit_qos_query_selector),
	KUNIT_CASE(sdxi_kunit_qos_align_bw),
	KUNIT_CASE(sdxi_kunit_qos_validate_devupd),
	KUNIT_CASE(sdxi_kunit_qos_validate_poolupd),
	KUNIT_CASE(sdxi_kunit_qos_validate_fnupd),
	KUNIT_CASE(sdxi_kunit_qos_validate_tel),
	{}
};

static struct kunit_suite sdxi_qos_suite = {
	.name = "AMD SDXI QoS helpers",
	.test_cases = sdxi_qos_cases,
};

kunit_test_suite(sdxi_qos_suite);

MODULE_DESCRIPTION("AMD SDXI QoS helper tests");
MODULE_AUTHOR("Wei Huang");
MODULE_LICENSE("GPL");
