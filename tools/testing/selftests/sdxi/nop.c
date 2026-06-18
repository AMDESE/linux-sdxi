// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI NOP descriptor selftest.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#include <stdlib.h>

#include "lib/descriptor.h"
#include "lib/fixture-context.h"
#include "lib/lib.h"
#include "../kselftest_harness.h"

TEST_F(sdxi_context, nop)
{
	struct sdxi_desc d = sdxi_dsc_encode_nop();

	EXPECT_EQ(sdxi_submit_sync(&self->context, &d), 0);
}

TEST_F(sdxi_context, nops_wrap)
{
	struct sdxi_desc d = sdxi_dsc_encode_nop();

	for (size_t i = 0; i < self->context.n_entries * 2; ++i)
		EXPECT_EQ(sdxi_submit_sync(&self->context, &d), 0);
}

TEST_HARNESS_MAIN
