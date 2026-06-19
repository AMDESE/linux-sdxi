// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI copy descriptor selftest.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#include <stdlib.h>

#include "lib/descriptor.h"
#include "lib/fixture-context.h"
#include "lib/lib.h"
#include "../kselftest_harness.h"

TEST_F(sdxi_context, copy)
{
	const long src = 0xabcdef;
	long dest = 0;
	struct sdxi_desc copy = sdxi_dsc_encode_copy(&dest, &src, sizeof(src));

	EXPECT_EQ(sdxi_submit_sync(&self->context, &copy), 0);

	EXPECT_EQ(dest, src);
}

TEST_F(sdxi_context, copy_wrap)
{

	for (size_t i = 0; i < self->context.n_entries * 2; ++i) {
		const long src = random();
		long dest = 0;
		struct sdxi_desc copy = sdxi_dsc_encode_copy(&dest, &src, sizeof(src));

		EXPECT_EQ(sdxi_submit_sync(&self->context, &copy), 0);

		EXPECT_EQ(dest, src);
	}
}

TEST_HARNESS_MAIN
