// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI error path selftests.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#include <stdlib.h>

#include "lib/descriptor.h"
#include "lib/fixture-context.h"
#include "lib/lib.h"
#include "../kselftest_harness.h"

TEST_F(sdxi_context, error)
{
	struct sdxi_desc d = sdxi_dsc_encode_rsvd();

	// Attempt to make the error log wrap
	for (size_t i = 0; i < 80; ++i)
		EXPECT_EQ(sdxi_submit_oneshot(&d), 0);
}

TEST_HARNESS_MAIN
