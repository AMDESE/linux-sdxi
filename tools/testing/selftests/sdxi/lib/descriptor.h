/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SDXI selftest descriptor encoders.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 */

#ifndef SELFTEST_SDXI_DESCRIPTOR_H
#define SELFTEST_SDXI_DESCRIPTOR_H

#include "linux/build_bug.h"
#include "linux/compiler.h"
#include "linux/types.h"

// Size of the "body" of each descriptor between the common opcode and
// csb_ptr fields.
#define SDXI_DESC_PAYLOAD_BYTES 52

#define declare_sdxi_desc_payload(_name, _layout)			\
	struct _name _layout __packed;					\
	static_assert(sizeof(struct _name) == SDXI_DESC_PAYLOAD_BYTES,	\
		      "descriptor payload size mismatch")

declare_sdxi_desc_payload(sdxi_desc_nop, {
		__u8 empty[SDXI_DESC_PAYLOAD_BYTES];
	});

declare_sdxi_desc_payload(sdxi_desc_copy, {
		__le32 size;
		__u8   attr;
		__u8   rsvd_0[3];
		__le16 akey0;
		__le16 akey1;
		__le64 addr0;
		__le64 addr1;
		__u8   rsvd_1[24];
	});

struct sdxi_desc {
	union {
		struct {
			__le32 opcode;
			union {
				__u8   operation[SDXI_DESC_PAYLOAD_BYTES];
				struct sdxi_desc_nop nop;
				struct sdxi_desc_copy copy;
			};
			__le64 csb_ptr;
		};
		__le64 qw[8];
	};
} __packed __aligned(64);
static_assert(sizeof(struct sdxi_desc) == 64, "descriptor size mismatch");

#endif /* SELFTEST_SDXI_DESCRIPTOR_H */
