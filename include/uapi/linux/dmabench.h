/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_DMABENCH_H
#define _UAPI_LINUX_DMABENCH_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define DMABENCH_CHANNEL_LEN	32
#define DMABENCH_F_VERIFY		(1U << 0)

#define DMABENCH_MAX_QUEUE_DEPTH	4096U
#define DMABENCH_MAX_BUFFER_COUNT	65536U
#define DMABENCH_MAX_TRANSFER_SIZE (1ULL << 30)
#define DMABENCH_MAX_ALLOCATION_BYTES (16ULL << 30)
#define DMABENCH_MAX_TIMEOUT_MS	600000U

struct dmabench_config {
	char channel[DMABENCH_CHANNEL_LEN]; /* NUL-terminated exact channel name */
	__aligned_u64 transfer_size;
	__aligned_u64 transfers;
	__aligned_u64 warmup_transfers;
	__u32 queue_depth;
	__u32 batch_size;
	__u32 buffer_count;
	__s32 cpu; /* -1 for unbound, otherwise an online CPU */
	__u32 timeout_ms; /* Maximum interval without batch completion progress */
	__u32 flags;
	__aligned_u64 reserved[4]; /* Must be zero */
};

struct dmabench_result {
	__aligned_u64 elapsed_ns;
	__aligned_u64 submitted;
	__aligned_u64 completed; /* Copies reclaimed through batch completions */
	__aligned_u64 payload_bytes;
	__aligned_u64 issue_pending_calls;
	__aligned_u64 allocation_bytes; /* Sum of page-rounded src/dst sizes */
	__aligned_u64 reserved[4]; /* Must be zero on input; zero on output */
};

struct dmabench_run {
	struct dmabench_config config;
	struct dmabench_result result;
};

#define DMABENCH_RUN _IOWR(0xb9, 0x00, struct dmabench_run)

#endif /* _UAPI_LINUX_DMABENCH_H */
