// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI RKey ioctl coverage.
 *
 * Copyright (C) 2026 Advanced Micro Devices, Inc.
 *
 * Exercises SDXI_GET_RKEY_LIST / SDXI_GET_RKEYS / SDXI_SET_RKEYS against
 * the device fd using the unified struct sdxi_key_entry +
 * sdxi_{key_list,get_keys,set_keys}_args contract.
 *
 * All tests skip cleanly when the device does not advertise RKey support
 * (MMIO_CAP1.rkey_cap == 0); root-only behavior is exercised when the
 * test is invoked with sufficient privileges and otherwise just validated
 * for the documented EPERM.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/sdxi.h>

#include "lib.h"
#include "lib/fixture-device.h"
#include "../kselftest_harness.h"

/*
 * Wire-format bits for an RKEY_ENT, mirrored from drivers/dma/sdxi/hw.h
 * so the test stays standalone (kernel-private headers aren't installed).
 * Keep in sync with `struct sdxi_rkey_ent` and SDXI_RKEY_ENT_*.
 */
#define RKEY_ENT_VL		(1U << 0)
#define RKEY_ENT_INTR_NUM_MAX	((1U << 11) - 1)	/* bits [14:4] */

static void rkey_pack_minimal(uint32_t data[4])
{
	memset(data, 0, sizeof(uint32_t) * 4);
	/* intr_num: only the valid bit; pasid/rsvd left zero. */
	data[0] = RKEY_ENT_VL;
}

static int rkey_get_max(int fd, uint32_t *out)
{
	struct sdxi_dev_attr_args args = {};
	int rc;

	args.argsz = sizeof(args);
	args.attr = SDXI_DEV_ATTR_MAX_RKEY_SZ;

	rc = ioctl(fd, SDXI_GET_DEV_ATTR, &args);
	if (rc != 0)
		return -errno;

	*out = (uint32_t)args.val;
	return 0;
}

/*
 * Check SDXI_DEV_ATTR_MAX_RKEY_SZ instead of issuing a list-with-zero-buffer
 * probe so privileged tests skip deterministically before exercising an
 * RKey ioctl.
 */
static bool rkey_available(struct __test_metadata *_metadata, int fd)
{
	uint32_t max = 0;
	int rc;

	rc = rkey_get_max(fd, &max);
	if (rc != 0)
		SKIP(return false,
		     "SDXI_GET_DEV_ATTR(MAX_RKEY_SZ) failed: %d", rc);
	if (max == 0)
		SKIP(return false,
		     "RKey table not present on this device");

	return true;
}

static int rkey_read_bitmap(int fd, struct sdxi_key_list_args **out)
{
	struct sdxi_key_list_args probe = {};
	struct sdxi_key_list_args *full;
	size_t total;
	int rc;

	probe.argsz = sizeof(probe);
	if (ioctl(fd, SDXI_GET_RKEY_LIST, &probe) == 0) {
		/* Empty table is legal; emit a synthesized header for caller. */
		*out = calloc(1, sizeof(probe));
		if (!*out)
			return -ENOMEM;
		**out = probe;
		return 0;
	}
	if (errno != ENOSPC)
		return -errno;

	total = sizeof(*full) + probe.buf_size;
	full = calloc(1, total);
	if (!full)
		return -ENOMEM;

	full->argsz = sizeof(*full);
	full->buf_size = probe.buf_size;
	rc = ioctl(fd, SDXI_GET_RKEY_LIST, full);
	if (rc != 0) {
		rc = -errno;
		free(full);
		return rc;
	}

	*out = full;
	return 0;
}

/* ----------------------- SDXI_GET_RKEY_LIST ----------------------- */

TEST_F(dev_sdxi, get_rkey_list_requires_admin)
{
	struct sdxi_key_list_args args = {};

	if (geteuid() == 0)
		SKIP(return, "needs non-root");

	args.argsz = sizeof(args);
	errno = 0;
	EXPECT_EQ(ioctl(self->fd, SDXI_GET_RKEY_LIST, &args), -1);
	EXPECT_EQ(errno, EPERM);
}

TEST_F(dev_sdxi, get_rkey_list_rejects_flags)
{
	struct sdxi_key_list_args args = {};

	if (geteuid() != 0)
		SKIP(return, "requires root");
	if (!rkey_available(_metadata, self->fd))
		return;

	args.argsz = sizeof(args);
	args.flags = 1;
	errno = 0;
	EXPECT_EQ(ioctl(self->fd, SDXI_GET_RKEY_LIST, &args), -1);
	EXPECT_EQ(errno, EINVAL);
}

TEST_F(dev_sdxi, get_rkey_list_rejects_rsvd)
{
	struct sdxi_key_list_args args = {};

	if (geteuid() != 0)
		SKIP(return, "requires root");
	if (!rkey_available(_metadata, self->fd))
		return;

	args.argsz = sizeof(args);
	args.rsvd0 = 1;
	errno = 0;
	EXPECT_EQ(ioctl(self->fd, SDXI_GET_RKEY_LIST, &args), -1);
	EXPECT_EQ(errno, EINVAL);
}

TEST_F(dev_sdxi, get_rkey_list_resize_and_retry)
{
	struct sdxi_key_list_args probe = {};
	struct sdxi_key_list_args *full;
	uint32_t required;
	uint32_t nentries;
	size_t total;

	if (geteuid() != 0)
		SKIP(return, "requires root");
	if (!rkey_available(_metadata, self->fd))
		return;

	/* Probe with buf_size = 0 to learn the required bitmap size. */
	probe.argsz = sizeof(probe);
	errno = 0;
	EXPECT_EQ(ioctl(self->fd, SDXI_GET_RKEY_LIST, &probe), -1);
	EXPECT_EQ(errno, ENOSPC);
	EXPECT_GT(probe.nentries, 0U);
	EXPECT_EQ(probe.buf_size, (probe.nentries + 7U) / 8U);

	required = probe.buf_size;
	nentries = probe.nentries;

	/* Re-issue with the requested capacity; must succeed. */
	total = sizeof(*full) + required;
	full = calloc(1, total);
	ASSERT_NE(full, NULL);

	full->argsz = sizeof(*full);
	full->buf_size = required;

	ASSERT_EQ(ioctl(self->fd, SDXI_GET_RKEY_LIST, full), 0);
	EXPECT_EQ(full->nentries, nentries);
	EXPECT_EQ(full->buf_size, required);
	EXPECT_LE(full->nvalid, nentries);

	free(full);
}

/* ------------------------- SDXI_GET_RKEYS ------------------------- */

TEST_F(dev_sdxi, get_rkeys_requires_admin)
{
	struct sdxi_get_keys_args args = {};

	if (geteuid() == 0)
		SKIP(return, "needs non-root");

	args.argsz = sizeof(args);
	errno = 0;
	EXPECT_EQ(ioctl(self->fd, SDXI_GET_RKEYS, &args), -1);
	EXPECT_EQ(errno, EPERM);
}

TEST_F(dev_sdxi, get_rkeys_rejects_oob_index)
{
	union {
		struct sdxi_get_keys_args align;
		unsigned char storage[sizeof(struct sdxi_get_keys_args) +
				      sizeof(struct sdxi_key_entry)];
	} buffer = {};
	struct sdxi_get_keys_args *args = (void *)buffer.storage;
	struct sdxi_key_entry *entry = (void *)(args + 1);
	uint32_t nentries;

	if (geteuid() != 0)
		SKIP(return, "requires root");
	if (!rkey_available(_metadata, self->fd))
		return;

	ASSERT_EQ(rkey_get_max(self->fd, &nentries), 0);

	args->argsz = sizeof(*args);
	args->nkeys = 1;
	entry->index = nentries;	/* one past the end */

	errno = 0;
	EXPECT_EQ(ioctl(self->fd, SDXI_GET_RKEYS, args), -1);
	EXPECT_EQ(errno, EINVAL);
}

TEST_F(dev_sdxi, get_rkeys_rejects_entry_rsvd)
{
	union {
		struct sdxi_get_keys_args align;
		unsigned char storage[sizeof(struct sdxi_get_keys_args) +
				      sizeof(struct sdxi_key_entry)];
	} buffer = {};
	struct sdxi_get_keys_args *args = (void *)buffer.storage;
	struct sdxi_key_entry *entry = (void *)(args + 1);

	if (geteuid() != 0)
		SKIP(return, "requires root");
	if (!rkey_available(_metadata, self->fd))
		return;

	args->argsz = sizeof(*args);
	args->nkeys = 1;
	entry->index = 0;
	entry->rsvd0 = 1;

	errno = 0;
	EXPECT_EQ(ioctl(self->fd, SDXI_GET_RKEYS, args), -1);
	EXPECT_EQ(errno, EINVAL);
}

/* ------------------------- SDXI_SET_RKEYS ------------------------- */

TEST_F(dev_sdxi, set_rkeys_requires_admin)
{
	struct sdxi_set_keys_args args = {};

	if (geteuid() == 0)
		SKIP(return, "needs non-root");

	args.argsz = sizeof(args);
	errno = 0;
	EXPECT_EQ(ioctl(self->fd, SDXI_SET_RKEYS, &args), -1);
	EXPECT_EQ(errno, EPERM);
}

TEST_F(dev_sdxi, set_rkeys_zero_nkeys_reports_commit_all)
{
	struct sdxi_set_keys_args args = {};

	if (geteuid() != 0)
		SKIP(return, "requires root");
	if (!rkey_available(_metadata, self->fd))
		return;

	args.argsz = sizeof(args);
	args.nkeys = 0;

	ASSERT_EQ(ioctl(self->fd, SDXI_SET_RKEYS, &args), 0);
	EXPECT_EQ(args.commit_state, (uint32_t)SDXI_KEY_COMMIT_ALL);
	EXPECT_EQ(args.cst_flags, 0U);
	EXPECT_EQ(args.first_failed_index, 0U);
}

TEST_F(dev_sdxi, set_rkeys_round_trip)
{
	union {
		struct sdxi_set_keys_args align;
		unsigned char storage[sizeof(struct sdxi_set_keys_args) +
				      sizeof(struct sdxi_key_entry)];
	} set_buffer = {};
	union {
		struct sdxi_get_keys_args align;
		unsigned char storage[sizeof(struct sdxi_get_keys_args) +
				      sizeof(struct sdxi_key_entry)];
	} get_buffer = {};
	struct sdxi_set_keys_args *set_args = (void *)set_buffer.storage;
	struct sdxi_get_keys_args *get_args = (void *)get_buffer.storage;
	struct sdxi_key_entry *set_entry = (void *)(set_args + 1);
	struct sdxi_key_entry *get_entry = (void *)(get_args + 1);
	uint32_t nentries;
	uint32_t target_index;

	if (geteuid() != 0)
		SKIP(return, "requires root");
	if (!rkey_available(_metadata, self->fd))
		return;

	ASSERT_EQ(rkey_get_max(self->fd, &nentries), 0);
	ASSERT_GT(nentries, 0U);

	/*
	 * Use the highest available index to minimize collisions with any
	 * driver-managed reservations at the bottom of the table.
	 */
	target_index = nentries - 1;

	/* Phase 1: write a minimal-but-valid RKey entry. */
	set_args->argsz = sizeof(*set_args);
	set_args->nkeys = 1;
	set_entry->index = target_index;
	rkey_pack_minimal(set_entry->data);

	ASSERT_EQ(ioctl(self->fd, SDXI_SET_RKEYS, set_args), 0);
	EXPECT_EQ(set_args->commit_state, (uint32_t)SDXI_KEY_COMMIT_ALL);
	EXPECT_EQ(set_args->cst_flags, 0U);
	EXPECT_EQ(set_args->first_failed_index, 0U);

	/* Phase 2: read it back and check the wire bytes survived. */
	get_args->argsz = sizeof(*get_args);
	get_args->nkeys = 1;
	get_entry->index = target_index;

	ASSERT_EQ(ioctl(self->fd, SDXI_GET_RKEYS, get_args), 0);
	EXPECT_EQ(get_args->nkeys, 1U);
	EXPECT_EQ(get_entry->index, target_index);
	EXPECT_EQ(get_entry->data[0], RKEY_ENT_VL);
	EXPECT_EQ(get_entry->data[1], 0U);
	EXPECT_EQ(get_entry->data[2], 0U);
	EXPECT_EQ(get_entry->data[3], 0U);

	/* Phase 3: bitmap reflects the new validity. */
	struct sdxi_key_list_args *full = NULL;
	uint8_t mask;

	ASSERT_EQ(rkey_read_bitmap(self->fd, &full), 0);
	ASSERT_NE(full, NULL);
	ASSERT_GE(full->buf_size, (target_index / 8) + 1);

	mask = full->data[target_index / 8] & (1U << (target_index % 8));
	EXPECT_NE(mask, 0);
	EXPECT_GT(full->nvalid, 0U);

	free(full);
}

TEST_F(dev_sdxi, set_rkeys_rejects_flags)
{
	struct sdxi_set_keys_args args = {};

	if (geteuid() != 0)
		SKIP(return, "requires root");
	if (!rkey_available(_metadata, self->fd))
		return;

	args.argsz = sizeof(args);
	args.flags = 1;

	errno = 0;
	EXPECT_EQ(ioctl(self->fd, SDXI_SET_RKEYS, &args), -1);
	EXPECT_EQ(errno, EINVAL);
}

TEST_F(dev_sdxi, set_rkeys_rejects_rsvd)
{
	struct sdxi_set_keys_args args = {};

	if (geteuid() != 0)
		SKIP(return, "requires root");
	if (!rkey_available(_metadata, self->fd))
		return;

	args.argsz = sizeof(args);
	args.rsvd0[0] = 1;

	errno = 0;
	EXPECT_EQ(ioctl(self->fd, SDXI_SET_RKEYS, &args), -1);
	EXPECT_EQ(errno, EINVAL);
}

TEST_HARNESS_MAIN
