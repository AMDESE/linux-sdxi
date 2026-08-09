// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI key table management.
 *
 * Copyright Advanced Micro Devices, Inc.
 */

#include <linux/bitfield.h>
#include <linux/capability.h>
#include <linux/dma-mapping.h>
#include <linux/kernel.h>
#include <linux/log2.h>
#include <linux/sizes.h>
#include <linux/string.h>
#include <uapi/linux/sdxi.h>

#include "admin.h"
#include "context.h"
#include "hw.h"
#include "intr.h"
#include "ioctl.h"
#include "keys.h"
#include "mmio.h"
#include "sdxi.h"

#define SDXI_KEY_DEFAULT_TIMEOUT_MS	5000U

static u32 sdxi_key_bitmap_bytes(u32 entries)
{
	return DIV_ROUND_UP(entries, 8);
}

static bool sdxi_key_entry_valid(const void *entry)
{
	__le16 intr_num;

	memcpy(&intr_num, entry, sizeof(intr_num));
	return le16_to_cpu(intr_num) & BIT(0);
}

static u32 sdxi_key_count_valid(const void *table, u32 entries, size_t stride)
{
	u32 count = 0;
	u32 i;

	for (i = 0; i < entries; i++)
		if (sdxi_key_entry_valid((const u8 *)table + i * stride))
			count++;

	return count;
}

static u32 sdxi_key_build_bitmap(u8 *bitmap, const void *table, u32 entries,
				 size_t stride)
{
	u32 bytes = sdxi_key_bitmap_bytes(entries);
	u32 count = 0;
	u32 i;

	memset(bitmap, 0, bytes);
	for (i = 0; i < entries; i++) {
		if (!sdxi_key_entry_valid((const u8 *)table + i * stride))
			continue;
		bitmap[i / 8] |= BIT(i % 8);
		count++;
	}

	return count;
}

static int sdxi_key_args_check(u32 argsz, size_t minimum, u32 flags,
			       const u32 *reserved, size_t reserved_words)
{
	size_t i;

	if (argsz < minimum || flags)
		return -EINVAL;
	for (i = 0; i < reserved_words; i++)
		if (reserved[i])
			return -EINVAL;

	return 0;
}

static int sdxi_key_list_fill(struct sdxi_key_list_args *args,
			      const void *table, u32 entries, size_t stride)
{
	u32 available = args->buf_size;
	u32 required = sdxi_key_bitmap_bytes(entries);

	args->argsz = sizeof(*args);
	args->buf_size = required;
	args->nentries = entries;
	args->nvalid = sdxi_key_count_valid(table, entries, stride);

	if (available < required)
		return -ENOSPC;

	args->nvalid = sdxi_key_build_bitmap(args->data, table, entries,
					     stride);
	return 0;
}

static int sdxi_key_check_indices(const struct sdxi_key_entry *keys,
				  u32 nkeys, u32 entries,
				  u16 *first, u16 *last)
{
	u16 minimum = U16_MAX;
	u16 maximum = 0;
	u32 i;

	for (i = 0; i < nkeys; i++) {
		if (keys[i].rsvd0 || keys[i].index >= entries)
			return -EINVAL;
		minimum = min_t(u16, minimum, keys[i].index);
		maximum = max_t(u16, maximum, keys[i].index);
	}

	if (first)
		*first = minimum;
	if (last)
		*last = maximum;
	return 0;
}

static void sdxi_set_keys_init(struct sdxi_set_keys_args *args)
{
	args->cst_flags = 0;
	args->commit_state = SDXI_KEY_COMMIT_NONE;
	args->first_failed_index = 0;
}

static unsigned int
sdxi_set_keys_timeout(const struct sdxi_set_keys_args *args)
{
	return args->timeout_ms ?: SDXI_KEY_DEFAULT_TIMEOUT_MS;
}

static int sdxi_rkey_validate(const struct sdxi_rkey_ent *entry)
{
	u16 intr_num = le16_to_cpu(entry->intr_num);
	u32 pasid = le32_to_cpu(entry->pasid);

	if (intr_num & BIT(15))
		return -EINVAL;
	if (pasid & ~(SDXI_RKEY_ENT_PASID | SDXI_RKEY_ENT_PR |
		      SDXI_RKEY_ENT_PH))
		return -EINVAL;
	if (memchr_inv(entry->rsvd_0, 0, sizeof(entry->rsvd_0)))
		return -EINVAL;

	return 0;
}

static void sdxi_rkey_store(struct sdxi_rkey_ent *destination,
			    const struct sdxi_rkey_ent *source)
{
	struct sdxi_rkey_ent entry = *source;
	u16 intr_num = le16_to_cpu(source->intr_num);

	entry.intr_num = cpu_to_le16(intr_num & ~SDXI_RKEY_ENT_VL);
	WRITE_ONCE(destination->intr_num, 0);
	dma_wmb();
	memcpy(destination, &entry, sizeof(entry));
	dma_wmb();
	WRITE_ONCE(destination->intr_num, source->intr_num);
}

static int sdxi_akey_validate(const struct sdxi_akey_ent *entry)
{
	u16 intr_num = le16_to_cpu(entry->intr_num);
	u32 pasid = le32_to_cpu(entry->pasid);

	if (intr_num & BIT(15))
		return -EINVAL;
	if (pasid & ~(SDXI_AKEY_ENT_PASID | SDXI_AKEY_ENT_PR |
		      SDXI_AKEY_ENT_PH))
		return -EINVAL;
	if (memchr_inv(entry->rsvd_0, 0, sizeof(entry->rsvd_0)) ||
	    memchr_inv(entry->rsvd_1, 0, sizeof(entry->rsvd_1)))
		return -EINVAL;

	return 0;
}

static int sdxi_akey_validate_user(const struct sdxi_cxt *cxt,
				   const struct sdxi_akey_ent *entry)
{
	u16 intr_num = le16_to_cpu(entry->intr_num);
	u32 pasid = le32_to_cpu(entry->pasid);

	if (!(intr_num & SDXI_AKEY_ENT_VL)) {
		if (intr_num || entry->tgt_sfunc || pasid || entry->stag ||
		    entry->rkey)
			return -EINVAL;
		return 0;
	}

	if (entry->tgt_sfunc || !(intr_num & SDXI_AKEY_ENT_PV) ||
	    intr_num & SDXI_AKEY_ENT_STE)
		return -EPERM;
	if (FIELD_GET(SDXI_AKEY_ENT_PASID, pasid) != cxt->pasid ||
	    pasid & (SDXI_AKEY_ENT_PR | SDXI_AKEY_ENT_PH))
		return -EPERM;
	if (entry->stag || entry->rkey)
		return -EPERM;
	if (!(intr_num & SDXI_AKEY_ENT_IV) &&
	    FIELD_GET(SDXI_AKEY_ENT_INTR_NUM, intr_num))
		return -EINVAL;

	return 0;
}

static bool sdxi_akey_driver_owned(const struct sdxi_cxt *cxt, u32 index)
{
	u16 intr_akey = READ_ONCE(cxt->intr_akey);

	return index < 2 || (intr_akey && index == intr_akey);
}

static int sdxi_akey_validate_interrupt(const struct sdxi_cxt *cxt,
					const struct sdxi_akey_ent *entry)
{
	u16 intr_num = le16_to_cpu(entry->intr_num);

	if (!(intr_num & SDXI_AKEY_ENT_IV))
		return 0;
	if (!sdxi_cxt_has_intr_fd(cxt))
		return -ENOTCONN;
	if (FIELD_GET(SDXI_AKEY_ENT_INTR_NUM, intr_num) != cxt->intr_vector)
		return -EINVAL;

	return 0;
}

static void sdxi_akey_store(struct sdxi_akey_ent *destination,
			    const struct sdxi_akey_ent *source)
{
	struct sdxi_akey_ent entry = *source;
	u16 intr_num = le16_to_cpu(source->intr_num);

	entry.intr_num = cpu_to_le16(intr_num & ~SDXI_AKEY_ENT_VL);
	WRITE_ONCE(destination->intr_num, 0);
	dma_wmb();
	memcpy(destination, &entry, sizeof(entry));
	dma_wmb();
	WRITE_ONCE(destination->intr_num, source->intr_num);
}

int sdxi_keys_init(struct sdxi_dev *sdxi, u64 cap1)
{
	size_t table_size;
	u64 reg;

	sdxi->rkey_cap = FIELD_GET(SDXI_MMIO_CAP1_RKEY_CAP, cap1);
	if (!sdxi->rkey_cap)
		return 0;

	sdxi->rkey_order = 0;
	table_size = SZ_4K << sdxi->rkey_order;
	sdxi->rkey_entries = table_size / sizeof(*sdxi->rkey_table);

	sdxi->rkey_table = dmam_alloc_coherent(sdxi->dev, table_size,
					       &sdxi->rkey_table_dma,
					       GFP_KERNEL);
	if (!sdxi->rkey_table)
		return -ENOMEM;
	memset(sdxi->rkey_table, 0, table_size);

	reg = FIELD_PREP(SDXI_MMIO_RKEY_PTR,
			 sdxi->rkey_table_dma >> ilog2(SZ_4K)) |
	      FIELD_PREP(SDXI_MMIO_RKEY_SZ, sdxi->rkey_order) |
	      SDXI_MMIO_RKEY_EN;
	sdxi_write64(sdxi, SDXI_MMIO_RKEY, reg);

	return 0;
}

void sdxi_keys_exit(struct sdxi_dev *sdxi)
{
	if (!sdxi->rkey_cap)
		return;

	sdxi_write64(sdxi, SDXI_MMIO_RKEY, 0);
	sdxi->rkey_table = NULL;
	sdxi->rkey_table_dma = 0;
	sdxi->rkey_entries = 0;
	sdxi->rkey_order = 0;
	sdxi->rkey_cap = false;
}

void sdxi_keys_resume(struct sdxi_dev *sdxi)
{
	u64 reg;

	if (!sdxi->rkey_cap || !sdxi->rkey_table)
		return;

	reg = FIELD_PREP(SDXI_MMIO_RKEY_PTR,
			 sdxi->rkey_table_dma >> ilog2(SZ_4K)) |
	      FIELD_PREP(SDXI_MMIO_RKEY_SZ, sdxi->rkey_order) |
	      SDXI_MMIO_RKEY_EN;
	sdxi_write64(sdxi, SDXI_MMIO_RKEY, reg);
}

int sdxi_ioctl_get_rkey_list(struct file *file, struct sdxi_file *sf,
			     void *data)
{
	struct sdxi_key_list_args *args = data;
	struct sdxi_dev *sdxi = sf->process->sdxi;
	int ret;

	ret = sdxi_key_args_check(args->argsz, sizeof(*args), args->flags,
				  &args->rsvd0, 1);
	if (ret)
		return ret;
	if (!sdxi->rkey_cap)
		return -EOPNOTSUPP;
	if (!sdxi->rkey_table)
		return -ENODEV;

	mutex_lock(&sdxi->rkey_lock);
	ret = sdxi_key_list_fill(args, sdxi->rkey_table,
				 sdxi->rkey_entries,
				 sizeof(*sdxi->rkey_table));
	mutex_unlock(&sdxi->rkey_lock);
	return ret;
}

int sdxi_ioctl_get_rkeys(struct file *file, struct sdxi_file *sf, void *data)
{
	struct sdxi_get_keys_args *args = data;
	struct sdxi_dev *sdxi = sf->process->sdxi;
	u32 i;
	int ret;

	ret = sdxi_key_args_check(args->argsz, sizeof(*args), args->flags,
				  &args->rsvd0, 1);
	if (ret)
		return ret;
	if (!sdxi->rkey_cap)
		return -EOPNOTSUPP;
	if (!sdxi->rkey_table)
		return -ENODEV;
	if (args->nkeys > sdxi->rkey_entries)
		return -EINVAL;

	ret = sdxi_key_check_indices(args->entries, args->nkeys,
				     sdxi->rkey_entries, NULL, NULL);
	if (ret)
		return ret;

	args->argsz = sizeof(*args);
	mutex_lock(&sdxi->rkey_lock);
	for (i = 0; i < args->nkeys; i++)
		memcpy(args->entries[i].data,
		       &sdxi->rkey_table[args->entries[i].index],
		       sizeof(args->entries[i].data));
	mutex_unlock(&sdxi->rkey_lock);

	return 0;
}

int sdxi_ioctl_set_rkeys(struct file *file, struct sdxi_file *sf, void *data)
{
	struct sdxi_set_keys_args *args = data;
	struct sdxi_dev *sdxi = sf->process->sdxi;
	u16 first;
	u16 last;
	u32 i;
	int ret;

	ret = sdxi_key_args_check(args->argsz, sizeof(*args), args->flags,
				  args->rsvd0, ARRAY_SIZE(args->rsvd0));
	if (ret)
		return ret;

	args->argsz = sizeof(*args);
	sdxi_set_keys_init(args);

	if (!sdxi->rkey_cap)
		return -EOPNOTSUPP;
	if (!sdxi->rkey_table)
		return -ENODEV;
	if (!args->nkeys) {
		args->commit_state = SDXI_KEY_COMMIT_ALL;
		return 0;
	}
	if (args->nkeys > sdxi->rkey_entries)
		return -EINVAL;

	ret = sdxi_key_check_indices(args->entries, args->nkeys,
				     sdxi->rkey_entries, &first, &last);
	if (ret)
		return ret;

	mutex_lock(&sdxi->rkey_lock);
	for (i = 0; i < args->nkeys; i++) {
		struct sdxi_rkey_ent entry;

		memcpy(&entry, args->entries[i].data, sizeof(entry));
		ret = sdxi_rkey_validate(&entry);
		if (ret)
			goto out_unlock;
	}

	for (i = 0; i < args->nkeys; i++) {
		struct sdxi_rkey_ent entry;

		memcpy(&entry, args->entries[i].data, sizeof(entry));
		sdxi_rkey_store(&sdxi->rkey_table[args->entries[i].index],
				&entry);
	}
	dma_wmb();

	ret = sdxi_adm_rkey_update_sync(sdxi, first, last,
					sdxi_set_keys_timeout(args), NULL);
	if (ret) {
		args->commit_state = SDXI_KEY_COMMIT_PARTIAL;
		goto out_unlock;
	}

	args->commit_state = SDXI_KEY_COMMIT_ALL;
out_unlock:
	mutex_unlock(&sdxi->rkey_lock);
	return ret;
}

int sdxi_ioctl_get_akey_list(struct file *file, struct sdxi_file *sf,
			     void *data)
{
	struct sdxi_key_list_args *args = data;
	struct sdxi_cxt *cxt = sf->cxt;
	int ret;

	ret = sdxi_key_args_check(args->argsz, sizeof(*args), args->flags,
				  &args->rsvd0, 1);
	if (ret)
		return ret;
	if (!cxt || sdxi_cxt_is_fatal(cxt))
		return -ENODEV;

	mutex_lock(&cxt->akey_lock);
	if (!cxt->akey_table) {
		ret = -ENODEV;
		goto out_unlock;
	}
	ret = sdxi_key_list_fill(args, cxt->akey_table,
				 ARRAY_SIZE(cxt->akey_table->entry),
				 sizeof(cxt->akey_table->entry[0]));
out_unlock:
	mutex_unlock(&cxt->akey_lock);
	return ret;
}

int sdxi_ioctl_get_akeys(struct file *file, struct sdxi_file *sf, void *data)
{
	struct sdxi_get_keys_args *args = data;
	struct sdxi_cxt *cxt = sf->cxt;
	u32 entries;
	u32 i;
	int ret;

	ret = sdxi_key_args_check(args->argsz, sizeof(*args), args->flags,
				  &args->rsvd0, 1);
	if (ret)
		return ret;
	if (!cxt || sdxi_cxt_is_fatal(cxt))
		return -ENODEV;

	entries = ARRAY_SIZE(cxt->akey_table->entry);
	if (args->nkeys > entries)
		return -EINVAL;
	ret = sdxi_key_check_indices(args->entries, args->nkeys, entries,
				     NULL, NULL);
	if (ret)
		return ret;

	args->argsz = sizeof(*args);
	mutex_lock(&cxt->akey_lock);
	if (!cxt->akey_table) {
		ret = -ENODEV;
		goto out_unlock;
	}
	for (i = 0; i < args->nkeys; i++)
		memcpy(args->entries[i].data,
		       &cxt->akey_table->entry[args->entries[i].index],
		       sizeof(args->entries[i].data));
	ret = 0;
out_unlock:
	mutex_unlock(&cxt->akey_lock);
	return ret;
}

int sdxi_ioctl_set_akeys(struct file *file, struct sdxi_file *sf, void *data)
{
	struct sdxi_set_keys_args *args = data;
	struct sdxi_cxt *cxt = sf->cxt;
	u32 entries;
	u16 first;
	u16 last;
	u32 i;
	int ret;

	ret = sdxi_key_args_check(args->argsz, sizeof(*args), args->flags,
				  args->rsvd0, ARRAY_SIZE(args->rsvd0));
	if (ret)
		return ret;

	args->argsz = sizeof(*args);
	sdxi_set_keys_init(args);

	if (!cxt || sdxi_cxt_is_fatal(cxt))
		return -ENODEV;
	entries = ARRAY_SIZE(cxt->akey_table->entry);
	if (!args->nkeys) {
		args->commit_state = SDXI_KEY_COMMIT_ALL;
		return 0;
	}
	if (args->nkeys > entries)
		return -EINVAL;

	ret = sdxi_key_check_indices(args->entries, args->nkeys, entries,
				     &first, &last);
	if (ret)
		return ret;

	mutex_lock(&cxt->akey_lock);
	if (!cxt->akey_table) {
		ret = -ENODEV;
		goto out_unlock;
	}

	for (i = 0; i < args->nkeys; i++) {
		struct sdxi_akey_ent entry;

		if (sdxi_akey_driver_owned(cxt, args->entries[i].index)) {
			ret = -EPERM;
			goto out_unlock;
		}

		memcpy(&entry, args->entries[i].data, sizeof(entry));
		ret = sdxi_akey_validate(&entry);
		if (ret)
			goto out_unlock;
		if (!capable(CAP_SYS_ADMIN)) {
			ret = sdxi_akey_validate_user(cxt, &entry);
			if (ret)
				goto out_unlock;
		}
		ret = sdxi_akey_validate_interrupt(cxt, &entry);
		if (ret)
			goto out_unlock;
	}

	for (i = 0; i < args->nkeys; i++) {
		struct sdxi_akey_ent entry;

		memcpy(&entry, args->entries[i].data, sizeof(entry));
		sdxi_akey_store(&cxt->akey_table->entry[args->entries[i].index],
				&entry);
	}
	dma_wmb();

	ret = sdxi_adm_akey_update_sync(cxt->sdxi, cxt->id, cxt->id,
					first, last,
					sdxi_set_keys_timeout(args), NULL);
	if (ret) {
		args->commit_state = SDXI_KEY_COMMIT_PARTIAL;
		goto out_unlock;
	}

	args->commit_state = SDXI_KEY_COMMIT_ALL;
out_unlock:
	mutex_unlock(&cxt->akey_lock);
	return ret;
}
