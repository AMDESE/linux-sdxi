// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI vendor operation handler registry.
 *
 * Copyright Advanced Micro Devices, Inc.
 */

#include <linux/dma-mapping.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/string.h>

#include "admin.h"
#include "sdxi.h"
#include "vendor.h"

static LIST_HEAD(sdxi_vendor_handlers);
static DEFINE_MUTEX(sdxi_vendor_lock);

int sdxi_vendor_register(struct sdxi_vendor_handler *handler)
{
	struct sdxi_vendor_handler *iter;
	int ret = 0;

	if (!handler || !handler->name || !handler->guid || !handler->ops ||
	    !handler->ops->authorize || !handler->ops->exec)
		return -EINVAL;

	if (!handler->entry.next)
		INIT_LIST_HEAD(&handler->entry);

	mutex_lock(&sdxi_vendor_lock);
	if (!list_empty(&handler->entry)) {
		ret = -EBUSY;
		goto out_unlock;
	}

	list_for_each_entry(iter, &sdxi_vendor_handlers, entry) {
		if (!memcmp(iter->guid, handler->guid, 16)) {
			ret = -EEXIST;
			goto out_unlock;
		}
	}

	list_add_tail(&handler->entry, &sdxi_vendor_handlers);

out_unlock:
	mutex_unlock(&sdxi_vendor_lock);
	return ret;
}
EXPORT_SYMBOL_NS_GPL(sdxi_vendor_register, "SDXI");

void sdxi_vendor_unregister(struct sdxi_vendor_handler *handler)
{
	if (!handler)
		return;
	if (!handler->entry.next)
		INIT_LIST_HEAD(&handler->entry);

	mutex_lock(&sdxi_vendor_lock);
	if (!list_empty(&handler->entry))
		list_del_init(&handler->entry);
	mutex_unlock(&sdxi_vendor_lock);
}
EXPORT_SYMBOL_NS_GPL(sdxi_vendor_unregister, "SDXI");

int sdxi_vendor_get(const u8 guid[16],
		    const struct sdxi_vendor_handler **handler_out)
{
	const struct sdxi_vendor_handler *handler;
	int ret = -EOPNOTSUPP;

	if (!guid || !handler_out)
		return -EINVAL;

	mutex_lock(&sdxi_vendor_lock);
	list_for_each_entry(handler, &sdxi_vendor_handlers, entry) {
		if (memcmp(handler->guid, guid, 16))
			continue;
		if (!try_module_get(handler->owner))
			break;

		*handler_out = handler;
		ret = 0;
		break;
	}
	mutex_unlock(&sdxi_vendor_lock);

	return ret;
}

void sdxi_vendor_put(const struct sdxi_vendor_handler *handler)
{
	if (handler)
		module_put(handler->owner);
}

int sdxi_vendor_find_opcode_type(struct sdxi_dev *sdxi, const u8 guid[16],
				 unsigned int timeout_ms, u16 *opcode_type)
{
	const u16 first = 1;
	const u16 last = 2047;
	const size_t record_size = 16;
	const size_t size = (last - first + 1) * record_size;
	dma_addr_t dma;
	u8 *records;
	u16 index;
	int ret;

	if (!sdxi || !guid || !opcode_type)
		return -EINVAL;
	if (!sdxi_dev_compatible(sdxi, SDXI_VERSION_1_1))
		return -EOPNOTSUPP;

	records = dma_alloc_coherent(sdxi->dev, size, &dma, GFP_KERNEL);
	if (!records)
		return -ENOMEM;

	ret = sdxi_adm_disc(sdxi, first, last, dma, timeout_ms, NULL);
	if (ret)
		goto free_records;

	dma_rmb();
	for (index = first; index <= last; index++) {
		const u8 *record = records + (index - first) * record_size;

		if (!memcmp(record, guid, record_size)) {
			*opcode_type = index;
			ret = 0;
			goto free_records;
		}
	}
	ret = -EOPNOTSUPP;

free_records:
	dma_free_coherent(sdxi->dev, size, records, dma);
	return ret;
}
