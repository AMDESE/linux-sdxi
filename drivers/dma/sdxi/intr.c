// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI userspace context interrupt routing.
 *
 * Copyright Advanced Micro Devices, Inc.
 */

#include <linux/bitfield.h>
#include <linux/dma-mapping.h>
#include <linux/eventfd.h>
#include <linux/interrupt.h>
#include <linux/string.h>

#include "admin.h"
#include "context.h"
#include "hw.h"
#include "intr.h"
#include "sdxi.h"

#define SDXI_UCXT_DEFAULT_AKEY		1
#define SDXI_INTR_UPDATE_TIMEOUT_MS	5000U

static int sdxi_cxt_alloc_intr_akey(struct sdxi_cxt *cxt, u16 *akey)
{
	u32 index;

	for (index = SDXI_UCXT_DEFAULT_AKEY + 1;
	     index < ARRAY_SIZE(cxt->akey_table->entry); index++) {
		u16 intr = le16_to_cpu(cxt->akey_table->entry[index].intr_num);

		if (!(intr & SDXI_AKEY_ENT_VL)) {
			*akey = index;
			return 0;
		}
	}

	return -ENOSPC;
}

static void sdxi_cxt_clear_intr_akey(struct sdxi_cxt *cxt, u16 akey)
{
	struct sdxi_akey_ent *entry;

	if (!cxt->akey_table || !akey ||
	    akey >= ARRAY_SIZE(cxt->akey_table->entry))
		return;

	entry = &cxt->akey_table->entry[akey];
	WRITE_ONCE(entry->intr_num, 0);
	dma_wmb();
	memset(entry, 0, sizeof(*entry));
	dma_wmb();
}

static void sdxi_cxt_arm_intr_akey(struct sdxi_cxt *cxt, u16 akey)
{
	struct sdxi_akey_ent *entry = &cxt->akey_table->entry[akey];
	u32 pasid = FIELD_PREP(SDXI_AKEY_ENT_PASID, cxt->pasid);
	u16 intr;

	intr = SDXI_AKEY_ENT_VL |
	       SDXI_AKEY_ENT_IV |
	       FIELD_PREP(SDXI_AKEY_ENT_PV, cxt->pasid_valid) |
	       FIELD_PREP(SDXI_AKEY_ENT_INTR_NUM, cxt->intr_vector);

	memset(entry, 0, sizeof(*entry));
	entry->pasid = cpu_to_le32(pasid);
	dma_wmb();
	WRITE_ONCE(entry->intr_num, cpu_to_le16(intr));
}

static irqreturn_t sdxi_cxt_irq_handler(int irq, void *data)
{
	struct sdxi_cxt *cxt = data;
	struct eventfd_ctx *eventfd;
	unsigned long flags;
	bool armed;

	spin_lock_irqsave(&cxt->intr_lock, flags);
	eventfd = cxt->intr_eventfd;
	armed = cxt->intr_armed;
	if (eventfd)
		eventfd_signal(eventfd);
	spin_unlock_irqrestore(&cxt->intr_lock, flags);

	if (!eventfd && armed) {
		dev_err(cxt->sdxi->dev,
			"context %u interrupt without eventfd\n", cxt->id);
		sdxi_cxt_kill(cxt);
	}

	return IRQ_HANDLED;
}

bool sdxi_cxt_has_intr_fd(const struct sdxi_cxt *cxt)
{
	return cxt && READ_ONCE(cxt->intr_eventfd);
}

int sdxi_cxt_init_intr(struct sdxi_cxt *cxt)
{
	int vector;
	int irq;
	int ret;

	if (!cxt || !cxt->akey_table || !cxt->id)
		return -EINVAL;
	if (cxt->intr_vector >= 0)
		return 0;

	vector = sdxi_alloc_vector(cxt->sdxi);
	if (vector < 0)
		return vector;
	if (!FIELD_FIT(SDXI_AKEY_ENT_INTR_NUM, vector)) {
		ret = -ENOSPC;
		goto free_vector;
	}

	irq = sdxi_vector_to_irq(cxt->sdxi, vector);
	if (irq < 0) {
		ret = irq;
		goto free_vector;
	}

	ret = request_irq(irq, sdxi_cxt_irq_handler, IRQF_TRIGGER_NONE,
			  "sdxi-context", cxt);
	if (ret)
		goto free_vector;

	cxt->intr_vector = vector;
	cxt->intr_irq = irq;
	return 0;

free_vector:
	sdxi_free_vector(cxt->sdxi, vector);
	return ret;
}

static int sdxi_cxt_clear_intr_fd(struct sdxi_cxt *cxt)
{
	struct eventfd_ctx *eventfd;
	unsigned long flags;
	u16 akey;
	int ret;

	mutex_lock(&cxt->akey_lock);
	if (!cxt->akey_table || cxt->intr_vector < 0 || cxt->intr_irq < 0) {
		ret = -ENODEV;
		goto out_unlock;
	}

	spin_lock_irqsave(&cxt->intr_lock, flags);
	akey = cxt->intr_akey;
	eventfd = cxt->intr_eventfd;
	spin_unlock_irqrestore(&cxt->intr_lock, flags);

	if (!akey) {
		ret = 0;
		goto out_unlock;
	}

	sdxi_cxt_clear_intr_akey(cxt, akey);
	ret = sdxi_adm_akey_update_sync(cxt->sdxi, cxt->id, cxt->id,
					akey, akey,
					SDXI_INTR_UPDATE_TIMEOUT_MS, NULL);
	if (ret) {
		sdxi_cxt_arm_intr_akey(cxt, akey);
		(void)sdxi_adm_akey_update_sync(cxt->sdxi, cxt->id, cxt->id,
						akey, akey,
						SDXI_INTR_UPDATE_TIMEOUT_MS,
						NULL);
		goto out_unlock;
	}

	spin_lock_irqsave(&cxt->intr_lock, flags);
	cxt->intr_armed = false;
	cxt->intr_akey = 0;
	cxt->intr_eventfd = NULL;
	spin_unlock_irqrestore(&cxt->intr_lock, flags);

out_unlock:
	mutex_unlock(&cxt->akey_lock);
	if (!ret && eventfd)
		eventfd_ctx_put(eventfd);
	return ret;
}

void sdxi_cxt_exit_intr(struct sdxi_cxt *cxt)
{
	struct eventfd_ctx *eventfd;
	unsigned long flags;
	int vector;
	int irq;
	u16 akey;

	if (!cxt)
		return;

	mutex_lock(&cxt->akey_lock);
	spin_lock_irqsave(&cxt->intr_lock, flags);
	akey = cxt->intr_akey;
	eventfd = cxt->intr_eventfd;
	cxt->intr_armed = false;
	cxt->intr_akey = 0;
	cxt->intr_eventfd = NULL;
	spin_unlock_irqrestore(&cxt->intr_lock, flags);
	sdxi_cxt_clear_intr_akey(cxt, akey);
	irq = cxt->intr_irq;
	vector = cxt->intr_vector;
	cxt->intr_irq = -1;
	cxt->intr_vector = -1;
	mutex_unlock(&cxt->akey_lock);

	if (eventfd)
		eventfd_ctx_put(eventfd);
	if (irq >= 0)
		free_irq(irq, cxt);
	if (vector >= 0)
		sdxi_free_vector(cxt->sdxi, vector);
}

int sdxi_cxt_set_intr_fd(struct sdxi_cxt *cxt, int eventfd_fd,
			 u16 *akey, u32 *intr_num)
{
	struct eventfd_ctx *old_eventfd;
	struct eventfd_ctx *eventfd;
	unsigned long flags;
	u16 old_akey;
	u16 intr_akey;
	bool old_armed;
	bool new_akey = false;
	bool published = false;
	int ret;

	if (!cxt || !cxt->akey_table)
		return -ENODEV;
	if (sdxi_cxt_is_fatal(cxt))
		return -ENODEV;
	if (cxt->intr_vector < 0 || cxt->intr_irq < 0)
		return -EOPNOTSUPP;

	if (eventfd_fd < 0) {
		ret = sdxi_cxt_clear_intr_fd(cxt);
		if (!ret) {
			if (akey)
				*akey = 0;
			if (intr_num)
				*intr_num = 0;
		}
		return ret;
	}

	eventfd = eventfd_ctx_fdget(eventfd_fd);
	if (IS_ERR(eventfd))
		return PTR_ERR(eventfd);

	mutex_lock(&cxt->akey_lock);
	if (!cxt->akey_table || cxt->intr_vector < 0 || cxt->intr_irq < 0 ||
	    sdxi_cxt_is_fatal(cxt)) {
		ret = -ENODEV;
		goto out_unlock;
	}

	spin_lock_irqsave(&cxt->intr_lock, flags);
	old_akey = cxt->intr_akey;
	intr_akey = old_akey;
	old_eventfd = cxt->intr_eventfd;
	old_armed = cxt->intr_armed;
	spin_unlock_irqrestore(&cxt->intr_lock, flags);

	if (!intr_akey) {
		ret = sdxi_cxt_alloc_intr_akey(cxt, &intr_akey);
		if (ret)
			goto out_unlock;
		new_akey = true;
	}

	spin_lock_irqsave(&cxt->intr_lock, flags);
	cxt->intr_eventfd = eventfd;
	cxt->intr_akey = intr_akey;
	cxt->intr_armed = true;
	spin_unlock_irqrestore(&cxt->intr_lock, flags);
	published = true;

	sdxi_cxt_arm_intr_akey(cxt, intr_akey);
	ret = sdxi_adm_akey_update_sync(cxt->sdxi, cxt->id, cxt->id,
					intr_akey, intr_akey,
					SDXI_INTR_UPDATE_TIMEOUT_MS, NULL);
	if (ret) {
		if (new_akey) {
			sdxi_cxt_clear_intr_akey(cxt, intr_akey);
			(void)sdxi_adm_akey_update_sync(cxt->sdxi,
							cxt->id, cxt->id,
							intr_akey, intr_akey,
							SDXI_INTR_UPDATE_TIMEOUT_MS,
							NULL);
		}
		spin_lock_irqsave(&cxt->intr_lock, flags);
		cxt->intr_eventfd = old_eventfd;
		cxt->intr_akey = old_akey;
		cxt->intr_armed = old_armed;
		spin_unlock_irqrestore(&cxt->intr_lock, flags);
		goto out_unlock;
	}
	mutex_unlock(&cxt->akey_lock);

	if (old_eventfd)
		eventfd_ctx_put(old_eventfd);
	if (akey)
		*akey = intr_akey;
	if (intr_num)
		*intr_num = cxt->intr_vector;
	return 0;

out_unlock:
	mutex_unlock(&cxt->akey_lock);
	if (!published || ret)
		eventfd_ctx_put(eventfd);
	return ret;
}
