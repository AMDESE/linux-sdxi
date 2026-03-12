// SPDX-License-Identifier: GPL-2.0-only
#include <linux/cleanup.h>
#include <linux/kernel.h>
#include <linux/processor.h>
#include <asm/rwonce.h>

#include "admin.h"
#include "completion.h"
#include "context.h"
#include "descriptor.h"
#include "ring.h"
#include "sdxi.h"

int sdxi_adm_start_cxt(struct sdxi_cxt *cxt)
{
	struct sdxi_cxt *adm = to_admin_cxt(cxt);
	struct sdxi_desc *desc;
	struct sdxi_ring_resv resv;
	int err;

	might_sleep();

	struct sdxi_completion *sc __free(sdxi_completion) =
		sdxi_completion_alloc(cxt->sdxi);

	/* This is not how to start the admin context. */
	if (WARN_ON(adm == cxt))
		return -EINVAL;

	err = sdxi_ring_reserve(adm->ring_state, 1, &resv);
	if (err)
		return err;

	desc = sdxi_ring_resv_next(&resv);
	sdxi_encode_cxt_start(desc, &(const struct sdxi_cxt_start) {
			.range = sdxi_cxt_range(cxt->id),
		});
	sdxi_completion_attach(desc, sc);
	sdxi_desc_make_valid(desc);
	sdxi_cxt_push_doorbell(adm, sdxi_ring_resv_dbval(&resv));
	sdxi_completion_poll(sc);

	return 0;
}

void sdxi_adm_stop_cxt(struct sdxi_cxt *cxt)
{
	struct sdxi_cxt *adm = to_admin_cxt(cxt);
	struct sdxi_desc *stop, *sync;
	struct sdxi_ring_resv resv;
	int err;

	might_sleep();

	struct sdxi_completion *sc __free(sdxi_completion) =
		sdxi_completion_alloc(cxt->sdxi);

	/* This is not how to stop the admin context. */
	if (WARN_ON(adm == cxt))
		return;

	err = sdxi_ring_reserve(adm->ring_state, 2, &resv);
	if (WARN_ON_ONCE(err))
		return;

	stop = sdxi_ring_resv_next(&resv);
	sync = sdxi_ring_resv_next(&resv);

	sdxi_encode_cxt_stop(stop, &(const struct sdxi_cxt_stop) {
			.range = sdxi_cxt_range(cxt->id),
		});
	sdxi_encode_sync(sync, &(const struct sdxi_sync) {
			.filter = SDXI_SYNC_FLT_STOP,
			.range = sdxi_cxt_range(cxt->id),
		});
	sdxi_completion_attach(sync, sc);
	sdxi_desc_make_valid(stop);
	sdxi_desc_make_valid(sync);
	sdxi_cxt_push_doorbell(adm, sdxi_ring_resv_dbval(&resv));
	sdxi_completion_poll(sc);
}
