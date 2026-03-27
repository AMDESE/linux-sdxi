/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright Advanced Micro Devices, Inc. */
#ifndef DMA_SDXI_RING_H
#define DMA_SDXI_RING_H

#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/range.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <asm/barrier.h>
#include <asm/byteorder.h>
#include <asm/div64.h>
#include <asm/rwonce.h>

#include "hw.h"

struct sdxi_sq;

/*
 * struct sdxi_ring_state - Software state for driving a submission queue.
 *
 * @lock: Guards the write index.
 * @sq: The submission queue being driven.
 * @wqh: Pending reservations.
 */
struct sdxi_ring_state {
	spinlock_t lock;
	struct sdxi_sq *sq;
	wait_queue_head_t wqh;
};

/*
 * Ring reservation and iteration state.
 */
struct sdxi_ring_resv {
	const struct sdxi_ring_state *rs;
	struct range range;
	u64 iter;
};

void sdxi_ring_state_init(struct sdxi_ring_state *ring, struct sdxi_sq *sq);
void sdxi_ring_wake_up(struct sdxi_ring_state *rs);
int sdxi_ring_reserve(struct sdxi_ring_state *ring, size_t nr,
		      struct sdxi_ring_resv *resv);
int sdxi_ring_try_reserve(struct sdxi_ring_state *ring, size_t nr,
			  struct sdxi_ring_resv *resv);
struct sdxi_desc *sdxi_ring_resv_next(struct sdxi_ring_resv *resv);

/* Reset reservation's internal iterator. */
static inline void sdxi_ring_resv_reset(struct sdxi_ring_resv *resv)
{
	resv->iter = resv->range.start;
}

/*
 * Return the value that should be written to the doorbell after
 * serializing descriptors for this reservation, i.e. the value of the
 * write index after obtaining the reservation.
 */
static inline u64 sdxi_ring_resv_dbval(const struct sdxi_ring_resv *resv)
{
	return resv->range.end + 1;
}

#define sdxi_ring_resv_foreach(resv_, desc_)                            \
	for (typeof(resv_) resv__ = (resv_); resv__; resv__ = NULL)     \
		for (sdxi_ring_resv_reset(resv__),                      \
		     desc_ = sdxi_ring_resv_next(resv__);               \
		     desc_;                                             \
		     desc_ = sdxi_ring_resv_next(resv__))

#endif /* DMA_SDXI_RING_H */
