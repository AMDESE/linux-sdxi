// SPDX-License-Identifier: GPL-2.0-only
/*
 * SDXI descriptor ring state management. Handles advancing the write
 * index correctly and supplies "reservations" i.e. slices of the ring
 * to be filled with descriptors.
 *
 * Copyright Advanced Micro Devices, Inc.
 */
#include <kunit/test-bug.h>
#include <kunit/visibility.h>
#include <linux/io-64-nonatomic-lo-hi.h>
#include <linux/jiffies.h>
#include <linux/lockdep.h>
#include <linux/range.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <asm/barrier.h>
#include <asm/byteorder.h>
#include <asm/div64.h>
#include <asm/rwonce.h>

#include "ring.h"
#include "hw.h"
#include "submission.h"

/*
 * Initialize ring management state from a submission queue. Caller is
 * responsible for allocating and initializing @sq.
 */
void sdxi_ring_state_init(struct sdxi_ring_state *rs, struct sdxi_sq *sq)
{
	WARN_ON_ONCE(!sq);
	/*
	 * See SDXI 1.0 Table 3-1 Memory Structure Summary. Minimum
	 * descriptor ring size in bytes is 64KB; thus 1024 64-byte
	 * entries.
	 */
	WARN_ON_ONCE(sq->count < SZ_1K);

	*rs = (typeof(*rs)) {
		.sq = sq,
	};
	spin_lock_init(&rs->lock);
	init_waitqueue_head(&rs->wqh);
}
EXPORT_SYMBOL_IF_KUNIT(sdxi_ring_state_init);

/* Non-blocking ring reservation. Callers must handle ring full (-EBUSY). */
int sdxi_ring_try_reserve(struct sdxi_ring_state *rs, size_t nr,
			  struct sdxi_ring_resv *resv)
{
	struct sdxi_sq *sq = rs->sq;
	u64 ridx, new_widx;

	/*
	 * Caller bug, warn and reject.
	 */
	if (nr < 1 || nr > sq->count) {
		WARN_ONCE(!kunit_get_current_test(),
			  "Reservation of size %zu requested from ring of size %u\n",
			  nr, sq->count);
		return -EINVAL;
	}

	/*
	 * The read index is read-only for us and incremented by the
	 * device. Ensure no torn reads.
	 */
	ridx = le64_to_cpu(READ_ONCE(sq->cxt_sts.read_index));

	scoped_guard(spinlock_irqsave, &rs->lock) {
		u64 widx = le64_to_cpu(sq->write_index);
		/*
		 * Bug: the read index should never exceed the write index.
		 * TODO: sdxi_err() or similar; need a reference to
		 * the device.
		 */
		if (ridx > widx)
			return -EIO;

		new_widx = widx + nr;

		/*
		 * Not enough space available right now.
		 * TODO: sdxi_dbg() or tracepoint here.
		 */
		if (new_widx - ridx > sq->count)
			return -EBUSY;

		WRITE_ONCE(sq->write_index, cpu_to_le64(new_widx));
	}

	*resv = (typeof(*resv)) {
		.rs = rs,
		.range = {
			.start = new_widx - nr,
			.end = new_widx - 1,
		},
	};

	return 0;
}
EXPORT_SYMBOL_IF_KUNIT(sdxi_ring_try_reserve);

/* Blocking ring reservation. Retries until success or non-transient error. */
int sdxi_ring_reserve(struct sdxi_ring_state *rs, size_t nr,
		      struct sdxi_ring_resv *resv)
{
	int ret, left;

	left = wait_event_killable_timeout(rs->wqh,
					   (ret = sdxi_ring_try_reserve(rs, nr, resv)) != -EBUSY,
					   HZ);

	/* success or hard error from try_reserve() */
	if (left > 0)
		return ret;

	/* timed out */
	if (left == 0)
		return -ETIMEDOUT;

	/* killed: -ERESTARTSYS */
	return left;
}

/* Completion code should call this whenever descriptors have been consumed. */
void sdxi_ring_wake_up(struct sdxi_ring_state *rs)
{
	wake_up_all(&rs->wqh);
}

/*
 * Map a logical (unwrapped) ring index onto its entry. The ring size is
 * not constrained to a power of two, hence the division.
 */
struct sdxi_desc *sdxi_ring_desc(const struct sdxi_ring_state *rs, u64 index)
{
	struct sdxi_sq *sq = rs->sq;

	return &sq->ring[do_div(index, sq->count)];
}
EXPORT_SYMBOL_IF_KUNIT(sdxi_ring_desc);
