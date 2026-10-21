// SPDX-License-Identifier: GPL-2.0-only
/* Copyright Advanced Micro Devices, Inc. */
#include <kunit/device.h>
#include <kunit/test.h>
#include <linux/bitfield.h>
#include <linux/module.h>

#include "completion.h"
#include "context.h"
#include "dma.h"

MODULE_IMPORT_NS("EXPORTED_FOR_KUNIT_TESTING");

struct dma_fixture {
	struct sdxi_dma_chan chan;
	struct sdxi_cxt cxt;
	struct sdxi_ring_state ring;
	struct dma_device dma_dev;
	atomic_t callbacks;
};

/* KUnit owns the txds; virt-dma still invokes their callbacks normally. */
static void txd_free(struct virt_dma_desc *vdesc)
{
}

static int setup(struct kunit *t)
{
	struct dma_fixture *f;
	struct sdxi_sq *sq;
	struct sdxi_cq *cq;

	f = kunit_kzalloc(t, sizeof(*f), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(t, f);
	sq = kunit_kzalloc(t, struct_size(sq, ring, SZ_1K), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(t, sq);
	cq = kunit_kzalloc(t, struct_size(cq, entry, SZ_1K), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(t, cq);
	f->cxt.akey_table = kunit_kzalloc(t, sizeof(*f->cxt.akey_table), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(t, f->cxt.akey_table);

	sq->count = cq->count = SZ_1K;
	f->cxt.sq = sq;
	f->cxt.cq = cq;
	f->cxt.ring_state = &f->ring;
	f->chan.cxt = &f->cxt;
	f->chan.akey = &f->cxt.akey_table->entry[0];
	sdxi_ring_state_init(&f->ring, sq);
	sdxi_ring_track_retirement(&f->ring);

	f->dma_dev.dev = kunit_device_register(t, "sdxi-dma-test");
	KUNIT_ASSERT_NOT_ERR_OR_NULL(t, f->dma_dev.dev);
	INIT_LIST_HEAD(&f->dma_dev.channels);
	f->chan.vchan.desc_free = txd_free;
	vchan_init(&f->chan.vchan, &f->dma_dev);
	INIT_LIST_HEAD(&f->chan.pending);
	t->priv = f;
	return 0;
}

static void teardown(struct kunit *t)
{
	struct dma_fixture *f = t->priv;

	vchan_synchronize(&f->chan.vchan);
}

static struct sdxi_dma_txd *queue_copy(struct kunit *t, unsigned long flags)
{
	struct dma_fixture *f = t->priv;
	struct sdxi_dma_txd *txd;
	struct dma_async_tx_descriptor *tx;

	txd = kunit_kzalloc(t, sizeof(*txd), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(t, txd);
	txd->copy = (struct sdxi_copy) { .src = 0x1000, .dst = 0x2000, .len = 64 };
	tx = vchan_tx_prep(&f->chan.vchan, &txd->vdesc, flags);
	tx->tx_submit(tx);
	return txd;
}

static bool issue(struct dma_fixture *f)
{
	guard(spinlock_irqsave)(&f->chan.vchan.lock);

	list_splice_tail_init(&f->chan.vchan.desc_submitted, &f->chan.pending);
	return sdxi_dma_drain_locked(&f->chan);
}

static void reap(struct dma_fixture *f)
{
	guard(spinlock_irqsave)(&f->chan.vchan.lock);

	sdxi_dma_reap_locked(&f->chan);
}

static void expect_slot(struct kunit *t, u64 index, bool interrupt)
{
	struct dma_fixture *f = t->priv;
	struct sdxi_desc *desc = sdxi_ring_desc(&f->ring, index);
	u32 opcode = le32_to_cpu(desc->opcode);

	KUNIT_EXPECT_EQ(t, FIELD_GET(SDXI_DSC_TYPE, opcode),
			interrupt ? SDXI_DSC_OP_TYPE_INTR : SDXI_DSC_OP_TYPE_DMAB);
	KUNIT_EXPECT_EQ(t, FIELD_GET(SDXI_DSC_SUBTYPE, opcode),
			interrupt ? SDXI_DSC_OP_SUBTYPE_INTR : SDXI_DSC_OP_SUBTYPE_COPY);
	KUNIT_EXPECT_EQ(t, !!(opcode & SDXI_DSC_FE), interrupt);
	KUNIT_EXPECT_TRUE(t, opcode & SDXI_DSC_VL);
	KUNIT_EXPECT_FALSE(t, opcode & SDXI_DSC_SE);
	KUNIT_EXPECT_EQ(t, !!(opcode & SDXI_DSC_CSR), !interrupt);
}

/* Two slots must make progress even with a much larger selected prefix. */
static void capacity(struct kunit *t)
{
	struct dma_fixture *f = t->priv;
	struct sdxi_sq *sq = f->cxt.sq;
	struct sdxi_dma_txd *txd[6];
	u64 start = sq->count - 2;

	sq->write_index = cpu_to_le64(start);
	for (int i = 0; i < ARRAY_SIZE(txd); i++)
		txd[i] = queue_copy(t, i == 2 ? DMA_PREP_INTERRUPT : 0);
	issue(f);
	KUNIT_EXPECT_EQ(t, le64_to_cpu(sq->write_index), sq->count);
	KUNIT_EXPECT_NOT_NULL(t, txd[0]->cst);
	KUNIT_EXPECT_NULL(t, txd[1]->cst);
	KUNIT_EXPECT_EQ(t, txd[2]->vdesc.tx.flags, (unsigned long)DMA_PREP_INTERRUPT);
	expect_slot(t, start, false);
	expect_slot(t, start + 1, true);

	/* Hardware progress alone cannot release the paired completion. */
	sq->cxt_sts.read_index = sq->write_index;
	issue(f);
	KUNIT_EXPECT_NULL(t, txd[1]->cst);
	txd[0]->cst->signal = cpu_to_le64(SDXI_CST_BLK_SIGNAL_TERMINAL);
	reap(f);
	KUNIT_EXPECT_EQ(t, f->ring.retire_index, sq->count);

	/* Another capacity cut still stops before the flag. */
	sq->write_index = cpu_to_le64(2 * sq->count - 2);
	issue(f);
	KUNIT_EXPECT_EQ(t, txd[1]->copy_index, 2 * sq->count - 2);
	KUNIT_EXPECT_NULL(t, txd[2]->cst);
	KUNIT_EXPECT_EQ(t, txd[2]->vdesc.tx.flags, (unsigned long)DMA_PREP_INTERRUPT);
	expect_slot(t, 2 * sq->count - 2, false);
	expect_slot(t, 2 * sq->count - 1, true);
}

static void flag_boundaries(struct kunit *t)
{
	const unsigned long flags[] = {
		0, DMA_PREP_INTERRUPT, DMA_PREP_FENCE,
		DMA_PREP_INTERRUPT | DMA_PREP_FENCE,
	};
	struct dma_fixture *f = t->priv;
	u64 start = 0;

	for (int i = 0; i < ARRAY_SIZE(flags); i++) {
		struct sdxi_dma_txd *a = queue_copy(t, 0);
		struct sdxi_dma_txd *b = queue_copy(t, flags[i]);
		struct sdxi_dma_txd *c = queue_copy(t, flags[i]);
		struct sdxi_dma_txd *d = queue_copy(t, 0);

		issue(f);
		KUNIT_EXPECT_EQ(t, a->copy_index, start);
		KUNIT_EXPECT_EQ(t, b->copy_index, start + 1);
		expect_slot(t, start, false);
		expect_slot(t, start + 1, false);
		if (flags[i]) {
			expect_slot(t, start + 2, true);
			KUNIT_EXPECT_EQ(t, c->copy_index, start + 3);
			expect_slot(t, start + 3, false);
			expect_slot(t, start + 4, true);
			KUNIT_EXPECT_EQ(t, d->copy_index, start + 5);
			expect_slot(t, start + 5, false);
			expect_slot(t, start + 6, true);
			start += 7;
		} else {
			KUNIT_EXPECT_EQ(t, c->copy_index, start + 2);
			KUNIT_EXPECT_EQ(t, d->copy_index, start + 3);
			expect_slot(t, start + 2, false);
			expect_slot(t, start + 3, false);
			expect_slot(t, start + 4, true);
			start += 5;
		}
		KUNIT_EXPECT_TRUE(t, list_empty(&f->chan.pending));
		KUNIT_EXPECT_EQ(t, le64_to_cpu(f->cxt.sq->write_index), start);
	}

	/* Separate issue calls always end their own batches. */
	queue_copy(t, DMA_PREP_FENCE);
	issue(f);
	expect_slot(t, start, false);
	expect_slot(t, start + 1, true);
	queue_copy(t, 0);
	issue(f);
	expect_slot(t, start + 2, false);
	expect_slot(t, start + 3, true);
}

static void exact_fit_and_leftover(struct kunit *t)
{
	struct dma_fixture *f = t->priv;
	struct sdxi_sq *sq = f->cxt.sq;
	struct sdxi_dma_txd *txd[6];
	u64 start = sq->count - 8;

	sq->write_index = cpu_to_le64(start);
	for (int i = 0; i < 6; i++)
		txd[i] = queue_copy(t, i == 1 ? DMA_PREP_INTERRUPT : 0);
	issue(f);
	KUNIT_EXPECT_EQ(t, le64_to_cpu(sq->write_index), sq->count);
	for (int i = 0; i < 8; i++)
		expect_slot(t, start + i, i == 2 || i == 7);
	KUNIT_EXPECT_TRUE(t, list_empty(&f->chan.pending));

	/* Consume the copies, then leave only three usable slots. */
	sq->cxt_sts.read_index = sq->write_index;
	for (int i = 0; i < ARRAY_SIZE(txd); i++)
		txd[i]->cst->signal = cpu_to_le64(SDXI_CST_BLK_SIGNAL_TERMINAL);
	reap(f);
	sq->write_index = cpu_to_le64(2 * sq->count - 3);
	queue_copy(t, DMA_PREP_FENCE);
	queue_copy(t, 0);
	issue(f);
	KUNIT_EXPECT_EQ(t, le64_to_cpu(sq->write_index), 2 * sq->count - 1);
	expect_slot(t, 2 * sq->count - 3, false);
	expect_slot(t, 2 * sq->count - 2, true);
	KUNIT_EXPECT_FALSE(t, list_empty(&f->chan.pending));
}

static void callback(void *param)
{
	atomic_inc(param);
}

static void ordered_completion(struct kunit *t)
{
	struct dma_fixture *f = t->priv;
	struct sdxi_dma_txd *a = queue_copy(t, 0);
	struct sdxi_dma_txd *b = queue_copy(t, DMA_PREP_INTERRUPT);
	struct sdxi_ring_resv resv;
	dma_cookie_t last_cookie = b->vdesc.tx.cookie;

	a->vdesc.tx.callback = b->vdesc.tx.callback = callback;
	a->vdesc.tx.callback_param = b->vdesc.tx.callback_param = &f->callbacks;
	issue(f);
	f->cxt.sq->cxt_sts.read_index = f->cxt.sq->write_index;
	b->cst->signal = cpu_to_le64(SDXI_CST_BLK_SIGNAL_TERMINAL);
	reap(f);
	KUNIT_EXPECT_EQ(t, f->ring.retire_index, 0);
	KUNIT_EXPECT_EQ(t, f->chan.vchan.chan.completed_cookie, 1);
	KUNIT_EXPECT_EQ(t, atomic_read(&f->callbacks), 0);
	KUNIT_EXPECT_EQ(t, sdxi_ring_try_reserve(&f->ring, SZ_1K - 2, &resv), -EBUSY);

	a->cst->flags = cpu_to_le32(SDXI_CST_BLK_ER);
	a->cst->signal = cpu_to_le64(SDXI_CST_BLK_SIGNAL_TERMINAL);
	reap(f);
	KUNIT_EXPECT_EQ(t, a->vdesc.tx_result.result, DMA_TRANS_ABORTED);
	KUNIT_EXPECT_EQ(t, f->ring.retire_index, 3);
	KUNIT_EXPECT_EQ(t, f->chan.vchan.chan.completed_cookie, last_cookie);
	vchan_synchronize(&f->chan.vchan);
	KUNIT_EXPECT_EQ(t, atomic_read(&f->callbacks), 2);
	KUNIT_EXPECT_EQ(t, sdxi_ring_try_reserve(&f->ring, SZ_1K, &resv), 0);
}

/* A timed-out synchronization remains pinned across later issue calls. */
static void synchronization_retirement(struct kunit *t)
{
	struct dma_fixture *f = t->priv;
	struct sdxi_dma_txd *before = queue_copy(t, 0);
	struct sdxi_dma_txd *after;
	struct sdxi_ring_resv resv;
	struct sdxi_slot nop;
	dma_cookie_t before_cookie = before->vdesc.tx.cookie, after_cookie;

	issue(f);
	KUNIT_ASSERT_EQ(t, sdxi_ring_try_reserve(&f->ring, 1, &resv), 0);
	nop = sdxi_ring_resv_slot(&resv, 0);
	sdxi_serialize_nop(sdxi_slot_desc(nop));
	sdxi_cxt_submit(&f->cxt, nop, &f->chan.sync_cst, SDXI_CXT_SUBMIT_FENCE);
	f->chan.sync_index = nop.index;
	f->chan.sync_polling = true;
	after = queue_copy(t, 0);
	after_cookie = after->vdesc.tx.cookie;
	issue(f);
	f->cxt.sq->cxt_sts.read_index = f->cxt.sq->write_index;
	before->cst->signal = cpu_to_le64(SDXI_CST_BLK_SIGNAL_TERMINAL);
	after->cst->signal = cpu_to_le64(SDXI_CST_BLK_SIGNAL_TERMINAL);
	reap(f);
	KUNIT_EXPECT_EQ(t, f->ring.retire_index, 2);
	KUNIT_EXPECT_NOT_NULL(t, f->chan.sync_cst);
	KUNIT_EXPECT_EQ(t, f->chan.vchan.chan.completed_cookie, before_cookie);

	/* A completed NOP is still pinned while a CPU is polling it. */
	f->chan.sync_cst->signal = cpu_to_le64(SDXI_CST_BLK_SIGNAL_TERMINAL);
	reap(f);
	KUNIT_EXPECT_EQ(t, f->ring.retire_index, 2);
	f->chan.sync_polling = false;
	reap(f);
	KUNIT_EXPECT_NULL(t, f->chan.sync_cst);
	KUNIT_EXPECT_EQ(t, f->ring.retire_index, 5);
	KUNIT_EXPECT_EQ(t, f->chan.vchan.chan.completed_cookie, after_cookie);

	/* Synchronization with no copies retires its own reservation. */
	KUNIT_ASSERT_EQ(t, sdxi_ring_try_reserve(&f->ring, 1, &resv), 0);
	nop = sdxi_ring_resv_slot(&resv, 0);
	sdxi_serialize_nop(sdxi_slot_desc(nop));
	sdxi_cxt_submit(&f->cxt, nop, &f->chan.sync_cst, SDXI_CXT_SUBMIT_FENCE);
	f->chan.sync_index = nop.index;
	f->chan.sync_cst->signal = cpu_to_le64(SDXI_CST_BLK_SIGNAL_TERMINAL);
	reap(f);
	KUNIT_EXPECT_EQ(t, f->ring.retire_index, 6);
	KUNIT_EXPECT_NULL(t, f->chan.sync_cst);
}

static void wraparound(struct kunit *t)
{
	struct dma_fixture *f = t->priv;
	struct sdxi_sq *sq = f->cxt.sq;
	struct sdxi_dma_txd *txd[4];
	u64 start = sq->count - 2;

	/* An empty ring near its end: copies and terminator cross wrap. */
	sq->write_index = sq->cxt_sts.read_index = cpu_to_le64(start);
	sdxi_ring_retire(&f->ring, start);
	for (int i = 0; i < ARRAY_SIZE(txd); i++)
		txd[i] = queue_copy(t, 0);
	KUNIT_EXPECT_TRUE(t, issue(f));
	for (int i = 0; i < ARRAY_SIZE(txd); i++) {
		KUNIT_EXPECT_EQ(t, txd[i]->copy_index, start + i);
		KUNIT_EXPECT_PTR_EQ(t, txd[i]->cst,
				    &f->cxt.cq->entry[(start + i) % sq->count]);
		expect_slot(t, start + i, false);
	}
	expect_slot(t, start + 4, true);
	KUNIT_EXPECT_EQ(t, le64_to_cpu(sq->write_index), start + 5);
	KUNIT_EXPECT_FALSE(t, issue(f));
}

/* The completion/IRQ drain cycle must sustain more work than the ring holds. */
static void sustained_drain(struct kunit *t)
{
	struct dma_fixture *f = t->priv;
	struct sdxi_sq *sq = f->cxt.sq;
	struct sdxi_dma_txd **txd;
	unsigned int count = 2 * sq->count, consumed = 0;

	txd = kunit_kcalloc(t, count, sizeof(*txd), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(t, txd);
	for (unsigned int i = 0; i < count; i++)
		txd[i] = queue_copy(t, 0);
	KUNIT_EXPECT_TRUE(t, issue(f));
	KUNIT_EXPECT_EQ(t, le64_to_cpu(sq->write_index), sq->count);
	KUNIT_EXPECT_NULL(t, txd[sq->count - 1]->cst);

	while (consumed < count) {
		unsigned int end = consumed;
		u64 write_index = le64_to_cpu(sq->write_index);

		while (end < count && txd[end]->cst) {
			expect_slot(t, txd[end]->copy_index, false);
			txd[end]->cst->signal = cpu_to_le64(SDXI_CST_BLK_SIGNAL_TERMINAL);
			end++;
		}
		KUNIT_ASSERT_GT(t, end, consumed);
		expect_slot(t, write_index - 1, true);
		sq->cxt_sts.read_index = cpu_to_le64(write_index);
		scoped_guard(spinlock_irqsave, &f->chan.vchan.lock) {
			sdxi_dma_reap_locked(&f->chan);
			KUNIT_EXPECT_EQ(t, f->ring.retire_index, write_index);
			KUNIT_EXPECT_EQ(t, sdxi_dma_drain_locked(&f->chan), end < count);
		}
		consumed = end;
	}
	KUNIT_EXPECT_TRUE(t, list_empty(&f->chan.pending));
	KUNIT_EXPECT_TRUE(t, list_empty(&f->chan.vchan.desc_issued));
	KUNIT_EXPECT_EQ(t, le64_to_cpu(sq->write_index), count + 3);
}

static struct kunit_case cases[] = {
	KUNIT_CASE(capacity),
	KUNIT_CASE(flag_boundaries),
	KUNIT_CASE(exact_fit_and_leftover),
	KUNIT_CASE(ordered_completion),
	KUNIT_CASE(synchronization_retirement),
	KUNIT_CASE(wraparound),
	KUNIT_CASE(sustained_drain),
	{}
};

static struct kunit_suite suite = {
	.name = "SDXI DMA batching",
	.init = setup,
	.exit = teardown,
	.test_cases = cases,
};
kunit_test_suite(suite);

MODULE_DESCRIPTION("SDXI DMA batching tests");
MODULE_LICENSE("GPL");
