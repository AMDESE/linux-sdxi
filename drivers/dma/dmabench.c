// SPDX-License-Identifier: GPL-2.0
/* Sustained memcpy throughput through the DMAengine client API. */

#include <linux/compat.h>
#include <linux/completion.h>
#include <linux/cpu.h>
#include <linux/ctype.h>
#include <linux/debugfs.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/fs.h>
#include <linux/highmem.h>
#include <linux/jiffies.h>
#include <linux/kthread.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>

#include <uapi/linux/dmabench.h>

struct dmabench_buffer {
	struct sg_table *sgt;
	void *vaddr;
	dma_addr_t dma;
};

struct dmabench_pair {
	struct dmabench_buffer src;
	struct dmabench_buffer dst;
	bool copied;
};

struct dmabench_request;

struct dmabench_batch {
	struct dmabench_request *request;
	u64 terminal;
	u32 length;
	bool final;
	bool done;
	bool error;
};

struct dmabench_request {
	struct dmabench_run run;
	struct dma_chan *chan;
	struct device *dev;
	struct dmabench_pair *pairs;
	struct dmabench_batch *batches;
	size_t allocation_size;
	u32 next_pair;
	/* Protects callback publication, progress, and batch reclamation. */
	spinlock_t lock;
	unsigned long progress;
	u64 end_ns;
	wait_queue_head_t wait;
	struct completion exited;
	bool cancel;
	bool submitted_dma;
	bool retained;
	int status;
	struct list_head retained_node;
};

static struct dentry *dmabench_dentry;
static LIST_HEAD(dmabench_retained);
static DEFINE_MUTEX(dmabench_retained_lock);

static bool dmabench_cancelled(struct dmabench_request *req)
{
	return READ_ONCE(req->cancel) || signal_pending(current);
}

static int dmabench_validate(struct dmabench_request *req)
{
	struct dmabench_config *cfg = &req->run.config;
	u64 bytes, rounded;
	size_t metadata;
	size_t len;
	u32 i;

	len = strnlen(cfg->channel, sizeof(cfg->channel));
	if (!len || len == sizeof(cfg->channel))
		return -EINVAL;
	for (i = 0; i < len; i++)
		if (!isalnum(cfg->channel[i]) && cfg->channel[i] != '_' &&
		    cfg->channel[i] != '-' && cfg->channel[i] != '.')
			return -EINVAL;
	if (cfg->flags & ~DMABENCH_F_VERIFY ||
	    memchr_inv(cfg->reserved, 0, sizeof(cfg->reserved)) ||
	    memchr_inv(req->run.result.reserved, 0,
		       sizeof(req->run.result.reserved)))
		return -EINVAL;
	memset(&req->run.result, 0, sizeof(req->run.result));

	if (!cfg->transfer_size || !cfg->transfers || !cfg->batch_size ||
	    cfg->batch_size > cfg->queue_depth ||
	    cfg->queue_depth > cfg->buffer_count || !cfg->timeout_ms ||
	    cfg->cpu < -1 || (cfg->cpu >= 0 && cfg->cpu >= nr_cpu_ids))
		return -EINVAL;
	if (cfg->buffer_count > DMABENCH_MAX_BUFFER_COUNT ||
	    cfg->queue_depth > DMABENCH_MAX_QUEUE_DEPTH ||
	    cfg->transfer_size > DMABENCH_MAX_TRANSFER_SIZE ||
	    cfg->timeout_ms > DMABENCH_MAX_TIMEOUT_MS)
		return -E2BIG;
	if (check_add_overflow(cfg->transfer_size, (u64)PAGE_SIZE - 1,
			       &rounded))
		return -EOVERFLOW;
	rounded &= ~((u64)PAGE_SIZE - 1);
	if (rounded > SIZE_MAX ||
	    check_mul_overflow(rounded, (u64)cfg->buffer_count * 2, &bytes) ||
	    bytes > SIZE_MAX ||
	    check_mul_overflow((size_t)cfg->buffer_count,
			       sizeof(*req->pairs), &metadata) ||
	    check_mul_overflow((size_t)cfg->queue_depth,
			       sizeof(*req->batches), &metadata))
		return -EOVERFLOW;
	if (bytes > DMABENCH_MAX_ALLOCATION_BYTES)
		return -E2BIG;
	req->allocation_size = rounded;
	req->run.result.allocation_bytes = bytes;
	if (check_mul_overflow(cfg->transfers, cfg->transfer_size, &bytes) ||
	    check_mul_overflow(cfg->warmup_transfers, cfg->transfer_size, &bytes))
		return -EOVERFLOW;
	return 0;
}

static bool dmabench_filter(struct dma_chan *chan, void *param)
{
	return !strcmp(dma_chan_name(chan), param);
}

static int dmabench_reserve(struct dmabench_request *req)
{
	struct dma_device *dma;
	dma_cap_mask_t mask;

	dma_cap_zero(mask);
	dma_cap_set(DMA_MEMCPY, mask);
	req->chan = dma_request_channel(mask, dmabench_filter,
					 req->run.config.channel);
	if (!req->chan)
		return -ENODEV;
	dma = req->chan->device;
	req->dev = get_device(dmaengine_get_dma_device(req->chan));
	if (dma_has_cap(DMA_COMPLETION_NO_ORDER, dma->cap_mask) ||
	    !dma->device_terminate_all || !dma->device_synchronize)
		return -EOPNOTSUPP;
	if (!is_dma_copy_aligned(dma, 0, 0, req->run.config.transfer_size))
		return -EINVAL;
	if (req->allocation_size > dma_max_mapping_size(req->dev) ||
	    req->allocation_size > dma_get_max_seg_size(req->dev))
		return -E2BIG;
	return 0;
}

static int dmabench_alloc_buffer(struct dmabench_request *req,
				 struct dmabench_buffer *buf,
				 enum dma_data_direction dir)
{
	u64 boundary = dma_get_seg_boundary(req->dev);
	dma_addr_t end;

	buf->sgt = dma_alloc_noncontiguous(req->dev, req->allocation_size, dir,
					 GFP_KERNEL | __GFP_NOWARN, 0);
	if (!buf->sgt)
		return -ENOMEM;
	buf->dma = sg_dma_address(buf->sgt->sgl);
	if (buf->sgt->nents != 1 ||
	    sg_dma_len(buf->sgt->sgl) < req->allocation_size ||
	    check_add_overflow(buf->dma,
			       (dma_addr_t)req->allocation_size - 1, &end) ||
	    ((buf->dma ^ end) & ~boundary))
		return -E2BIG;
	if (!is_dma_copy_aligned(req->chan->device, buf->dma, 0,
				req->run.config.transfer_size))
		return -EINVAL;
	buf->vaddr = dma_vmap_noncontiguous(req->dev, req->allocation_size,
					   buf->sgt);
	if (!buf->vaddr)
		return -ENOMEM;
	dma_sync_sgtable_for_cpu(req->dev, buf->sgt, dir);
	invalidate_kernel_vmap_range(buf->vaddr, req->allocation_size);
	return 0;
}

static void dmabench_buffer_to_device(struct dmabench_request *req,
				     struct dmabench_buffer *buf,
				     enum dma_data_direction dir)
{
	flush_kernel_vmap_range(buf->vaddr, req->allocation_size);
	dma_sync_sgtable_for_device(req->dev, buf->sgt, dir);
}

static int dmabench_alloc_pool(struct dmabench_request *req)
{
	struct dmabench_config *cfg = &req->run.config;
	size_t offset, j;
	u32 i;
	int ret;

	req->pairs = kvcalloc(cfg->buffer_count, sizeof(*req->pairs), GFP_KERNEL);
	req->batches = kvcalloc(cfg->queue_depth, sizeof(*req->batches), GFP_KERNEL);
	if (!req->pairs || !req->batches)
		return -ENOMEM;
	for (i = 0; i < cfg->buffer_count; i++) {
		struct dmabench_pair *pair = &req->pairs[i];
		u8 *src, *dst;

		if (dmabench_cancelled(req))
			return -EINTR;
		ret = dmabench_alloc_buffer(req, &pair->src, DMA_TO_DEVICE);
		if (ret)
			return ret;
		/* CPU poisoning requires writeback as well as invalidation. */
		ret = dmabench_alloc_buffer(req, &pair->dst, DMA_BIDIRECTIONAL);
		if (ret)
			return ret;
		src = pair->src.vaddr;
		dst = pair->dst.vaddr;
		for (offset = 0; offset < req->allocation_size; offset += PAGE_SIZE) {
			if (dmabench_cancelled(req))
				return -EINTR;
			for (j = offset; j < offset + PAGE_SIZE; j++) {
				src[j] = (i >> ((j & 3) * 8)) ^ j ^ (j >> 8) ^ 0x5a;
				dst[j] = ~src[j];
			}
			cond_resched();
		}
		dmabench_buffer_to_device(req, &pair->src, DMA_TO_DEVICE);
		dmabench_buffer_to_device(req, &pair->dst, DMA_BIDIRECTIONAL);
	}
	return 0;
}

static void dmabench_callback(void *param, const struct dmaengine_result *result)
{
	struct dmabench_batch *batch = param;
	struct dmabench_request *req = batch->request;
	unsigned long flags;

	spin_lock_irqsave(&req->lock, flags);
	if (batch->final)
		req->end_ns = ktime_get_ns();
	batch->error = result && result->result != DMA_TRANS_NOERROR;
	WRITE_ONCE(req->progress, jiffies);
	/* Final access to the record; the worker may recycle it after unlock. */
	WRITE_ONCE(batch->done, true);
	wake_up_interruptible(&req->wait);
	spin_unlock_irqrestore(&req->lock, flags);
}

static u32 dmabench_next_batch(struct dmabench_request *req, u32 index)
{
	return index + 1 == req->run.config.queue_depth ? 0 : index + 1;
}

static int dmabench_phase(struct dmabench_request *req, u64 count, bool measured)
{
	struct dmabench_config *cfg = &req->run.config;
	unsigned long timeout = msecs_to_jiffies(cfg->timeout_ms);
	u64 submitted = 0, completed = 0, issues = 0, start_ns = 0;
	u32 head = 0, tail = 0, active = 0, outstanding = 0;
	unsigned long flags, progress, deadline;
	int ret;

	if (!count)
		return 0;
	spin_lock_irqsave(&req->lock, flags);
	WRITE_ONCE(req->progress, jiffies);
	req->end_ns = 0;
	spin_unlock_irqrestore(&req->lock, flags);

	while (completed < count) {
		struct dmabench_batch *batch;
		u32 length, i;

		if (dmabench_cancelled(req))
			return -EINTR;
		spin_lock_irqsave(&req->lock, flags);
		while (active && req->batches[head].done) {
			batch = &req->batches[head];
			if (batch->error) {
				spin_unlock_irqrestore(&req->lock, flags);
				return -EIO;
			}
			completed = batch->terminal;
			outstanding -= batch->length;
			active--;
			head = dmabench_next_batch(req, head);
		}
		progress = req->progress;
		deadline = progress + timeout;
		if (completed != count && time_after_eq(jiffies, deadline)) {
			spin_unlock_irqrestore(&req->lock, flags);
			return -ETIMEDOUT;
		}
		spin_unlock_irqrestore(&req->lock, flags);
		if (completed == count)
			break;
		if (submitted == count || outstanding == cfg->queue_depth) {
			long remaining = deadline - jiffies;

			if (remaining <= 0)
				continue;
			ret = wait_event_interruptible_timeout(req->wait,
				READ_ONCE(req->cancel) ||
				READ_ONCE(req->batches[head].done) ||
				READ_ONCE(req->progress) != progress,
				remaining);
			if (ret < 0)
				return -EINTR;
			continue;
		}

		length = min(cfg->batch_size, cfg->queue_depth - outstanding);
		length = min_t(u64, length, count - submitted);
		batch = &req->batches[tail];
		/* No callback can still access this reclaimed record. */
		batch->request = req;
		batch->terminal = submitted + length;
		batch->length = length;
		batch->final = measured && batch->terminal == count;
		WRITE_ONCE(batch->done, false);
		batch->error = false;

		for (i = 0; i < length; i++) {
			struct dmabench_pair *pair = &req->pairs[req->next_pair];
			struct dma_async_tx_descriptor *tx;
			unsigned long prep_flags = DMA_CTRL_ACK;
			dma_cookie_t cookie;

			if (dmabench_cancelled(req))
				return -EINTR;
			if (i == length - 1)
				prep_flags |= DMA_PREP_INTERRUPT;
			if (measured && !submitted)
				start_ns = ktime_get_ns();
			tx = dmaengine_prep_dma_memcpy(req->chan, pair->dst.dma,
					pair->src.dma, cfg->transfer_size, prep_flags);
			if (!tx)
				return -EIO;
			tx->callback = NULL;
			tx->callback_result = NULL;
			tx->callback_param = NULL;
			if (i == length - 1) {
				tx->callback_result = dmabench_callback;
				tx->callback_param = batch;
			}
			/* Prep and submit must stay adjacent: prep may hold a lock. */
			req->submitted_dma = true;
			cookie = dmaengine_submit(tx);
			if (dma_submit_error(cookie))
				return -EIO;
			submitted++;
			pair->copied = true;
			if (++req->next_pair == cfg->buffer_count)
				req->next_pair = 0;
		}
		outstanding += length;
		active++;
		tail = dmabench_next_batch(req, tail);
		if (dmabench_cancelled(req))
			return -EINTR;
		dma_async_issue_pending(req->chan);
		issues++;
		cond_resched();
	}

	if (measured) {
		if (req->end_ns <= start_ns)
			return -EIO;
		req->run.result.elapsed_ns = req->end_ns - start_ns;
		req->run.result.submitted = submitted;
		req->run.result.completed = completed;
		req->run.result.payload_bytes = completed * cfg->transfer_size;
		req->run.result.issue_pending_calls = issues;
	}
	return 0;
}

static int dmabench_verify(struct dmabench_request *req)
{
	u32 i;

	for (i = 0; i < req->run.config.buffer_count; i++) {
		struct dmabench_pair *pair = &req->pairs[i];
		size_t offset;

		if (!pair->copied)
			continue;
		dma_sync_sgtable_for_cpu(req->dev, pair->src.sgt, DMA_TO_DEVICE);
		dma_sync_sgtable_for_cpu(req->dev, pair->dst.sgt, DMA_BIDIRECTIONAL);
		invalidate_kernel_vmap_range(pair->src.vaddr, req->allocation_size);
		invalidate_kernel_vmap_range(pair->dst.vaddr, req->allocation_size);
		for (offset = 0; offset < req->run.config.transfer_size;
		     offset += PAGE_SIZE) {
			size_t len = min_t(size_t, PAGE_SIZE,
					  req->run.config.transfer_size - offset);

			if (dmabench_cancelled(req))
				return -EINTR;
			if (memcmp(pair->src.vaddr + offset, pair->dst.vaddr + offset,
				   len))
				return -EILSEQ;
			cond_resched();
		}
	}
	return 0;
}

static void dmabench_free_buffer(struct dmabench_request *req,
				  struct dmabench_buffer *buf,
				  enum dma_data_direction dir)
{
	if (buf->vaddr)
		dma_vunmap_noncontiguous(req->dev, buf->vaddr);
	if (buf->sgt)
		dma_free_noncontiguous(req->dev, req->allocation_size, buf->sgt, dir);
}

static void dmabench_free_resources(struct dmabench_request *req)
{
	u32 i;

	if (req->pairs) {
		for (i = 0; i < req->run.config.buffer_count; i++) {
			dmabench_free_buffer(req, &req->pairs[i].src, DMA_TO_DEVICE);
			dmabench_free_buffer(req, &req->pairs[i].dst, DMA_BIDIRECTIONAL);
			cond_resched();
		}
	}
	kvfree(req->pairs);
	kvfree(req->batches);
	if (req->chan)
		dma_release_channel(req->chan);
	put_device(req->dev);
}

static int dmabench_worker(void *data)
{
	struct dmabench_request *req = data;
	int ret, terminate_ret;

	ret = dmabench_reserve(req);
	if (ret)
		goto free;
	ret = dmabench_alloc_pool(req);
	if (ret)
		goto free;
	ret = dmabench_phase(req, req->run.config.warmup_transfers, false);
	if (!ret)
		ret = dmabench_phase(req, req->run.config.transfers, true);

	if (req->submitted_dma) {
		/* Also quiesce callbacks after a successful complete drain. */
		terminate_ret = dmaengine_terminate_sync(req->chan);
		if (terminate_ret) {
			/*
			 * DMA or callbacks may still be live. Keep every reachable
			 * resource, the reservation and a permanent module reference.
			 * There is deliberately no unsafe automatic recovery path.
			 */
			__module_get(THIS_MODULE);
			req->retained = true;
			mutex_lock(&dmabench_retained_lock);
			list_add_tail(&req->retained_node, &dmabench_retained);
			mutex_unlock(&dmabench_retained_lock);
			pr_crit("dmabench: %s termination failed (%d); resources retained, unload disabled until reboot\n",
				req->run.config.channel, terminate_ret);
			ret = -EIO;
			goto exited;
		}
	}
	if (!ret && req->run.config.flags & DMABENCH_F_VERIFY)
		ret = dmabench_verify(req);
free:
	dmabench_free_resources(req);
exited:
	req->status = ret;
	kthread_complete_and_exit(&req->exited, 0);
}

static long dmabench_run_ioctl(unsigned int cmd, unsigned long arg)
{
	void __user *user = (void __user *)arg;
	struct dmabench_request *req;
	struct task_struct *worker;
	int ret;

	if (cmd != DMABENCH_RUN)
		return -ENOTTY;
	req = kzalloc_obj(*req);
	if (!req)
		return -ENOMEM;
	if (copy_from_user(&req->run, user, sizeof(req->run))) {
		ret = -EFAULT;
		goto free;
	}
	ret = dmabench_validate(req);
	if (ret)
		goto free;
	spin_lock_init(&req->lock);
	init_waitqueue_head(&req->wait);
	init_completion(&req->exited);

	cpus_read_lock();
	if (req->run.config.cpu >= 0 && !cpu_online(req->run.config.cpu)) {
		ret = -EINVAL;
		goto unlock;
	}
	worker = kthread_create(dmabench_worker, req, "dmabench/%s",
				req->run.config.channel);
	if (IS_ERR(worker)) {
		ret = PTR_ERR(worker);
		goto unlock;
	}
	if (req->run.config.cpu >= 0)
		kthread_bind(worker, req->run.config.cpu);
	wake_up_process(worker);
	cpus_read_unlock();

	ret = wait_for_completion_interruptible(&req->exited);
	if (ret) {
		WRITE_ONCE(req->cancel, true);
		wake_up_interruptible(&req->wait);
		/* The worker must finish DMA synchronization before we return. */
		wait_for_completion(&req->exited);
		ret = -EINTR;
	}
	if (!ret || req->retained)
		ret = req->status;
	if (!ret && copy_to_user(user, &req->run, sizeof(req->run)))
		ret = -EFAULT;
	if (!req->retained)
		kfree(req);
	return ret;
unlock:
	cpus_read_unlock();
free:
	kfree(req);
	return ret;
}

static long dmabench_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	int ret;

	ret = debugfs_file_get(file->f_path.dentry);
	if (ret)
		return ret;
	ret = dmabench_run_ioctl(cmd, arg);
	debugfs_file_put(file->f_path.dentry);
	return ret;
}

static const struct file_operations dmabench_fops = {
	.owner = THIS_MODULE,
	.open = nonseekable_open,
	.unlocked_ioctl = dmabench_ioctl,
	.compat_ioctl = compat_ptr_ioctl,
};

static int __init dmabench_init(void)
{
	/*
	 * The full debugfs proxy does not forward compat_ioctl. Use our own
	 * removal protection; debugfs still protects open and pins .owner.
	 */
	dmabench_dentry = debugfs_create_file_unsafe("dmabench", 0600, NULL, NULL,
						     &dmabench_fops);
	return PTR_ERR_OR_ZERO(dmabench_dentry);
}

static void __exit dmabench_exit(void)
{
	debugfs_remove(dmabench_dentry);
}

module_init(dmabench_init);
module_exit(dmabench_exit);

MODULE_DESCRIPTION("DMAengine memcpy throughput benchmark");
MODULE_LICENSE("GPL");
