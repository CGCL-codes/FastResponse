// SPDX-License-Identifier: GPL-2.0
/*
 * LD:limited depth. similar to Kyber.
 */

#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/elevator.h>
#include <linux/module.h>
#include <linux/sbitmap.h>

#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-debugfs.h"
#include "blk-mq-sched.h"
#include "blk-mq-tag.h"

#define CREATE_TRACE_POINTS

#include <linux/printk.h>

/*
 * Scheduling domains: the device is divided into multiple domains based on the
 * request type.
 */

enum {
	LD_SYNC,
	LD_ASYNC,
	LD_NUM_DOMAINS,
};

enum {
	/*
	 * In order to prevent starvation of synchronous requests by a flood of
	 * asynchronous requests, we reserve 25% of requests for synchronous
	 * operations.
	 */
	LD_ASYNC_PERCENT = 75,
};

/*
 * Maximum device-wide depth for each scheduling domain.
 *
 * Even for fast devices with lots of tags like NVMe, you can saturate the
 * device with only a fraction of the maximum possible queue depth. So, we cap
 * these to a reasonable value.
 */
static unsigned int ld_depth = 32;

/*
 * Batch size (number of requests we'll dispatch in a row) for each scheduling
 * domain.
 */

static unsigned int ld_batch_size[] = {
	[LD_SYNC] = 8,
	[LD_ASYNC] = 4,
};


/*
 * There is a same mapping between ctx & hctx and lcq & lhd,
 * we use request->mq_ctx->index_hw to index the lcq in lhd.
 */
struct ld_ctx_queue {
	/*
	 * Used to ensure operations on rq_list and lcq_map to be an atmoic one.
	 * Also protect the rqs on rq_list when merge.
	 */
	spinlock_t lock;
	struct list_head rq_list[LD_NUM_DOMAINS];
} ____cacheline_aligned_in_smp;

struct ld_queue_data {
	struct request_queue *q;

	/*
	 * All scheduling domains have a limited number of in-flight requests
	 * device-wide, limited by these tokens.
	 */
	struct sbitmap_queue tokens;

	/*
	 * Async request percentage, converted to per-word depth for
	 * sbitmap_get_shallow().
	 */
	unsigned int async_depth;
};


struct ld_hctx_data {
	spinlock_t lock;
	struct list_head rqs[LD_NUM_DOMAINS];
	unsigned int cur_domain;
	unsigned int batching;
	struct ld_ctx_queue *lcqs;
	struct sbitmap lcq_map[LD_NUM_DOMAINS];
	struct sbq_wait domain_wait[LD_NUM_DOMAINS];
	struct sbq_wait_state *domain_ws[LD_NUM_DOMAINS];
	atomic_t wait_index[LD_NUM_DOMAINS];
};

static int ld_domain_wake(wait_queue_entry_t *wait, unsigned mode, int flags,
			     void *key);


static unsigned int ld_sched_domain(unsigned int op)
{
	if (op_is_sync(op))
		return LD_SYNC;
	else
		return LD_ASYNC;
}

static unsigned int ld_sched_tags_shift(struct request_queue *q)
{
	/*
	 * All of the hardware queues have the same depth, so we can just grab
	 * the shift of the first one.
	 */
	return q->queue_hw_ctx[0]->sched_tags->bitmap_tags.sb.shift;
}

static struct ld_queue_data *ld_queue_data_alloc(struct request_queue *q)
{
	struct ld_queue_data *lqd;
	unsigned int shift;
	int ret = -ENOMEM;
	int i;

	lqd = kzalloc_node(sizeof(*lqd), GFP_KERNEL, q->node);
	if (!lqd)
		goto err;

	lqd->q = q;

	WARN_ON(!ld_depth);
	ret = sbitmap_queue_init_node(&lqd->tokens,
					      ld_depth, -1, false,
					      GFP_KERNEL, q->node);
	if (ret) {
		sbitmap_queue_free(&lqd->tokens);
		goto err_lqd;
	}


	for (i = 0; i < LD_NUM_DOMAINS; i++) {
		WARN_ON(!ld_batch_size[i]);
	}

	shift = ld_sched_tags_shift(q);
	lqd->async_depth = (1U << shift) * LD_ASYNC_PERCENT / 100U;

	return lqd;

err_lqd:
	kfree(lqd);
err:
	return ERR_PTR(ret);
}


static int ld_init_sched(struct request_queue *q, struct elevator_type *e)
{
	struct ld_queue_data *lqd;
	struct elevator_queue *eq;

	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	lqd = ld_queue_data_alloc(q);
	if (IS_ERR(lqd)) {
		kobject_put(&eq->kobj);
		return PTR_ERR(lqd);
	}

	blk_stat_enable_accounting(q);

	eq->elevator_data = lqd;
	q->elevator = eq;

	return 0;
}


static void ld_exit_sched(struct elevator_queue *e)
{
	struct ld_queue_data *lqd = e->elevator_data;

	sbitmap_queue_free(&lqd->tokens);
	kfree(lqd);
}


static void ld_ctx_queue_init(struct ld_ctx_queue *lcq)
{
	unsigned int i;

	spin_lock_init(&lcq->lock);
	for (i = 0; i < LD_NUM_DOMAINS; i++)
		INIT_LIST_HEAD(&lcq->rq_list[i]);
}


static int ld_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct ld_queue_data *lqd = hctx->queue->elevator->elevator_data;
	struct ld_hctx_data *lhd;
	int i;

	lhd = kmalloc_node(sizeof(*lhd), GFP_KERNEL, hctx->numa_node);
	if (!lhd)
		return -ENOMEM;

	lhd->lcqs = kmalloc_array_node(hctx->nr_ctx,
				       sizeof(struct ld_ctx_queue),
				       GFP_KERNEL, hctx->numa_node);
	if (!lhd->lcqs)
		goto err_lhd;

	for (i = 0; i < hctx->nr_ctx; i++)
		ld_ctx_queue_init(&lhd->lcqs[i]);

	for (i = 0; i < LD_NUM_DOMAINS; i++) {
		if (sbitmap_init_node(&lhd->lcq_map[i], hctx->nr_ctx,
				      ilog2(8), GFP_KERNEL, hctx->numa_node)) {
			while (--i >= 0)
				sbitmap_free(&lhd->lcq_map[i]);
			goto err_lcqs;
		}
	}

	spin_lock_init(&lhd->lock);

	for (i = 0; i < LD_NUM_DOMAINS; i++) {
		INIT_LIST_HEAD(&lhd->rqs[i]);
		lhd->domain_wait[i].sbq = NULL;
		init_waitqueue_func_entry(&lhd->domain_wait[i].wait,
					  ld_domain_wake);
		lhd->domain_wait[i].wait.private = hctx;
		INIT_LIST_HEAD(&lhd->domain_wait[i].wait.entry);
		atomic_set(&lhd->wait_index[i], 0);
	}

	lhd->cur_domain = 0;
	lhd->batching = 0;

	hctx->sched_data = lhd;
	sbitmap_queue_min_shallow_depth(&hctx->sched_tags->bitmap_tags,
					lqd->async_depth);

	return 0;

err_lcqs:
	kfree(lhd->lcqs);
err_lhd:
	kfree(lhd);
	return -ENOMEM;
}


static void ld_exit_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct ld_hctx_data *lhd = hctx->sched_data;
	int i;

	for (i = 0; i < LD_NUM_DOMAINS; i++)
		sbitmap_free(&lhd->lcq_map[i]);
	kfree(lhd->lcqs);
	kfree(hctx->sched_data);
}


static int rq_get_domain_token(struct request *rq)
{
	return (long)rq->elv.priv[0];
}


static void rq_set_domain_token(struct request *rq, int token)
{
	rq->elv.priv[0] = (void *)(long)token;
}


static void rq_clear_domain_token(struct ld_queue_data *lqd,
				  struct request *rq)
{
	int nr;

	nr = rq_get_domain_token(rq);
	if (nr != -1) {
		sbitmap_queue_clear(&lqd->tokens, nr,
				    rq->mq_ctx->cpu);
	}
}

static void ld_limit_depth(unsigned int op, struct blk_mq_alloc_data *data)
{
	/*
	 * We use the scheduler tags as per-hardware queue queueing tokens.
	 * Async requests can be limited at this stage.
	 */
	if (!op_is_sync(op)) {
		struct ld_queue_data *lqd = data->q->elevator->elevator_data;

		data->shallow_depth = lqd->async_depth;
	}
}

static bool ld_bio_merge(struct blk_mq_hw_ctx *hctx, struct bio *bio,
		unsigned int nr_segs)
{
	struct ld_hctx_data *lhd = hctx->sched_data;
	struct blk_mq_ctx *ctx = blk_mq_get_ctx(hctx->queue);
	struct ld_ctx_queue *lcq = &lhd->lcqs[ctx->index_hw[hctx->type]];
	unsigned int sched_domain = ld_sched_domain(bio->bi_opf);
	struct list_head *rq_list = &lcq->rq_list[sched_domain];
	bool merged;

	spin_lock(&lcq->lock);
	merged = blk_mq_bio_list_merge(hctx->queue, rq_list, bio, nr_segs);
	spin_unlock(&lcq->lock);

	return merged;
}

static void ld_prepare_request(struct request *rq, struct bio *bio)
{
	rq_set_domain_token(rq, -1);
}

static void ld_insert_requests(struct blk_mq_hw_ctx *hctx,
				  struct list_head *rq_list, bool at_head)
{
	struct ld_hctx_data *lhd = hctx->sched_data;
	struct request *rq, *next;

	list_for_each_entry_safe(rq, next, rq_list, queuelist) {
		unsigned int sched_domain = ld_sched_domain(rq->cmd_flags);
		struct ld_ctx_queue *lcq = &lhd->lcqs[rq->mq_ctx->index_hw[hctx->type]];
		struct list_head *head = &lcq->rq_list[sched_domain];

		spin_lock(&lcq->lock);
		if (at_head)
			list_move(&rq->queuelist, head);
		else
			list_move_tail(&rq->queuelist, head);
		sbitmap_set_bit(&lhd->lcq_map[sched_domain],
				rq->mq_ctx->index_hw[hctx->type]);
		blk_mq_sched_request_inserted(rq);
		spin_unlock(&lcq->lock);
	}
}

static void ld_finish_request(struct request *rq)
{
	struct ld_queue_data *lqd = rq->q->elevator->elevator_data;

	rq_clear_domain_token(lqd, rq);
}

static void ld_completed_request(struct request *rq, u64 now)
{
	unsigned int sched_domain;

	sched_domain = ld_sched_domain(rq->cmd_flags);

	/*
	if(rq->io_start_time_ns > rq->start_time_ns)
		//group_id, task_id, critical, total_time, io_time, kernel_time, bio2rq, in_plug, plug2queue, int_queue op_is_critical(rq->cmd_flags)
		printk(KERN_DEBUG
			"limited_depth_completed_request:%d %d %u %u  %llu %llu %llu %llu %llu %llu %llu\n",
			rq->task_id, rq->task_group_id, op_is_critical(rq->cmd_flags), rq->__data_len, now - rq->start_time_ns, now - rq->io_start_time_ns, rq->io_start_time_ns - rq->start_time_ns,
			rq->bio_to_rq_time_ns - rq->start_time_ns, rq->rq_dequeue_from_plug ? rq->rq_dequeue_from_plug - rq->bio_to_rq_time_ns : 0, rq->rq_insert_into_queue ? (rq->rq_insert_into_queue -rq->rq_dequeue_from_plug) : 0,
			rq->rq_insert_into_queue ? rq->io_start_time_ns - rq->rq_insert_into_queue : (rq->rq_dequeue_from_plug ? rq->io_start_time_ns -rq->rq_dequeue_from_plug : rq->io_start_time_ns - rq->bio_to_rq_time_ns));
	*/
}

struct flush_lcq_data {
	struct ld_hctx_data *lhd;
	unsigned int sched_domain;
	struct list_head *list;
};

static bool flush_busy_lcq(struct sbitmap *sb, unsigned int bitnr, void *data)
{
	struct flush_lcq_data *flush_data = data;
	struct ld_ctx_queue *lcq = &flush_data->lhd->lcqs[bitnr];

	spin_lock(&lcq->lock);
	list_splice_tail_init(&lcq->rq_list[flush_data->sched_domain],
			      flush_data->list);
	sbitmap_clear_bit(sb, bitnr);
	spin_unlock(&lcq->lock);

	return true;
}

static void ld_flush_busy_lcqs(struct ld_hctx_data *lhd,
				  unsigned int sched_domain,
				  struct list_head *list)
{
	struct flush_lcq_data data = {
		.lhd = lhd,
		.sched_domain = sched_domain,
		.list = list,
	};

	sbitmap_for_each_set(&lhd->lcq_map[sched_domain],
			     flush_busy_lcq, &data);
}

static int ld_domain_wake(wait_queue_entry_t *wqe, unsigned mode, int flags,
			     void *key)
{
	struct blk_mq_hw_ctx *hctx = READ_ONCE(wqe->private);
	struct sbq_wait *wait = container_of(wqe, struct sbq_wait, wait);

	sbitmap_del_wait_queue(wait);
	blk_mq_run_hw_queue(hctx, true);
	return 1;
}

// this function is called to set token for critical requests
static void ld_prepare_token(struct blk_mq_hw_ctx *hctx, struct request *rq)
{
	u64 time0, time1, time2, time3;
	time0 = ktime_get_ns();
	struct ld_queue_data *lqd = hctx->queue->elevator->elevator_data;
	struct sbitmap_queue *tokens = &lqd->tokens;
	int nr;
	if (!op_is_critical(rq->cmd_flags) || rq_get_domain_token(rq) != -1)
		return ;
	time1 = ktime_get_ns();
	nr = __sbitmap_queue_get(tokens);
	time2 = ktime_get_ns();
	if(nr >= 0){
		// we got a token for critical request
		rq_set_domain_token(rq, nr);
	}
	// It doesn't matter if we don't get a token. We try to get token to limit non-critical requests 
	// other than critical requests
	time3 = ktime_get_ns();

//	printk(KERN_DEBUG
//		 "ld_prepare_token: current=%d critical=%u nr=%d %llu %llu %llu %llu\n",current->pid, current->critical, nr, time3-time0, time1-time0, time2-time1, time3-time2);

	return ;
}

static int ld_get_domain_token(struct ld_queue_data *lqd,
				  struct ld_hctx_data *lhd,
				  struct blk_mq_hw_ctx *hctx)
{
	unsigned int sched_domain = lhd->cur_domain;
	struct sbitmap_queue *tokens = &lqd->tokens;
	struct sbq_wait *wait = &lhd->domain_wait[sched_domain];
	struct sbq_wait_state *ws;
	int nr;

	nr = __sbitmap_queue_get(tokens);

	/*
	 * If we failed to get a domain token, make sure the hardware queue is
	 * run when one becomes available. Note that this is serialized on
	 * lhd->lock, but we still need to be careful about the waker.
	 */
	if (nr < 0 && list_empty_careful(&wait->wait.entry)) {
		ws = sbq_wait_ptr(tokens,
				  &lhd->wait_index[sched_domain]);
		lhd->domain_ws[sched_domain] = ws;
		sbitmap_add_wait_queue(tokens, ws, wait);

		/*
		 * Try again in case a token was freed before we got on the wait
		 * queue.
		 */
		nr = __sbitmap_queue_get(tokens);
	}

	/*
	 * If we got a token while we were on the wait queue, remove ourselves
	 * from the wait queue to ensure that all wake ups make forward
	 * progress. It's possible that the waker already deleted the entry
	 * between the !list_empty_careful() check and us grabbing the lock, but
	 * list_del_init() is okay with that.
	 */
	if (nr >= 0 && !list_empty_careful(&wait->wait.entry)) {
		ws = lhd->domain_ws[sched_domain];
		spin_lock_irq(&ws->wait.lock);
		sbitmap_del_wait_queue(wait);
		spin_unlock_irq(&ws->wait.lock);
	}

	return nr;
}

static struct request *
ld_dispatch_cur_domain(struct ld_queue_data *lqd,
			  struct ld_hctx_data *lhd,
			  struct blk_mq_hw_ctx *hctx)
{
	struct list_head *rqs;
	struct request *rq;
	int nr;

	rqs = &lhd->rqs[lhd->cur_domain];

	/*
	 * If we already have a flushed request, then we just need to get a
	 * token for it. Otherwise, if there are pending requests in the lcqs,
	 * flush the lcqs, but only if we can get a token. If not, we should
	 * leave the requests in the lcqs so that they can be merged. Note that
	 * lhd->lock serializes the flushes, so if we observed any bit set in
	 * the lcq_map, we will always get a request.
	 */
	rq = list_first_entry_or_null(rqs, struct request, queuelist);
	if (rq) {
		nr = ld_get_domain_token(lqd, lhd, hctx);
		if (nr >= 0) {
			lhd->batching++;
			rq_set_domain_token(rq, nr);
			list_del_init(&rq->queuelist);
			return rq;
		} else {
			;
		}
	} else if (sbitmap_any_bit_set(&lhd->lcq_map[lhd->cur_domain])) {
		nr = ld_get_domain_token(lqd, lhd, hctx);
		if (nr >= 0) {
			ld_flush_busy_lcqs(lhd, lhd->cur_domain, rqs);
			rq = list_first_entry(rqs, struct request, queuelist);
			lhd->batching++;
			rq_set_domain_token(rq, nr);
			list_del_init(&rq->queuelist);
			return rq;
		} else {
			;
		}
	}

	/* There were either no pending requests or no tokens. */
	return NULL;
}

static struct request *ld_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct ld_queue_data *lqd = hctx->queue->elevator->elevator_data;
	struct ld_hctx_data *lhd = hctx->sched_data;
	struct request *rq;
	int i;

	spin_lock(&lhd->lock);

	/*
	 * First, if we are still entitled to batch, try to dispatch a request
	 * from the batch.
	 */
	if (lhd->batching < ld_batch_size[lhd->cur_domain]) {
		rq = ld_dispatch_cur_domain(lqd, lhd, hctx);
		if (rq)
			goto out;
	}

	/*
	 * Either,
	 * 1. We were no longer entitled to a batch.
	 * 2. The domain we were batching didn't have any requests.
	 * 3. The domain we were batching was out of tokens.
	 *
	 * Start another batch. Note that this wraps back around to the original
	 * domain if no other domains have requests or tokens.
	 */
	lhd->batching = 0;
	for (i = 0; i < LD_NUM_DOMAINS; i++) {
		if (lhd->cur_domain == LD_NUM_DOMAINS - 1)
			lhd->cur_domain = 0;
		else
			lhd->cur_domain++;

		rq = ld_dispatch_cur_domain(lqd, lhd, hctx);
		if (rq)
			goto out;
	}

	rq = NULL;
out:
	spin_unlock(&lhd->lock);
	return rq;
}

static bool ld_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct ld_hctx_data *lhd = hctx->sched_data;
	int i;

	for (i = 0; i < LD_NUM_DOMAINS; i++) {
		if (!list_empty_careful(&lhd->rqs[i]) ||
		    sbitmap_any_bit_set(&lhd->lcq_map[i]))
			return true;
	}

	return false;
}

/*
 * sysfs parts below
 */
static ssize_t
limited_depth_var_show(unsigned long long var, char *page)
{
	return sprintf(page, "%llu\n", var);
}

static int
limited_depth_var_store(unsigned long long *var, const char *page)
{
	unsigned long long new_val;
	int ret = kstrtoull(page, 10, &new_val);

	if (ret)
		return ret;
	*var = new_val;
	return 0;
}

// struct ld_queue_data *lqd = e->elevator_data;
#define SHOW_FUNCTION(__FUNC, __VAR)				\
static ssize_t __FUNC(struct elevator_queue *e, char *page)		\
{									\
	int __data = __VAR;						\
	return limited_depth_var_show(__data, (page));			\
}

SHOW_FUNCTION(limited_depth_depth_show, ld_depth);
SHOW_FUNCTION(limited_depth_sync_batch_show, ld_batch_size[LD_SYNC]);
SHOW_FUNCTION(limited_depth_async_batch_show, ld_batch_size[LD_ASYNC]);
#undef SHOW_FUNCTION

// 	struct ld_queue_data *lqd = e->elevator_data;
#define STORE_FUNCTION(__FUNC, __PTR, MIN, MAX)			\
static ssize_t __FUNC(struct elevator_queue *e, const char *page, size_t count)	\
{									\
	u64 __data;							\
	int ret;							\
	ret = limited_depth_var_store(&__data, (page));				\
	if (ret)							\
		return ret;						\
	if (__data < (MIN))						\
		__data = (MIN);						\
	else if (__data > (MAX))					\
		__data = (MAX);						\
	*(__PTR) = __data;					\
	return count;							\
}
STORE_FUNCTION(limited_depth_sync_batch_store, &ld_batch_size[LD_SYNC], 0, UINT_MAX);
STORE_FUNCTION(limited_depth_async_batch_store, &ld_batch_size[LD_ASYNC], 0, UINT_MAX);
#undef STORE_FUNCTION

#define STORE_FUNCTION_DEPTH(__FUNC, __PTR, MIN, MAX)			\
static ssize_t __FUNC(struct elevator_queue *e, const char *page, size_t count)	\
{									\
	struct ld_queue_data *lqd = e->elevator_data;		\
	u64 __data;							\
	int ret;							\
	ret = limited_depth_var_store(&__data, (page));				\
	if (ret)							\
		return ret;						\
	if (__data < (MIN))						\
		__data = (MIN);						\
	else if (__data > (MAX))					\
		__data = (MAX);						\
	*(__PTR) = __data;					\
	if (__data != lqd->tokens.sb.depth){  \
	 	printk(KERN_DEBUG "ld_resize_domain:  depth=%llu\n", __data);	\
		sbitmap_queue_resize(&lqd->tokens, __data);\
	} \
	return count;							\
}
STORE_FUNCTION_DEPTH(limited_depth_depth_store, &ld_depth, 0, UINT_MAX);
#undef STORE_FUNCTION_DEPTH

#define LD_MOD_ATTR(name) \
	__ATTR(name, 0644, limited_depth_##name##_show, limited_depth_##name##_store)

static struct elv_fs_entry limited_depth_sched_attrs[] = {
	LD_MOD_ATTR(depth),
	LD_MOD_ATTR(sync_batch),
	LD_MOD_ATTR(async_batch),
	__ATTR_NULL
};


static struct elevator_type limited_depth_sched = {
	.ops = {
		.init_sched = ld_init_sched,
		.exit_sched = ld_exit_sched,
		.init_hctx = ld_init_hctx,
		.exit_hctx = ld_exit_hctx,
		.limit_depth = ld_limit_depth,
		.bio_merge = ld_bio_merge,
		.prepare_request = ld_prepare_request,
		.prepare_token = ld_prepare_token,
		.insert_requests = ld_insert_requests,
		.finish_request = ld_finish_request,
		.requeue_request = ld_finish_request,
		.completed_request = ld_completed_request,
		.dispatch_request = ld_dispatch_request,
		.has_work = ld_has_work,
	},
	.elevator_attrs = limited_depth_sched_attrs,
	.elevator_name = "limited-depth",
	.elevator_owner = THIS_MODULE,
};

static int __init limited_depth_init(void)
{
	return elv_register(&limited_depth_sched);
}

static void __exit limited_depth_exit(void)
{
	elv_unregister(&limited_depth_sched);
}

module_init(limited_depth_init);
module_exit(limited_depth_exit);

MODULE_AUTHOR("Omar Sandoval & LMZ");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("limited-depth I/O scheduler");
