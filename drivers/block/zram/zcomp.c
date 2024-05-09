// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2014 Sergey Senozhatsky.
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/err.h>
#include <linux/slab.h>
#include <linux/highmem.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <uapi/linux/sched/types.h>

#define CREATE_TRACE_POINTS
#include <trace/events/zram.h>

#include "zram_drv.h"
#include "zcomp.h"

#define ZCOMP_ALGO_NAME_MAX 64
#define ZCOMP_BATCH_SIZE 64

struct zcomp_backend {
	const char algo_name[ZCOMP_ALGO_NAME_MAX];
	struct zcomp_operation *op;
};

#define LRU_SIZE 256
struct zram_cache_node {
	u32 index;
	char page_data[PAGE_SIZE];
	struct zram_cache_node *next;
	struct zram_cache_node *prev;
};

struct zram_cache_list {
	u16 size;
	struct zram_cache_node *start_node;
	struct zram_cache_node *last_node;
};
static struct zram_cache_list cache_list = {};

struct buffer_zram_cache_node {
	struct buffer_zram_cache_node *next;
	struct buffer_zram_cache_node *prev;
	struct zram_cache_node node_buffer;
};

struct buffer_zram_cache_list {
	u16 size;
	struct buffer_zram_cache_node *start_node;
	struct buffer_zram_cache_node *last_node;
};

static struct buffer_zram_cache_list free_cache_list;

//static DEFINE_SPINLOCK(cache_spinlock);
//static DEFINE_SPINLOCK(buff_spinlock);

static struct zram_cache_node *allocate_buffer_cache()
{
	struct buffer_zram_cache_node *tempt;
	if (free_cache_list.size < 1) {
		BUG();
	}
	tempt = free_cache_list.last_node;
	free_cache_list.last_node = free_cache_list.last_node->prev;
	free_cache_list.last_node->next = NULL;
	free_cache_list.size--;
	return &tempt->node_buffer;
}

static void free_buffer_cache(struct zram_cache_node *node)
{
	struct buffer_zram_cache_node *tempt =
		container_of(node, struct buffer_zram_cache_node, node_buffer);
	tempt->prev = free_cache_list.last_node;
	tempt->next = NULL;
	free_cache_list.last_node->next = tempt;
	free_cache_list.last_node = tempt;
	free_cache_list.size++;
}

static void find_index_from_cache_list(u32 index, struct page *page)
{
	struct zram_cache_node *cur, *cache;
	void *dst;
	cache = NULL;

	//spin_lock(&cache_spinlock);

	cur = cache_list.start_node;

	while (cur) {
		if (cur->index == index) {
			cache = cur;
			break;
		}
		cur = cur->next;
	}
	if (cache) {
		dst = kmap_atomic(page);
		memcpy(dst, cache->page_data, PAGE_SIZE);
		kunmap_atomic(dst);
		cache->prev->next = cache->next;
		if (cache->next)
			cache->next->prev = cache->prev;
		else
			cache_list.last_node = cache->prev;
		cache_list.size--;
	} else {
		printk("Size %lu but not found\n", cache_list.size);
		BUG();
	}
	//spin_unlock(&cache_spinlock);

	free_buffer_cache(cache);
}

/* zcomp_backend list registered by zcomp instances */
static LIST_HEAD(zcomp_list);
static DECLARE_RWSEM(zcomp_rwsem);

/* caller should hold a zcomp_rwsem under semaphore */
struct zcomp *find_zcomp(const char *algo_name)
{
	struct zcomp *cursor, *ret = NULL;

	list_for_each_entry (cursor, &zcomp_list, list) {
		if (!strcmp(cursor->algo_name, algo_name)) {
			ret = cursor;
			break;
		}
	}

	return ret;
}

void zcomp_init_node_lists(void)
{
	int i = 0;
	static struct buffer_zram_cache_node buffer_list[LRU_SIZE + 2] = {};
	struct zram_cache_node *node = kmalloc(sizeof(struct zram_cache_node), GFP_ATOMIC);
	node->index = (u32)-1;
	node->next = NULL;
	node->prev = NULL;
	cache_list.start_node = node;
	cache_list.last_node = NULL;
	cache_list.size = 0;

	for (i = 0; i < (LRU_SIZE + 2); ++i) {
		if (i != 0)
			buffer_list[i].prev = &buffer_list[i - 1];
		if (i != LRU_SIZE + 1)
			buffer_list[i].next = &buffer_list[i + 1];
	}
	free_cache_list.start_node = &buffer_list[0];
	free_cache_list.start_node->prev = NULL;
	free_cache_list.last_node = &buffer_list[LRU_SIZE + 1];
	free_cache_list.last_node->next = NULL;
	free_cache_list.size = LRU_SIZE + 2;
}
EXPORT_SYMBOL(zcomp_init_node_lists);

int zcomp_register(const char *algo_name, const struct zcomp_operation *op)
{
	struct zcomp *zcomp;
	size_t len;
	int ret = 0;

	if (!algo_name || !op)
		return -EINVAL;

	len = strlen(algo_name);
	if (len >= ZCOMP_ALGO_NAME_MAX)
		return -EINVAL;

	zcomp = kzalloc(sizeof(*zcomp), GFP_KERNEL);
	if (!zcomp) {
		ret = -ENOMEM;
		goto out;
	}

	strncpy(zcomp->algo_name, algo_name, len);
	zcomp->algo_name[len] = '\0';
	zcomp->op = op;

	down_write(&zcomp_rwsem);
	if (find_zcomp(algo_name)) {
		up_write(&zcomp_rwsem);
		kfree(zcomp);
		ret = -EEXIST;
		goto out;
	}

	list_add(&zcomp->list, &zcomp_list);
	up_write(&zcomp_rwsem);

out:
	return ret;
}
EXPORT_SYMBOL(zcomp_register);

int zcomp_unregister(const char *algo_name)
{
	int ret = -EINVAL;
	struct zcomp *cursor;

	down_write(&zcomp_rwsem);
	list_for_each_entry (cursor, &zcomp_list, list) {
		if (strcmp(cursor->algo_name, algo_name))
			continue;

		list_del(&cursor->list);
		kfree(cursor);
		ret = 0;
		break;
	}
	up_write(&zcomp_rwsem);

	return ret;
}
EXPORT_SYMBOL(zcomp_unregister);

static void zcomp_fill_page(void *ptr, unsigned long len, unsigned long value)
{
	WARN_ON_ONCE(!IS_ALIGNED(len, sizeof(unsigned long)));
	memset_l(ptr, value, len / sizeof(unsigned long));
}

static bool zcomp_page_same_pattern(struct page *page, unsigned long *element)
{
	unsigned int pos;
	unsigned long *mem;
	unsigned long val;
	bool ret = true;

	mem = kmap_atomic(page);
	val = mem[0];
	for (pos = 1; pos < PAGE_SIZE / sizeof(*mem); pos++) {
		if (val != mem[pos]) {
			ret = false;
			goto out;
		}
	}

	*element = val;
out:
	kunmap_atomic(mem);
	return ret;
}

bool zcomp_available_algorithm(const char *algo_name)
{
	bool found;

	down_read(&zcomp_rwsem);
	found = find_zcomp(algo_name);
	up_read(&zcomp_rwsem);

	return found;
}

/* show available compressors */
ssize_t zcomp_available_show(const char *comp, char *buf)
{
	bool known_algorithm = false;
	ssize_t sz = 0;
	struct zcomp *zcomp;

	down_read(&zcomp_rwsem);
	list_for_each_entry (zcomp, &zcomp_list, list) {
		if (!strcmp(comp, zcomp->algo_name)) {
			known_algorithm = true;
			sz += scnprintf(buf + sz, PAGE_SIZE - sz - 2, "[%s] ", zcomp->algo_name);
		} else {
			sz += scnprintf(buf + sz, PAGE_SIZE - sz - 2, "%s ", zcomp->algo_name);
		}
	}
	sz += scnprintf(buf + sz, PAGE_SIZE - sz - 1, "%c", '\n');
	up_read(&zcomp_rwsem);

	/*
	 * XXX: handle Out-of-tree module known to crypto api or a
	 * mssing entry in backends'.
	 */
	return sz;
}

static inline bool zcomp_async(struct zcomp *comp)
{
	return comp->op->compress_async ? true : false;
}

/*
 * The caller needs to hold cookie_pool.lock
 */
static bool refill_zcomp_cookie(struct zcomp *zcomp)
{
	int i;
	struct zcomp_cookie *cookie;

	WARN_ON(zcomp->cookie_pool.count != 0);

	for (i = 0; i < BATCH_ZCOMP_REQUEST; i++) {
		cookie = kmalloc(sizeof(struct zcomp_cookie), GFP_ATOMIC);
		if (!cookie)
			break;
		list_add(&cookie->list, &zcomp->cookie_pool.head);
		zcomp->cookie_pool.count++;
	}

	return !zcomp->cookie_pool.count;
}

static struct zcomp_cookie *alloc_zcomp_cookie(struct zcomp *zcomp)
{
	struct zcomp_cookie *cookie = NULL;

	WARN_ON(in_interrupt());

	spin_lock(&zcomp->cookie_pool.lock);
	if (list_empty(&zcomp->cookie_pool.head)) {
		if (refill_zcomp_cookie(zcomp))
			goto out;
	}

	cookie = list_first_entry(&zcomp->cookie_pool.head, struct zcomp_cookie, list);
	list_del(&cookie->list);
	zcomp->cookie_pool.count--;
out:
	spin_unlock(&zcomp->cookie_pool.lock);

	return cookie;
}

static void free_zcomp_cookie(struct zcomp *zcomp, struct zcomp_cookie *cookie)
{
	spin_lock(&zcomp->cookie_pool.lock);
	list_add(&cookie->list, &zcomp->cookie_pool.head);
	zcomp->cookie_pool.count++;

	if (zcomp->cookie_pool.count >= BATCH_ZCOMP_REQUEST * 2) {
		int i;

		for (i = 0; i < BATCH_ZCOMP_REQUEST; i++) {
			cookie = list_last_entry(&zcomp->cookie_pool.head, struct zcomp_cookie,
						 list);
			list_del(&cookie->list);
			kfree(cookie);
			zcomp->cookie_pool.count--;
		}
	}
	spin_unlock(&zcomp->cookie_pool.lock);
}

static void init_zcomp_cookie_pool(struct zcomp *zcomp)
{
	INIT_LIST_HEAD(&zcomp->cookie_pool.head);
	spin_lock_init(&zcomp->cookie_pool.lock);
	zcomp->cookie_pool.count = 0;
}

static void destroy_zcomp_cookie_pool(struct zcomp *zcomp)
{
	struct zcomp_cookie *cookie;

	spin_lock(&zcomp->cookie_pool.lock);
	while (!list_empty(&zcomp->cookie_pool.head)) {
		cookie = list_first_entry(&zcomp->cookie_pool.head, struct zcomp_cookie, list);
		list_del(&cookie->list);
		kfree(cookie);
		zcomp->cookie_pool.count--;
	}
	spin_unlock(&zcomp->cookie_pool.lock);
}

static int flush_pending_io(struct zcomp *comp)
{
	int err = 0;
	LIST_HEAD(req_list);

	spin_lock(&comp->request_lock);
	list_splice_init(&comp->request_list, &req_list);
	spin_unlock(&comp->request_lock);

	while (!list_empty(&req_list)) {
		struct zcomp_cookie *cookie;

		cookie = list_last_entry(&req_list, struct zcomp_cookie, list);
		list_del(&cookie->list);
		if (comp->op->compress_async(comp, cookie->page, cookie)) {
			if (cookie->bio)
				bio_io_error(cookie->bio);
			err = -EIO;
		}
	}

	return err;
}

static void zram_unplug(struct blk_plug_cb *cb, bool from_schedule)
{
	flush_pending_io((struct zcomp *)(cb->data));
	kfree(cb);
}

/*
 * If the comp is plugged, append the cookie to request list and return true
 * otherwise, return false.
 */
static void zram_append_request(struct zcomp *comp, struct zcomp_cookie *cookie)
{
	spin_lock(&comp->request_lock);
	list_add(&cookie->list, &comp->request_list);
	spin_unlock(&comp->request_lock);
}

static void zram_cache_append(struct zcomp *comp, u32 index, struct page *page)
{
	struct zram_cache_node *node;
	void *src;

	node = allocate_buffer_cache();
	if (node == NULL)
		BUG();

	//spin_lock(&cache_spinlock);
	node->next = NULL;
	node->index = index;

	if (cache_list.last_node == NULL) {
		cache_list.last_node = node;
		node->prev = cache_list.start_node;
		cache_list.start_node->next = node;
	} else {
		cache_list.last_node->next = node;
		node->prev = cache_list.last_node;
		cache_list.last_node = node;
	}
	cache_list.size++;
	src = kmap_atomic(page);
	memcpy(node->page_data, src, PAGE_SIZE);
	kunmap_atomic(src);
	//spin_unlock(&cache_spinlock);

	zram_slot_update_cache(comp->zram, index);
}

static void zram_compress_cache_async(struct zcomp *comp, struct bio *bio)
{
	struct zcomp_cookie stack_cookie;
	struct zram_cache_node *node = cache_list.start_node->next;
	if (!node) {
		printk("NULL Pointer !!!!!!!!!!!!!!!!!!!!!!!!");
		return;
	}
	//spin_lock(&cache_spinlock);
	cache_list.start_node->next = node->next;
	if (node->next)
		node->next->prev = cache_list.start_node;
	cache_list.size--;

	stack_cookie.zram = comp->zram;
	stack_cookie.index = node->index;
	stack_cookie.bio = bio;
	//spin_unlock(&cache_spinlock);
	if (comp->op->compress_cache)
		comp->op->compress_cache(comp, node->page_data, &stack_cookie);
	else
		printk("NULL Function Pointer !!!!!!!!!!!!!!!!!!!!!!!!");

	free_buffer_cache(node);
}

int zcomp_compress(struct zcomp *comp, u32 index, struct page *page, struct bio *bio)
{
	/*
	 * Async IO should return 1 instead of 0 to indicate
	 * IO submit is successful because IO completion
	 * callback should be handled at different context.
	 */
	int ret = 1;
	void *src;
	unsigned long element;
	unsigned long flags;
	int i;
	struct zcomp_cookie *cookie;

	if (zcomp_page_same_pattern(page, &element)) {
		zram_slot_update(comp->zram, index, element, 0);
		return 0;
	}

	if (cache_list.size < LRU_SIZE) {
		zram_cache_append(comp, index, page);
		if (cache_list.size > 200) {
			for ( i = 0; i < ZCOMP_BATCH_SIZE; ++i)
				zram_compress_cache_async(comp, bio);
		}
		return 0;
	}

	if (!zcomp_async(comp)) {
		struct zcomp_cookie stack_cookie;

		cookie = &stack_cookie;
		cookie->zram = comp->zram;
		cookie->index = index;
		cookie->page = page;
		cookie->bio = bio;

		return comp->op->compress(comp, page, cookie);
	}

	cookie = alloc_zcomp_cookie(comp);
	if (!cookie)
		return -ENOMEM;

	cookie->zram = comp->zram;
	cookie->index = index;
	cookie->page = page;
	cookie->bio = bio;
	/*
	 * Since __zram_make_request has bio_endio, zcomp_async needs
	 * to hold the bio completion until the IO request is done if
	 * the IO is submitted successfully. zcomp_copy_buffer in
	 * zcomp instance will handle it. If the IO submission fails,
	 * we release the bio chain here so that __zram_make_request's
	 * bio_endio will finally call the IO completion to handle
	 * the error propagation.
	 */
	if (bio)
		bio_inc_remaining(bio);

	if (blk_check_plugged(zram_unplug, comp, sizeof(struct blk_plug_cb))) {
		zram_append_request(comp, cookie);
	} else {
		flush_pending_io(comp);
		if (comp->op->compress_async(comp, page, cookie)) {
			if (cookie->bio)
				bio_io_error(cookie->bio);
			ret = -EIO;
		}
	}

	return ret;
}

int zcomp_decompress(struct zcomp *comp, u32 index, struct page *page)
{
	int ret = 0;
	void *dst, *src;
	unsigned int src_len;
	unsigned long handle;
	struct zram_cache_node *cache;
	struct zram *zram = comp->zram;
	unsigned long flags;

	handle = zram_get_handle(zram, index);

	if (zram_test_flag(zram, index, ZRAM_CACHE)) {
		find_index_from_cache_list(index, page);
		goto out;
	}

	if ((!handle || zram_test_flag(zram, index, ZRAM_SAME))) {
		unsigned long val = handle ? zram_get_element(zram, index) : 0;
		dst = kmap_atomic(page);
		zcomp_fill_page(dst, PAGE_SIZE, val);
		kunmap_atomic(dst);
		goto out;
	}

	src_len = zram_get_obj_size(zram, index);
	if (src_len == PAGE_SIZE) {
		src = zs_map_object(zram->mem_pool, handle, ZS_MM_RO);
		dst = kmap_atomic(page);
		memcpy(dst, src, PAGE_SIZE);
		kunmap_atomic(dst);
		zs_unmap_object(zram->mem_pool, handle);
		goto out;
	}

	src = zs_map_object(zram->mem_pool, handle, ZS_MM_RO);
	trace_zcomp_decompress_start(page, index);
	ret = comp->op->decompress(comp, src, src_len, page);
	trace_zcomp_decompress_end(page, index);
	zs_unmap_object(zram->mem_pool, handle);
out:

	return ret;
}

void zcomp_destroy(struct zcomp *comp)
{
	comp->op->destroy(comp);
	if (zcomp_async(comp))
		destroy_zcomp_cookie_pool(comp);
}

/*
 * search available compressors for requested algorithm.
 * allocate new zcomp and initialize it. return compressing
 * backend pointer or ERR_PTR if things went bad. ERR_PTR(-EINVAL)
 * if requested algorithm is not supported, ERR_PTR(-ENOMEM) in
 * case of allocation error, or any other error potentially
 * returned by zcomp_create().
 */
struct zcomp *zcomp_create(const char *algo_name, struct zram *zram)
{
	struct zcomp *comp;
	int error;

	down_read(&zcomp_rwsem);
	comp = find_zcomp(algo_name);
	if (!comp) {
		up_read(&zcomp_rwsem);
		return ERR_PTR(-EINVAL);
	}

	error = comp->op->create(comp, algo_name);
	if (error) {
		up_read(&zcomp_rwsem);
		return ERR_PTR(error);
	}

	if (zcomp_async(comp)) {
		init_zcomp_cookie_pool(comp);
		INIT_LIST_HEAD(&comp->request_list);
		spin_lock_init(&comp->request_lock);
	}
	comp->zram = zram;
	up_read(&zcomp_rwsem);

	return comp;
}

/*
 * Once zcomp instance finishes the compression, it need to copy the compressed
 * buffer to zram's memory space.
 *
 * @err: the error from zcomp instance
 * @buffer: memory address compressed objecd is stored
 * @comp_len: compressed object size
 * @cookie: the one we got when comopress function is called
 */
int zcomp_copy_buffer(int err, void *buffer, int comp_len, struct zcomp_cookie *cookie)
{
	void *dst_addr;
	unsigned long handle;
	struct zram *zram = cookie->zram;
	struct page *page = cookie->page;
	struct bio *bio = cookie->bio;
	u32 index = cookie->index;

	if (err)
		goto out;
	/*static struct task_struct *async_thread;

	 * Pages that compress to sizes equals or greater than this are stored
	 * uncompressed in memory to make decompress fast.
	 */
	if (comp_len >= zs_huge_class_size(zram->mem_pool))
		comp_len = PAGE_SIZE;

	handle = zs_malloc(zram->mem_pool, comp_len,
			   __GFP_KSWAPD_RECLAIM | __GFP_NOWARN | __GFP_HIGHMEM | __GFP_MOVABLE |
				   __GFP_CMA);
	if (!handle) {
		err = -ENOMEM;
		goto out;
	}

	dst_addr = zs_map_object(zram->mem_pool, handle, ZS_MM_WO);
	if (comp_len == PAGE_SIZE) {
		void *src = kmap_atomic(page);

		memcpy(dst_addr, src, comp_len);
		kunmap_atomic(src);
	} else {
		memcpy(dst_addr, buffer, comp_len);
	}
	zs_unmap_object(zram->mem_pool, handle);
	zram_slot_update(zram, index, handle, comp_len);
out:
	if (zcomp_async(zram->comp)) {
		if (!bio) { /* rw_page case */
			zram_page_write_endio(zram, page, err);
		} else {
			zram_bio_endio(zram, bio, true, err);
		}

		free_zcomp_cookie(zram->comp, cookie);
	}

	return err;
}
EXPORT_SYMBOL(zcomp_copy_buffer);

int zcomp_copy_buffer_cache(int err, void *buffer, int comp_len, struct zcomp_cookie *cookie)
{
	void *dst_addr;
	unsigned long handle;
	struct zram *zram = cookie->zram;
	struct bio *bio = cookie->bio;
	u32 index = cookie->index;

	if (err)
		goto out;
	/*static struct task_struct *async_thread;

	 * Pages that compress to sizes equals or greater than this are stored
	 * uncompressed in memory to make decompress fast.
	 */
	if (comp_len >= zs_huge_class_size(zram->mem_pool))
		comp_len = PAGE_SIZE;

	handle = zs_malloc(zram->mem_pool, comp_len,
			   __GFP_KSWAPD_RECLAIM | __GFP_NOWARN | __GFP_HIGHMEM | __GFP_MOVABLE |
				   __GFP_CMA);
	if (!handle) {
		err = -ENOMEM;
		goto out;
	}

	dst_addr = zs_map_object(zram->mem_pool, handle, ZS_MM_WO);

	memcpy(dst_addr, buffer, comp_len);

	zs_unmap_object(zram->mem_pool, handle);
	zram_slot_update(zram, index, handle, comp_len);
out:

	return err;
}
EXPORT_SYMBOL(zcomp_copy_buffer_cache);

struct zcomp_strm *zcomp_stream_get(struct zcomp *comp)
{
	struct zcomp_strm *zstrm = comp->private;

	local_lock(&zstrm->lock);
	return this_cpu_ptr(zstrm);
}
EXPORT_SYMBOL(zcomp_stream_get);

static struct task_struct *async_thread;

static void zcomp_copy_cache_to_compress()
{
	int i, err;
	unsigned long flags;

	if (cache_list.size < (ZCOMP_BATCH_SIZE))
		return;

	for (i = 0; i < ZCOMP_BATCH_SIZE; ++i) {
		//zram_compress_cache_async();
	}
	return;
}

static int zcomp_async_thread(void *data)
{
	set_cpus_allowed_ptr(current, cpumask_of(5));

	while (!kthread_should_stop()) {
		// Do some work here
		//zcomp_copy_cache_to_compress();
		// Sleep for 1 second
		printk("List Size %lu", cache_list.size);
		ssleep(1);
	}
	return 0;
}

void zcomp_cpu_thread(void)
{
	printk(KERN_ERR "Initializing zcomp kernel module\n");

	// Create kernel thread
	async_thread = kthread_create(zcomp_async_thread, NULL, "zcomp_async_thread");
	if (async_thread) {
		// Start the thread
		struct sched_param params = { .sched_priority = MAX_RT_PRIO - 1 };
		sched_setscheduler(async_thread, SCHED_FIFO, &params);
		wake_up_process(async_thread);
	} else {
		printk(KERN_ERR "Failed to create thread\n");
	}
}
EXPORT_SYMBOL(zcomp_cpu_thread);
