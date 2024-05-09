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
#include <linux/page-flags.h>
#include <linux/bio.h>

#define CREATE_TRACE_POINTS
#include <trace/events/zram.h>

#include "zram_drv.h"
#include "zcomp.h"

extern volatile __u8  decompress_on;
extern __u8 new_algo_on;
#define ZCOMP_ALGO_NAME_MAX 64

struct zcomp_backend {
	const char algo_name[ZCOMP_ALGO_NAME_MAX];
	struct zcomp_operation *op;
};

/* zcomp_backend list registered by zcomp instances */
static LIST_HEAD(zcomp_list);
static DECLARE_RWSEM(zcomp_rwsem);

/* caller should hold a zcomp_rwsem under semaphore */
struct zcomp *find_zcomp(const char *algo_name)
{
	struct zcomp *cursor, *ret = NULL;

	list_for_each_entry(cursor, &zcomp_list, list) {
		if (!strcmp(cursor->algo_name, algo_name)) {
			ret = cursor;
			break;
		}
	}

	return ret;
}

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
	list_for_each_entry(cursor, &zcomp_list, list) {
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

static void zcomp_fill_page(void *ptr, unsigned long len,
					unsigned long value)
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
	list_for_each_entry(zcomp, &zcomp_list, list) {
		if (!strcmp(comp, zcomp->algo_name)) {
			known_algorithm = true;
			sz += scnprintf(buf + sz, PAGE_SIZE - sz - 2,
					"[%s] ", zcomp->algo_name);
		} else {
			sz += scnprintf(buf + sz, PAGE_SIZE - sz - 2,
					"%s ", zcomp->algo_name);
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

	cookie = list_first_entry(&zcomp->cookie_pool.head,
					struct zcomp_cookie, list);
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
			cookie = list_last_entry(&zcomp->cookie_pool.head,
						struct zcomp_cookie, list);
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
		cookie = list_first_entry(&zcomp->cookie_pool.head,
					struct zcomp_cookie, list);
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

extern unsigned int compress_amount;
extern pid_t track_pid;
extern unsigned int slot_cache;
extern unsigned int slot_lzo_rle;
extern unsigned int slot_non_important_lzo_rle;
extern unsigned int slot_zstd;

int zcomp_compress(struct zcomp *comp, u32 index, struct page *page, struct bio *bio)
{
	/*
	 * Async IO should return 1 instead of 0 to indicate
	 * IO submit is successful because IO completion
	 * callback should be handled at different context.
	 */
	int ret = 1;
	unsigned long element;
	struct zcomp_cookie *cookie;


	comp->zram->table[index].comp_time = ktime_get_boottime();
	if (decompress_on && current->group_leader->pid == track_pid)
		compress_amount++;
	
	if (zcomp_page_same_pattern(page, &element)) {
		zram_slot_update(comp->zram, index, element, 0);
		return 0;
	}

	if (!zcomp_async(comp)) {
		struct zcomp_cookie stack_cookie;

		cookie = &stack_cookie;
		cookie->zram = comp->zram;
		cookie->index = index;
		cookie->page = page;
		cookie->bio = bio;

		if (new_algo_on > 0) {
			if (PageCachezram(page)) {
				comp->zram->table[index].non_zstd = 1;
				ret = comp->op->cache_compress(comp, page, cookie);
				slot_cache++;
			} else if (PageLzorle(page)) {
				comp->zram->table[index].non_zstd = 2;
				ret = comp->op->compress(comp, page, cookie);
				slot_lzo_rle++;
			} else{
				comp->zram->table[index].non_zstd = 3;
				ret = comp->op->compress(comp, page, cookie);
				slot_non_important_lzo_rle++;
			}
		} else {
			ret = comp->op->compress(comp, page, cookie);
		}
		return ret;
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

int zcomp_compress_to_lzo_rle(struct zram *zram, u32 index)
{
	void *src;
	int ret;
	unsigned int src_len;
	static u8 page_buff[PAGE_SIZE];
	static struct zcomp_cookie cookie;
	unsigned long handle = zram_get_handle(zram, index);

	if (!handle || zram->table[index].non_zstd != 1)
		return 0;
	
	src_len = zram_get_obj_size(zram, index);
	src = zs_map_object(zram->mem_pool, handle, ZS_MM_RO);
	memcpy(page_buff, src, PAGE_SIZE);

	
	zs_unmap_object(zram->mem_pool, handle);
	cookie.zram = zram;
	cookie.index = index;

	ret = zram->comp->op->cache_recompress(zram->comp, page_buff, &cookie);
	zram->table[index].non_zstd = 2;
	slot_cache--;
	slot_lzo_rle++;
	
	return 0;

}
int zcomp_compress_to_zstd(struct zram *zram, u32 index)
{
	void *src;
	int ret;
	unsigned int src_len;
	static u8 page_buff[PAGE_SIZE];
	static struct zcomp_cookie cookie;
	unsigned long handle = zram_get_handle(zram, index);

	if (!handle || zram_test_flag(zram, index, ZRAM_SAME))
		return 0;
	
	src_len = zram_get_obj_size(zram, index);
	src = zs_map_object(zram->mem_pool, handle, ZS_MM_RO);
	if (src_len == PAGE_SIZE) 
		memcpy(page_buff, src, PAGE_SIZE);
	else  
		ret = zram->comp->op->dest_decompress(zram->comp, src, src_len, page_buff);
	
	zs_unmap_object(zram->mem_pool, handle);
	cookie.zram = zram;
	cookie.index = index;

	ret = zram->comp->op->zstd_compress(zram->comp, page_buff, &cookie);

	zram_set_flag(zram, index, ZRAM_ZSTD);
	zram->table[index].non_zstd = 4;
	slot_non_important_lzo_rle--;
	slot_zstd++;
	return 0;

}
extern unsigned int decompress_amount_no_sync;
extern unsigned int decompress_amount_no_sync_zstd;
extern unsigned int decompress_amount_sync;
extern unsigned int decompress_amount_zstd;
extern unsigned int decompress_amount_lzo_rle;
extern unsigned int decompress_amount_cache;
extern volatile __u32 expire;

int zcomp_decompress(struct zcomp *comp, u32 index, struct page *page)
{
	int ret = 0;
	void *dst, *src;
	unsigned int src_len;
	unsigned long handle;
	struct zram *zram = comp->zram;

	if (new_algo_on > 0) {
		if (decompress_on) {
			if (current->group_leader->pid == track_pid) {
				decompress_amount_sync++;
				SetPageCachezram(page);

				if (zram_test_flag(zram, index, ZRAM_ZSTD)) {
					decompress_amount_zstd++;
					slot_zstd--;
				} else if (zram->table[index].non_zstd == 2) {
					decompress_amount_lzo_rle++;
					slot_lzo_rle--;
				} else if (zram->table[index].non_zstd == 1) {
					slot_cache--;
					decompress_amount_cache++;
				} else {
					slot_non_important_lzo_rle--;
				}
			} else {
				decompress_amount_no_sync++;
				if (zram_test_flag(zram, index, ZRAM_ZSTD)) {
					decompress_amount_no_sync_zstd++;
					slot_zstd--;
				} else if (zram->table[index].non_zstd == 1) {
					SetPageCachezram(page);
					slot_cache--;
				} else {
					SetPageLzorle(page);
					if (zram->table[index].non_zstd == 2)
						slot_lzo_rle--;
					else
						slot_non_important_lzo_rle--;
				}
			}
		} else if (new_algo_on == 2) {
			if (zram->table[index].non_zstd == 2) {
				SetPageLzorle(page);
				slot_lzo_rle--;

			} else if (zram->table[index].non_zstd == 1) {
				SetPageCachezram(page);
				slot_cache--;
			} else if (zram_test_flag(zram, index, ZRAM_ZSTD)) {
				slot_zstd--;
			} else {
				slot_non_important_lzo_rle--;
			}
		}
	}

	zram->table[index].non_zstd = 0;
	zram->table[index].comp_time = 0;
	comp->zram->table[index].switch_cnt = -1;

	handle = zram_get_handle(zram, index);
	if (!handle || zram_test_flag(zram, index, ZRAM_SAME)) {
		unsigned long val = handle ? zram_get_element(zram, index) : 0;

		dst = kmap_atomic(page);
		zcomp_fill_page(dst, PAGE_SIZE, val);
		kunmap_atomic(dst);
		goto out;
	}

	// Page cache here too.
	src_len = zram_get_obj_size(zram, index);
	if (src_len == PAGE_SIZE) {
		src = zs_map_object(zram->mem_pool, handle, ZS_MM_RO);
		dst = kmap_atomic(page);
		memcpy(dst, src, PAGE_SIZE);
		kunmap_atomic(dst);
		zs_unmap_object(zram->mem_pool, handle);
		goto out;
	}

	
	trace_zcomp_decompress_start(page, index);
	if (zram_test_flag(zram, index, ZRAM_ZSTD)) {
		src = zs_map_object(zram->mem_pool, handle, ZS_MM_RO);
		ret = comp->op->zstd_decompress(comp, src, src_len, page);
		zs_unmap_object(zram->mem_pool, handle);
	} else {
		src = zs_map_object(zram->mem_pool, handle, ZS_MM_RO);
		ret = comp->op->decompress(comp, src, src_len, page);
		zs_unmap_object(zram->mem_pool, handle);

	}
	trace_zcomp_decompress_end(page, index);
	
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
int zcomp_copy_buffer(int err, void *buffer, int comp_len,
		      struct zcomp_cookie *cookie)
{
	void *dst_addr;
	unsigned long handle;
	struct zram *zram = cookie->zram;
	struct page *page = cookie->page;
	struct bio *bio = cookie->bio;
	u32 index = cookie->index;

	if (err)
		goto out;
	/*
	 * Pages that compress to sizes equals or greater than this are stored
	 * uncompressed in memory to make decompress fast.
	 */
	if (comp_len >= zs_huge_class_size(zram->mem_pool))
		comp_len = PAGE_SIZE;

	handle = zs_malloc(zram->mem_pool, comp_len,
			__GFP_KSWAPD_RECLAIM |
			__GFP_NOWARN |
			__GFP_HIGHMEM |
			__GFP_MOVABLE |
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
