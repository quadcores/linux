/*
 * Copyright (C) 2015 Fujitsu.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */
#include "ctree.h"
#include "dedup.h"
#include "btrfs_inode.h"
#include "transaction.h"
#include "delayed-ref.h"

struct inmem_hash {
	struct rb_node hash_node;
	struct rb_node bytenr_node;
	struct list_head lru_list;

	u64 bytenr;
	u32 num_bytes;

	u8 hash[];
};

static inline struct inmem_hash *inmem_alloc_hash(u16 type)
{
	if (WARN_ON(type >= ARRAY_SIZE(btrfs_dedup_sizes)))
		return NULL;
	return kzalloc(sizeof(struct inmem_hash) + btrfs_dedup_sizes[type],
			GFP_NOFS);
}

int btrfs_dedup_enable(struct btrfs_fs_info *fs_info, u16 type, u16 backend,
		       u64 blocksize, u64 limit)
{
	struct btrfs_dedup_info *dedup_info;
	int ret = 0;

	/* Sanity check */
	if (blocksize > BTRFS_DEDUP_BLOCKSIZE_MAX ||
	    blocksize < BTRFS_DEDUP_BLOCKSIZE_MIN ||
	    blocksize < fs_info->tree_root->sectorsize ||
	    !is_power_of_2(blocksize))
		return -EINVAL;
	if (type > ARRAY_SIZE(btrfs_dedup_sizes))
		return -EINVAL;
	if (backend >= BTRFS_DEDUP_BACKEND_LAST)
		return -EINVAL;
	if (backend == BTRFS_DEDUP_BACKEND_INMEMORY && limit == 0)
		limit = 4096; /* default value */
	if (backend == BTRFS_DEDUP_BACKEND_ONDISK && limit != 0)
		limit = 0;

	if (fs_info->dedup_info) {
		dedup_info = fs_info->dedup_info;

		/* Check if we are re-enable for different dedup config */
		if (dedup_info->blocksize != blocksize ||
		    dedup_info->hash_type != type ||
		    dedup_info->backend != backend) {
			btrfs_dedup_disable(fs_info);
			goto enable;
		}

		/* On-fly limit change is OK */
		mutex_lock(&dedup_info->lock);
		fs_info->dedup_info->limit_nr = limit;
		mutex_unlock(&dedup_info->lock);
		return 0;
	}

enable:
	fs_info->dedup_info = kzalloc(sizeof(*dedup_info), GFP_NOFS);
	if (!fs_info->dedup_info)
		return -ENOMEM;

	dedup_info = fs_info->dedup_info;

	dedup_info->hash_type = type;
	dedup_info->backend = backend;
	dedup_info->blocksize = blocksize;
	dedup_info->limit_nr = limit;

	/* Only support SHA256 yet */
	dedup_info->dedup_driver = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(dedup_info->dedup_driver)) {
		btrfs_err(fs_info, "failed to init sha256 driver");
		ret = PTR_ERR(dedup_info->dedup_driver);
		goto out;
	}

	dedup_info->hash_root = RB_ROOT;
	dedup_info->bytenr_root = RB_ROOT;
	dedup_info->current_nr = 0;
	INIT_LIST_HEAD(&dedup_info->lru_list);
	mutex_init(&dedup_info->lock);

	fs_info->dedup_info = dedup_info;
out:
	if (ret < 0) {
		kfree(dedup_info);
		fs_info->dedup_info = NULL;
	}
	return ret;
}

static int inmem_insert_hash(struct rb_root *root,
			     struct inmem_hash *hash, int hash_len)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct inmem_hash *entry = NULL;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct inmem_hash, hash_node);
		if (memcmp(hash->hash, entry->hash, hash_len) < 0)
			p = &(*p)->rb_left;
		else if (memcmp(hash->hash, entry->hash, hash_len) > 0)
			p = &(*p)->rb_right;
		else
			return 1;
	}
	rb_link_node(&hash->hash_node, parent, p);
	rb_insert_color(&hash->hash_node, root);
	return 0;
}

static int inmem_insert_bytenr(struct rb_root *root,
			       struct inmem_hash *hash)
{
	struct rb_node **p = &root->rb_node;
	struct rb_node *parent = NULL;
	struct inmem_hash *entry = NULL;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct inmem_hash, bytenr_node);
		if (hash->bytenr < entry->bytenr)
			p = &(*p)->rb_left;
		else if (hash->bytenr > entry->bytenr)
			p = &(*p)->rb_right;
		else
			return 1;
	}
	rb_link_node(&hash->bytenr_node, parent, p);
	rb_insert_color(&hash->bytenr_node, root);
	return 0;
}

static void __inmem_del(struct btrfs_dedup_info *dedup_info,
			struct inmem_hash *hash)
{
	list_del(&hash->lru_list);
	rb_erase(&hash->hash_node, &dedup_info->hash_root);
	rb_erase(&hash->bytenr_node, &dedup_info->bytenr_root);

	if (!WARN_ON(dedup_info->current_nr == 0))
		dedup_info->current_nr--;

	kfree(hash);
}

/*
 * Insert a hash into in-memory dedup tree
 * Will remove exceeding last recent use hash.
 *
 * If the hash mathced with existing one, we won't insert it, to
 * save memory
 */
static int inmem_add(struct btrfs_dedup_info *dedup_info,
		     struct btrfs_dedup_hash *hash)
{
	int ret = 0;
	u16 type = dedup_info->hash_type;
	struct inmem_hash *ihash;

	ihash = inmem_alloc_hash(type);

	if (!ihash)
		return -ENOMEM;

	/* Copy the data out */
	ihash->bytenr = hash->bytenr;
	ihash->num_bytes = hash->num_bytes;
	memcpy(ihash->hash, hash->hash, btrfs_dedup_sizes[type]);

	mutex_lock(&dedup_info->lock);

	ret = inmem_insert_bytenr(&dedup_info->bytenr_root, ihash);
	if (ret > 0) {
		kfree(ihash);
		ret = 0;
		goto out;
	}

	ret = inmem_insert_hash(&dedup_info->hash_root, ihash,
				btrfs_dedup_sizes[type]);
	if (ret > 0) {
		/*
		 * We only keep one hash in tree to save memory, so if
		 * hash conflicts, free the one to insert.
		 */
		rb_erase(&ihash->bytenr_node, &dedup_info->bytenr_root);
		kfree(ihash);
		ret = 0;
		goto out;
	}

	list_add(&ihash->lru_list, &dedup_info->lru_list);
	dedup_info->current_nr++;

	/* Remove the last dedup hash if we exceed limit */
	while (dedup_info->current_nr > dedup_info->limit_nr) {
		struct inmem_hash *last;

		last = list_entry(dedup_info->lru_list.prev,
				  struct inmem_hash, lru_list);
		__inmem_del(dedup_info, last);
	}
out:
	mutex_unlock(&dedup_info->lock);
	return 0;
}

int btrfs_dedup_add(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		    struct btrfs_dedup_hash *hash)
{
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_dedup_info *dedup_info = fs_info->dedup_info;

	if (!dedup_info || !hash)
		return 0;

	if (WARN_ON(hash->bytenr == 0))
		return -EINVAL;

	if (dedup_info->backend == BTRFS_DEDUP_BACKEND_INMEMORY)
		return inmem_add(dedup_info, hash);
	return -EINVAL;
}

static struct inmem_hash *
inmem_search_bytenr(struct btrfs_dedup_info *dedup_info, u64 bytenr)
{
	struct rb_node **p = &dedup_info->bytenr_root.rb_node;
	struct rb_node *parent = NULL;
	struct inmem_hash *entry = NULL;

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct inmem_hash, bytenr_node);

		if (bytenr < entry->bytenr)
			p = &(*p)->rb_left;
		else if (bytenr > entry->bytenr)
			p = &(*p)->rb_right;
		else
			return entry;
	}

	return NULL;
}

/* Delete a hash from in-memory dedup tree */
static int inmem_del(struct btrfs_dedup_info *dedup_info, u64 bytenr)
{
	struct inmem_hash *hash;

	mutex_lock(&dedup_info->lock);
	hash = inmem_search_bytenr(dedup_info, bytenr);
	if (!hash) {
		mutex_unlock(&dedup_info->lock);
		return 0;
	}

	__inmem_del(dedup_info, hash);
	mutex_unlock(&dedup_info->lock);
	return 0;
}

/* Remove a dedup hash from dedup tree */
int btrfs_dedup_del(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		    u64 bytenr)
{
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_dedup_info *dedup_info = fs_info->dedup_info;

	if (!dedup_info)
		return 0;

	if (dedup_info->backend == BTRFS_DEDUP_BACKEND_INMEMORY)
		return inmem_del(dedup_info, bytenr);
	return -EINVAL;
}

static void inmem_destroy(struct btrfs_fs_info *fs_info)
{
	struct inmem_hash *entry, *tmp;
	struct btrfs_dedup_info *dedup_info = fs_info->dedup_info;

	mutex_lock(&dedup_info->lock);
	list_for_each_entry_safe(entry, tmp, &dedup_info->lru_list, lru_list)
		__inmem_del(dedup_info, entry);
	mutex_unlock(&dedup_info->lock);
}

int btrfs_dedup_disable(struct btrfs_fs_info *fs_info)
{
	struct btrfs_dedup_info *dedup_info = fs_info->dedup_info;

	if (!dedup_info)
		return 0;

	if (dedup_info->backend == BTRFS_DEDUP_BACKEND_INMEMORY)
		inmem_destroy(fs_info);
	return 0;
}

/*
 * Caller must ensure the corresponding ref head is not being run.
 */
static struct inmem_hash *
inmem_search_hash(struct btrfs_dedup_info *dedup_info, u8 *hash)
{
	struct rb_node **p = &dedup_info->hash_root.rb_node;
	struct rb_node *parent = NULL;
	struct inmem_hash *entry = NULL;
	u16 hash_type = dedup_info->hash_type;
	int hash_len = btrfs_dedup_sizes[hash_type];

	while (*p) {
		parent = *p;
		entry = rb_entry(parent, struct inmem_hash, hash_node);

		if (memcmp(hash, entry->hash, hash_len) < 0) {
			p = &(*p)->rb_left;
		} else if (memcmp(hash, entry->hash, hash_len) > 0) {
			p = &(*p)->rb_right;
		} else {
			/* Found, need to re-add it to LRU list head */
			list_del(&entry->lru_list);
			list_add(&entry->lru_list, &dedup_info->lru_list);
			return entry;
		}
	}
	return NULL;
}

static int inmem_search(struct inode *inode, u64 file_pos,
			struct btrfs_dedup_hash *hash)
{
	int ret;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_trans_handle *trans;
	struct btrfs_delayed_ref_root *delayed_refs;
	struct btrfs_delayed_ref_head *head;
	struct inmem_hash *found_hash;
	struct btrfs_dedup_info *dedup_info = fs_info->dedup_info;
	u64 bytenr;
	u32 num_bytes;

	trans = btrfs_join_transaction(root);
	if (IS_ERR(trans))
		return PTR_ERR(trans);

again:
	mutex_lock(&dedup_info->lock);
	found_hash = inmem_search_hash(dedup_info, hash->hash);
	/* If we don't find a duplicated extent, just return. */
	if (!found_hash) {
		ret = 0;
		goto out;
	}
	bytenr = found_hash->bytenr;
	num_bytes = found_hash->num_bytes;

	delayed_refs = &trans->transaction->delayed_refs;

	spin_lock(&delayed_refs->lock);
	head = btrfs_find_delayed_ref_head(trans, bytenr);
	if (!head) {
		/*
		 * We can safely insert a new delayed_ref as long as we
		 * hold delayed_refs->lock.
		 * Only need to use atomic inc_extent_ref()
		 */
		ret = btrfs_inc_extent_ref_atomic(trans, root, bytenr,
				num_bytes, 0, root->root_key.objectid,
				btrfs_ino(inode), file_pos);
		spin_unlock(&delayed_refs->lock);

		if (ret == 0) {
			hash->bytenr = bytenr;
			hash->num_bytes = num_bytes;
			ret = 1;
		}
		goto out;
	}

	/*
	 * We can't lock ref head with dedup_info->lock hold or we will cause
	 * ABBA dead lock.
	 */
	mutex_unlock(&dedup_info->lock);
	ret = btrfs_delayed_ref_lock(trans, head);
	spin_unlock(&delayed_refs->lock);
	if (ret == -EAGAIN)
		goto again;

	mutex_lock(&dedup_info->lock);
	/* Search again to ensure the hash is still here */
	found_hash = inmem_search_hash(dedup_info, hash->hash);
	if (!found_hash) {
		ret = 0;
		mutex_unlock(&head->mutex);
		goto out;
	}
	hash->bytenr = bytenr;
	hash->num_bytes = num_bytes;

	/*
	 * Increase the extent ref right now, to avoid delayed ref run
	 * Or we may increase ref on non-exist extent.
	 */
	btrfs_inc_extent_ref(trans, root, bytenr, num_bytes, 0,
			     root->root_key.objectid,
			     btrfs_ino(inode), file_pos);
	mutex_unlock(&head->mutex);
out:
	mutex_unlock(&dedup_info->lock);
	btrfs_end_transaction(trans, root);

	return ret;
}

int btrfs_dedup_search(struct inode *inode, u64 file_pos,
		       struct btrfs_dedup_hash *hash)
{
	struct btrfs_fs_info *fs_info = BTRFS_I(inode)->root->fs_info;
	struct btrfs_dedup_info *dedup_info = fs_info->dedup_info;
	int ret = 0;

	if (WARN_ON(!dedup_info || !hash))
		return 0;

	if (dedup_info->backend == BTRFS_DEDUP_BACKEND_INMEMORY)
		ret = inmem_search(inode, file_pos, hash);

	/* It's possible hash->bytenr/num_bytenr already changed */
	if (ret == 0) {
		hash->num_bytes = 0;
		hash->bytenr = 0;
	}
	return ret;
}
