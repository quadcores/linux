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

#ifndef __BTRFS_CBS__
#define __BTRFS_CBS__

#include <linux/btrfs.h>
#include <crypto/hash.h>

/*
 * Cbs storage backend
 * On disk is persist storage but overhead is large
 * In memory is fast but will lose all its hash on umount
 */

/* Hash algorithm, only support SHA256 yet */
#define BTRFS_CBS_HASH_SHA256		0

static int btrfs_cbs_sizes[] = { 32 };

/*
 * For caller outside of cbs.c
 *
 */
struct btrfs_cbs_hash {
	u64 bytenr;
	u32 num_bytes;
	u64 inode_no;
	/* last field is a variable length array of cbs hash */
	u8 hash[];
};

struct btrfs_root;

struct btrfs_cbs_info {
	u16 hash_type;

	struct crypto_shash *cbs_driver;
	struct mutex lock;

	/* for persist data like cbs-hash and cbs status */
	struct btrfs_root *cbs_root;
};

struct btrfs_trans_handle;

static inline int btrfs_cbs_hash_size(u16 type)
{
	if (WARN_ON(type >= ARRAY_SIZE(btrfs_cbs_sizes)))
		return -EINVAL;
	return sizeof(struct btrfs_cbs_hash) + btrfs_cbs_sizes[type];
}

static inline struct btrfs_cbs_hash *btrfs_cbs_alloc_hash(u16 type)
{
	return kzalloc(btrfs_cbs_hash_size(type), GFP_NOFS);
}

/*
 * Called at cbs enable time.
 */
int btrfs_cbs_enable(struct btrfs_fs_info *fs_info, u16 type);

/*
 * Disable cbs and invalidate all its cbs data.
 * Called at cbs disable time.
 */
int btrfs_cbs_disable(struct btrfs_fs_info *fs_info);

/*
 * Restore previous cbs setup from disk
 * Called at mount time
 */
int btrfs_cbs_resume(struct btrfs_fs_info *fs_info,
		       struct btrfs_root *cbs_root);

/*
 * Free current btrfs_cbs_info
 * Called at umount(close_ctree) time
 */
int btrfs_cbs_cleanup(struct btrfs_fs_info *fs_info);

/*
 * Calculate hash for cbs (hash of the complete file).
 * Caller must ensure [start, end] has valid data.
 */
int btrfs_cbs_calc_hash(struct btrfs_root *root, struct inode *inode,
			  u64 start, u64 end, struct btrfs_cbs_hash *hash);

/*
 * Converts the 64 byte name recieved from userspace to 32 byte hash.
 * Later, calls ondisk_search_hash to fetch inode_no from hash vs inode cbs tree.
 */

unsigned long prepare_hash(struct inode *dir, const char* name);

/*
 * Search for duplicated extents by calculated hash
 * Caller must call btrfs_cbs_calc_hash() first to get the hash.
 *
 * @inode: the inode for we are writing
 * @file_pos: offset inside the inode
 * As we will increase extent ref immediately after a hash match,
 * we need @file_pos and @inode in this case.
 *
 * Return > 0 for a hash match, and the extent ref will be
 * *INCREASED*, and hash->bytenr/num_bytes will record the existing
 * extent data.
 * Return 0 for a hash miss. Nothing is done
 * Return <0 for error.
 *
 * Only on-disk backedn may return error though.
 */
unsigned long btrfs_cbs_search(struct inode *inode, u8 *hash);

/* Add a cbs hash into cbs info */
int btrfs_cbs_add(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		    struct btrfs_cbs_hash *hash);

/* Remove a cbs hash from cbs info */
int btrfs_cbs_del(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		    u64 bytenr);
#endif
