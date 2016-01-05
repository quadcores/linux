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
