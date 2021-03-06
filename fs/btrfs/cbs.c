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
#include "cbs.h"
#include "btrfs_inode.h"
#include "transaction.h"
#include "delayed-ref.h"
#include "disk-io.h"
#include <linux/vmalloc.h>

static int init_cbs_info(struct btrfs_fs_info *fs_info, u16 type)
{
	struct btrfs_cbs_info *cbs_info;
	int ret;

	fs_info->cbs_info = kzalloc(sizeof(*cbs_info), GFP_NOFS);
	if (!fs_info->cbs_info)
		return -ENOMEM;

	cbs_info = fs_info->cbs_info;

	cbs_info->hash_type = type;

	/* Only support SHA256 yet */
	cbs_info->cbs_driver = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(cbs_info->cbs_driver)) {
		btrfs_err(fs_info, "failed to init sha256 driver");
		ret = PTR_ERR(cbs_info->cbs_driver);
		kfree(fs_info->cbs_info);
		fs_info->cbs_info = NULL;
		return ret;
	}

	mutex_init(&cbs_info->lock);
	return 0;
}

int btrfs_cbs_enable(struct btrfs_fs_info *fs_info, u16 type)
{
	struct btrfs_cbs_info *cbs_info;
	struct btrfs_root *cbs_root;
	struct btrfs_key key;
	struct btrfs_trans_handle *trans;
	struct btrfs_path *path;
	struct btrfs_cbs_status_item *status;
	int create_tree;
	u64 compat_ro_flag;
	int ret = 0;

	btrfs_set_fs_compat_ro(fs_info, CBS);
	compat_ro_flag = btrfs_super_compat_ro_flags(fs_info->super_copy);

	/* Meaningless and unable to enable cbs for RO fs */
	if (fs_info->sb->s_flags & MS_RDONLY)
		return -EINVAL;

	if (fs_info->cbs_info) {
		cbs_info = fs_info->cbs_info;

		/* Check if we re-enable for different cbs config */
		if (cbs_info->hash_type != type)
		{
			btrfs_cbs_disable(fs_info);
			goto enable;
		}

		return 0;
	}

enable:
	create_tree = compat_ro_flag & BTRFS_FEATURE_COMPAT_RO_CBS;

	ret = init_cbs_info(fs_info, type);
	cbs_info = fs_info->cbs_info;
	if (ret < 0)
		goto out;

	if (!create_tree)
		goto out;

	/* Create cbs tree for status at least */
	path = btrfs_alloc_path();
	if (!path) {
		ret = -ENOMEM;
		goto out;
	}

	trans = btrfs_start_transaction(fs_info->tree_root, 2);
	if (IS_ERR(trans)) {
		ret = PTR_ERR(trans);
		btrfs_free_path(path);
		goto out;
	}

	cbs_root = btrfs_create_tree(trans, fs_info,
				       BTRFS_CBS_TREE_OBJECTID);
	if (IS_ERR(cbs_root)) {
		ret = PTR_ERR(cbs_root);
		btrfs_abort_transaction(trans, fs_info->tree_root, ret);
		btrfs_free_path(path);
		goto out;
	}

	cbs_info->cbs_root = cbs_root;

	key.objectid = 0;
	key.type = BTRFS_CBS_STATUS_ITEM_KEY;
	key.offset = 0;

	ret = btrfs_insert_empty_item(trans, cbs_root, path, &key,
				      sizeof(*status));
	if (ret < 0) {
		btrfs_abort_transaction(trans, fs_info->tree_root, ret);
		btrfs_free_path(path);
		goto out;
	}
	status = btrfs_item_ptr(path->nodes[0], path->slots[0],
				struct btrfs_cbs_status_item);
	btrfs_set_cbs_status_hash_type(path->nodes[0], status, type);
	btrfs_mark_buffer_dirty(path->nodes[0]);

	btrfs_free_path(path);
	ret = btrfs_commit_transaction(trans, fs_info->tree_root);

out:
	if (ret < 0) {
		kfree(cbs_info);
		fs_info->cbs_info = NULL;
	}

	return ret;
}

int btrfs_cbs_resume(struct btrfs_fs_info *fs_info,
		       struct btrfs_root *cbs_root)
{
	struct btrfs_cbs_status_item *status;
	struct btrfs_key key;
	struct btrfs_path *path;
	u16 type;
	int ret = 0;

	printk(KERN_INFO "_________________________________________________________________________________________________________________________\n|");
	printk(KERN_INFO "|\n| Resuming last CBS configuration 				|\n");
	printk(KERN_INFO "|________________________________________________________________________________________________________________________\n");

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	key.objectid = 0;
	key.type = BTRFS_CBS_STATUS_ITEM_KEY;
	key.offset = 0;

	ret = btrfs_search_slot(NULL, cbs_root, &key, path, 0, 0);
	if (ret > 0) {
		ret = -ENOENT;
		goto out;
	} else if (ret < 0) {
		goto out;
	}

	status = btrfs_item_ptr(path->nodes[0], path->slots[0],
				struct btrfs_cbs_status_item);
	type = btrfs_cbs_status_hash_type(path->nodes[0], status);

	ret = init_cbs_info(fs_info, type);
	if (ret < 0)
		goto out;
	fs_info->cbs_info->cbs_root = cbs_root;

out:
	btrfs_free_path(path);
	return ret;
}

static unsigned long ondisk_search_hash(struct btrfs_cbs_info *cbs_info, struct btrfs_cbs_hash *hash, struct btrfs_path *path);
static unsigned long ondisk_search_hash_del(struct btrfs_trans_handle *trans, struct btrfs_cbs_info *cbs_info, u8 *hash, struct btrfs_path *path);

int btrfs_cbs_cleanup(struct btrfs_fs_info *fs_info)
{

	if (!fs_info->cbs_info){
		return 0;
	}
	
	if (fs_info->cbs_info->cbs_root) {
		free_root_extent_buffers(fs_info->cbs_info->cbs_root);
		kfree(fs_info->cbs_info->cbs_root);
	}
	crypto_free_shash(fs_info->cbs_info->cbs_driver);
	kfree(fs_info->cbs_info);
	fs_info->cbs_info = NULL;
	return 0;
}
static int ondisk_add(struct btrfs_trans_handle *trans,
		      struct btrfs_cbs_info *cbs_info,
		      struct btrfs_cbs_hash *hash)
{
	struct btrfs_path *path, *temp_path;
	struct btrfs_root *cbs_root = cbs_info->cbs_root;
	struct btrfs_key key;
	struct btrfs_cbs_hash_item *hash_item;
	int hash_len = btrfs_cbs_sizes[cbs_info->hash_type];
	int ret = 0;
	unsigned long inode_no;

	mutex_lock(&cbs_info->lock);

	temp_path = btrfs_alloc_path();
	if (!temp_path)
		return -ENOMEM;

	inode_no = ondisk_search_hash(cbs_info, hash, temp_path);
	btrfs_free_path(temp_path);

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	if (inode_no == 0) {
		ret = -1;
		printk(KERN_INFO "| In %s : Error in searching hash on-disk \n", __func__);
		goto out;
	}
	/* Same hash found, don't re-add to save cbs tree space */
	if (inode_no > 1) {
		ret = 1;
		goto out;
	}

	/* Insert hash->bytenr item */
	memcpy(&key.objectid, hash->hash + hash_len - 8, 8);
	key.type = BTRFS_CBS_HASH_ITEM_KEY;
	key.offset = 0;

	// ret = btrfs_insert_empty_item(trans, cbs_root, path, &key,
	// 		sizeof(*hash_item) + hash_len + hash->name_len);

	ret = btrfs_insert_empty_item(trans, cbs_root, path, &key,
			sizeof(*hash_item) + hash_len + hash->name_len);

	//WARN_ON(ret == -EEXIST);

	if (ret < 0)
		goto out;
	hash_item = btrfs_item_ptr(path->nodes[0], path->slots[0],
				   struct btrfs_cbs_hash_item);
	btrfs_set_cbs_hash_len(path->nodes[0], hash_item, hash->num_bytes);
	btrfs_set_cbs_inode_no(path->nodes[0], hash_item, hash->inode_no);
	btrfs_set_cbs_name_len(path->nodes[0], hash_item, hash->name_len);

	write_extent_buffer(path->nodes[0], hash->hash,
	 		    (unsigned long)(hash_item + 1), hash_len);
	write_extent_buffer(path->nodes[0], hash->file_name,
			    (unsigned long)(hash_item + 1) + hash_len, hash->name_len);
	btrfs_mark_buffer_dirty(path->nodes[0]);

out:
	mutex_unlock(&cbs_info->lock);
	btrfs_free_path(path);

	return ret;
}

int btrfs_cbs_add(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		    struct btrfs_cbs_hash *hash)
{

	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_cbs_info *cbs_info = fs_info->cbs_info;

	if (!cbs_info || !hash)
		return 0;

	return ondisk_add(trans, cbs_info, hash);
}

static int ondisk_del(struct btrfs_trans_handle *trans,
		      struct btrfs_cbs_info *cbs_info, u8 *hash)
{
	struct btrfs_root *cbs_root = cbs_info->cbs_root;
	struct btrfs_path *path;
	int ret = 0;

	path = btrfs_alloc_path();
	if (!path)
		return -ENOMEM;

	path->leave_spinning = 1;
	mutex_lock(&cbs_info->lock);

	ret = ondisk_search_hash_del(trans, cbs_info, hash, path);

	if (WARN_ON(ret == 0)) {
		ret = -ENOENT;
		goto out;
	}
	if (ret == 1)
		goto out;

	printk(KERN_INFO "| Deleting item from hash vs inode tree b+tree (CBS Tree) \n");
	printk(KERN_INFO "|________________________________________________________________________________________________________________________\n\n");
	btrfs_del_item(trans, cbs_root, path);

out:
	mutex_unlock(&cbs_info->lock);
	btrfs_release_path(path);
	btrfs_free_path(path);
	return ret;
}

/* Remove a cbs hash from cbs tree */
int btrfs_cbs_del(struct btrfs_trans_handle *trans, struct btrfs_root *root,
		    u8 *hash)
{
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_cbs_info *cbs_info = fs_info->cbs_info;

	if (!cbs_info)
		return 0;
	else{
		return ondisk_del(trans, cbs_info, hash);
	}

	return -EINVAL;
}

/* review */
int btrfs_cbs_disable(struct btrfs_fs_info *fs_info)
{

	struct btrfs_cbs_info *cbs_info = fs_info->cbs_info;
	int ret = 0;

	if (!cbs_info)
		return 0;

	if (cbs_info->cbs_root)
		ret = btrfs_drop_snapshot(cbs_info->cbs_root, NULL, 1, 0);
	crypto_free_shash(fs_info->cbs_info->cbs_driver);
	kfree(fs_info->cbs_info);
	fs_info->cbs_info = NULL;
	return ret;
}

/*
 * Search hash for cbs_add. Passes NULL and cow = 0.
 * Return 0 for error
 * Return inode_no for found
 * Return 1 for not found
 */
static unsigned long ondisk_search_hash(struct btrfs_cbs_info *cbs_info, struct btrfs_cbs_hash *hash, struct btrfs_path *path)
{
	struct btrfs_key key;
	struct btrfs_root *cbs_root = cbs_info->cbs_root;
	u8 *buf = NULL;
	u64 hash_key;
	int hash_len = btrfs_cbs_sizes[cbs_info->hash_type];
	int ret;
	unsigned long inode_no;

	buf = kmalloc(hash_len, GFP_NOFS);
	if (!buf) {
		ret = 0;
		goto out;
	}

	memcpy(&hash_key, hash->hash + hash_len - 8, 8);
	key.objectid = hash_key;
	key.type = BTRFS_CBS_HASH_ITEM_KEY;
	key.offset = (u64)-1;

	ret = btrfs_search_slot(NULL, cbs_root, &key, path, 0, 0);
	if (ret < 0)
	{
		ret = 0;
		goto out;
	}
	//WARN_ON(ret == 0);
	while (1) {
		struct extent_buffer *node;
		struct btrfs_cbs_hash_item *hash_item;
		int slot;

		ret = btrfs_previous_item(cbs_root, path, hash_key,
					  BTRFS_CBS_HASH_ITEM_KEY);
		if (ret < 0){
			ret = 0;
			goto out;
		}
		if (ret > 0) {
			ret = 1;
			goto out;
		}

		node = path->nodes[0];
		slot = path->slots[0];
		btrfs_item_key_to_cpu(node, &key, slot);

		if (key.type != BTRFS_CBS_HASH_ITEM_KEY ||
		    memcmp(&key.objectid, hash->hash + hash_len - 8, 8))
			break;
		hash_item = btrfs_item_ptr(node, slot,
				struct btrfs_cbs_hash_item);
	
		read_extent_buffer(node, buf, (unsigned long)(hash_item + 1), hash_len);
		if (!memcmp(buf, hash->hash, hash_len)) {
			inode_no = btrfs_cbs_inode_no(node, hash_item);
			hash->name_len = btrfs_cbs_name_len(node, hash_item);
			hash->file_name = kmalloc((hash->name_len)+1, GFP_NOFS);
			read_extent_buffer(node, hash->file_name, (unsigned long)(hash_item + 1) + hash_len, hash->name_len);
			hash->file_name[hash->name_len] = '\0';

			ret = inode_no;
			break;
		}
	}
out:
	kfree(buf);
	return ret;
}

/*
 * Search hash for cbs_del. Passes NULL and cow = 0.
 * Return 0 for error
 * Return inode_no for found
 * Return 1 for not found
 */
static unsigned long ondisk_search_hash_del(struct btrfs_trans_handle *trans, struct btrfs_cbs_info *cbs_info, u8 *hash, struct btrfs_path *path)
{
	struct btrfs_key key;
	struct btrfs_root *cbs_root = cbs_info->cbs_root;
	u8 *buf = NULL;
	u64 hash_key;
	int hash_len = btrfs_cbs_sizes[cbs_info->hash_type];
	int ret;
	unsigned long inode_no;

	printk(KERN_INFO "| Searching hash for deleting hash vs inode entry \n");
	buf = kmalloc(hash_len, GFP_NOFS);
	if (!buf) {
		ret = 0;
		goto out;
	}

	memcpy(&hash_key, hash + hash_len - 8, 8);
	key.objectid = hash_key;
	key.type = BTRFS_CBS_HASH_ITEM_KEY;
	key.offset = (u64)-1;	// doubtful

	ret = btrfs_search_slot(trans, cbs_root, &key, path, -1, 1);
	if (ret < 0)
	{
		ret = 0;
		goto out;
	}
	//WARN_ON(ret == 0);
	while (1) {
		struct extent_buffer *node;
		struct btrfs_cbs_hash_item *hash_item;
		int slot;

		ret = btrfs_previous_item(cbs_root, path, hash_key,
					  BTRFS_CBS_HASH_ITEM_KEY);
		if (ret < 0){
			ret = 0;
			goto out;
		}
		if (ret > 0) {
			ret = 1;
			goto out;
		}

		node = path->nodes[0];
		slot = path->slots[0];
		btrfs_item_key_to_cpu(node, &key, slot);

		if (key.type != BTRFS_CBS_HASH_ITEM_KEY ||
		    memcmp(&key.objectid, hash + hash_len - 8, 8))
			break;
		hash_item = btrfs_item_ptr(node, slot,
				struct btrfs_cbs_hash_item);
	
		read_extent_buffer(node, buf, (unsigned long)(hash_item + 1),
				   hash_len);
		if (!memcmp(buf, hash, hash_len)) {
			inode_no = btrfs_cbs_inode_no(node, hash_item);
			ret = inode_no;
			break;
		}
	}
out:
	kfree(buf);
	return ret;
}


/* review */
static unsigned long generic_search(struct inode *inode, struct btrfs_cbs_hash *hash)
{
	unsigned long inode_no = 0;
	struct btrfs_root *root = BTRFS_I(inode)->root;
	struct btrfs_fs_info *fs_info = root->fs_info;
	struct btrfs_cbs_info *cbs_info = fs_info->cbs_info;
	struct btrfs_path *path;	

	mutex_lock(&cbs_info->lock);

	path = btrfs_alloc_path();
	if (!path)
		return 0;

	inode_no = ondisk_search_hash(cbs_info, hash, path);

	btrfs_free_path(path);
	mutex_unlock(&cbs_info->lock);

	return inode_no;
}

unsigned long btrfs_cbs_search(struct inode *inode, struct btrfs_cbs_hash *hash)
{
	struct btrfs_fs_info *fs_info = BTRFS_I(inode)->root->fs_info;
	struct btrfs_cbs_info *cbs_info = fs_info->cbs_info;
	unsigned long inode_no = 0;

	if (WARN_ON(!cbs_info || !hash))
		return 0;

	inode_no = generic_search(inode, hash);

	return inode_no;
}

static int hash_data(struct btrfs_cbs_info *cbs_info, const char *data,
		     u64 length, struct btrfs_cbs_hash *hash)
{
	struct crypto_shash *tfm = cbs_info->cbs_driver;
	struct {
		struct shash_desc desc;
		char ctx[crypto_shash_descsize(tfm)];
	} sdesc;
	int ret;

	sdesc.desc.tfm = tfm;
	sdesc.desc.flags = 0;

	ret = crypto_shash_digest(&sdesc.desc, data, length,
				  (char *)(hash->hash));

	return ret;
}

int btrfs_cbs_calc_hash(struct btrfs_root *root, struct inode *inode,
			  u64 start, u64 end, struct btrfs_cbs_hash *hash)
{
	struct page *p;
	struct btrfs_cbs_info *cbs_info = root->fs_info->cbs_info;
	char *data;
	int i;
	int ret;
	u64 len;
	u64 sectorsize = root->sectorsize;

	if (!cbs_info || !hash)
		return 0;

	WARN_ON(!IS_ALIGNED(start, sectorsize));

	len = end-start+1;
	data = vmalloc(len);
	if (!data) {
		printk(KERN_INFO "| %s : vmalloc failed 									|\n", __func__);
		return -ENOMEM;
	}
	for (i = 0; sectorsize * i < len; i++) {
		char *d;

		/* TODO: Add support for subpage size case */
		p = find_get_page(inode->i_mapping,
				  (start >> PAGE_CACHE_SHIFT) + i);
		WARN_ON(!p);
		d = kmap_atomic(p);
		memcpy((data + sectorsize * i), d, sectorsize);
		kunmap_atomic(d);
		page_cache_release(p);
	}
	ret = hash_data(cbs_info, data, len, hash);
	vfree(data);
	return ret;
}

/*
 * Return binary representation of hexadecimal digit passed as arg
 */

static u8 convert_hex_binary (char a)
{
	switch(a)
    {
        case '0':
            return 0b00000000;
        case '1':
            return 0b00000001;
        case '2':
            return 0b00000010;
        case '3':
            return 0b00000011;
        case '4':
            return 0b00000100;
        case '5':
            return 0b00000101;
        case '6':
            return 0b00000110;
        case '7':
            return 0b00000111;
        case '8':
            return 0b00001000;
        case '9':
            return 0b00001001;
        case 'a':
            return 0b00001010;
        case 'b':
            return 0b00001011;
        case 'c':
            return 0b00001100;
        case 'd':
            return 0b00001101;
        case 'e':
            return 0b00001110;
        case 'f':
            return 0b00001111;
        default:
        	return 0b00000000;
    }
}

/*
 * Converts the 64 byte name recieved from userspace to 32 byte hash.
 * Later, calls ondisk_search_hash to fetch inode_no from hash vs inode cbs tree.
 */

unsigned long prepare_hash(const char* name, u8 hash[32])
{
    int i = 0, j = 0;
    u8 msb, lsb;

	i=0;
    while(i<64)
    {
        msb = convert_hex_binary(name[i]);
        msb = (msb<<4);
        i++;
        if(i>64)
        	break;

        lsb = convert_hex_binary(name[i]);
        msb = (msb | lsb);
        
        i++;
        if(i>64)
        	break;

        hash[j] = msb;
        j++;	
    }
    i=0;
    while(i<32)
    {
    	i++;
    }

	return 0;
}

void btrfs_cbs_set_name(char *name, int len)
{
	file_name_cbs.name = kmalloc(GFP_NOFS, sizeof(*name));
	file_name_cbs.name = name;
	file_name_cbs.len = len;
}

char *btrfs_cbs_get_name()
{
	return file_name_cbs.name;
}

int btrfs_cbs_get_len()
{
	return file_name_cbs.len;
}