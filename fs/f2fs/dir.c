/*
 * fs/f2fs/dir.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
#include <linux/fs.h>
#include <linux/f2fs_fs.h>
#include "f2fs.h"
#include "node.h"
#include "acl.h"
#include "xattr.h"

static unsigned long dir_blocks(struct inode *inode)
{
	return ((unsigned long long) (i_size_read(inode) + PAGE_CACHE_SIZE - 1))
							>> PAGE_CACHE_SHIFT;
}

static unsigned int dir_buckets(unsigned int level, int dir_level)
{
<<<<<<< HEAD
	if (level < MAX_DIR_HASH_DEPTH / 2)
		return 1 << (level + dir_level);
	else
		return 1 << ((MAX_DIR_HASH_DEPTH / 2 + dir_level) - 1);
=======
	if (level + dir_level < MAX_DIR_HASH_DEPTH / 2)
		return 1 << (level + dir_level);
	else
		return MAX_DIR_BUCKETS;
>>>>>>> 97c0eac... fs: add f2fs support
}

static unsigned int bucket_blocks(unsigned int level)
{
	if (level < MAX_DIR_HASH_DEPTH / 2)
		return 2;
	else
		return 4;
}

<<<<<<< HEAD
static unsigned char f2fs_filetype_table[F2FS_FT_MAX] = {
=======
unsigned char f2fs_filetype_table[F2FS_FT_MAX] = {
>>>>>>> 97c0eac... fs: add f2fs support
	[F2FS_FT_UNKNOWN]	= DT_UNKNOWN,
	[F2FS_FT_REG_FILE]	= DT_REG,
	[F2FS_FT_DIR]		= DT_DIR,
	[F2FS_FT_CHRDEV]	= DT_CHR,
	[F2FS_FT_BLKDEV]	= DT_BLK,
	[F2FS_FT_FIFO]		= DT_FIFO,
	[F2FS_FT_SOCK]		= DT_SOCK,
	[F2FS_FT_SYMLINK]	= DT_LNK,
};

#define S_SHIFT 12
static unsigned char f2fs_type_by_mode[S_IFMT >> S_SHIFT] = {
	[S_IFREG >> S_SHIFT]	= F2FS_FT_REG_FILE,
	[S_IFDIR >> S_SHIFT]	= F2FS_FT_DIR,
	[S_IFCHR >> S_SHIFT]	= F2FS_FT_CHRDEV,
	[S_IFBLK >> S_SHIFT]	= F2FS_FT_BLKDEV,
	[S_IFIFO >> S_SHIFT]	= F2FS_FT_FIFO,
	[S_IFSOCK >> S_SHIFT]	= F2FS_FT_SOCK,
	[S_IFLNK >> S_SHIFT]	= F2FS_FT_SYMLINK,
};

<<<<<<< HEAD
static void set_de_type(struct f2fs_dir_entry *de, struct inode *inode)
{
	mode_t mode = inode->i_mode;
=======
void set_de_type(struct f2fs_dir_entry *de, struct inode *inode)
{
	umode_t mode = inode->i_mode;
>>>>>>> 97c0eac... fs: add f2fs support
	de->file_type = f2fs_type_by_mode[(mode & S_IFMT) >> S_SHIFT];
}

static unsigned long dir_block_index(unsigned int level,
				int dir_level, unsigned int idx)
{
	unsigned long i;
	unsigned long bidx = 0;

	for (i = 0; i < level; i++)
		bidx += dir_buckets(i, dir_level) * bucket_blocks(i);
	bidx += idx * bucket_blocks(level);
	return bidx;
}

<<<<<<< HEAD
static bool early_match_name(const char *name, size_t namelen,
			f2fs_hash_t namehash, struct f2fs_dir_entry *de)
=======
static bool early_match_name(size_t namelen, f2fs_hash_t namehash,
				struct f2fs_dir_entry *de)
>>>>>>> 97c0eac... fs: add f2fs support
{
	if (le16_to_cpu(de->name_len) != namelen)
		return false;

	if (de->hash_code != namehash)
		return false;

	return true;
}

static struct f2fs_dir_entry *find_in_block(struct page *dentry_page,
<<<<<<< HEAD
			const char *name, size_t namelen, int *max_slots,
			f2fs_hash_t namehash, struct page **res_page)
{
	struct f2fs_dir_entry *de;
	unsigned long bit_pos = 0;
	struct f2fs_dentry_block *dentry_blk = kmap(dentry_page);
	const void *dentry_bits = &dentry_blk->dentry_bitmap;
	int max_len = 0;

	while (bit_pos < NR_DENTRY_IN_BLOCK) {
		if (!test_bit_le(bit_pos, dentry_bits)) {
			if (bit_pos == 0)
				max_len = 1;
			else if (!test_bit_le(bit_pos - 1, dentry_bits))
=======
				struct qstr *name, int *max_slots,
				struct page **res_page)
{
	struct f2fs_dentry_block *dentry_blk;
	struct f2fs_dir_entry *de;
	struct f2fs_dentry_ptr d;

	dentry_blk = (struct f2fs_dentry_block *)kmap(dentry_page);

	make_dentry_ptr(&d, (void *)dentry_blk, 1);
	de = find_target_dentry(name, max_slots, &d);

	if (de)
		*res_page = dentry_page;
	else
		kunmap(dentry_page);

	/*
	 * For the most part, it should be a bug when name_len is zero.
	 * We stop here for figuring out where the bugs has occurred.
	 */
	f2fs_bug_on(F2FS_P_SB(dentry_page), d.max < 0);
	return de;
}

struct f2fs_dir_entry *find_target_dentry(struct qstr *name, int *max_slots,
						struct f2fs_dentry_ptr *d)
{
	struct f2fs_dir_entry *de;
	unsigned long bit_pos = 0;
	f2fs_hash_t namehash = f2fs_dentry_hash(name);
	int max_len = 0;

	if (max_slots)
		*max_slots = 0;
	while (bit_pos < d->max) {
		if (!test_bit_le(bit_pos, d->bitmap)) {
			if (bit_pos == 0)
				max_len = 1;
			else if (!test_bit_le(bit_pos - 1, d->bitmap))
>>>>>>> 97c0eac... fs: add f2fs support
				max_len++;
			bit_pos++;
			continue;
		}
<<<<<<< HEAD
		de = &dentry_blk->dentry[bit_pos];
		if (early_match_name(name, namelen, namehash, de)) {
			if (!memcmp(dentry_blk->filename[bit_pos],
							name, namelen)) {
				*res_page = dentry_page;
				goto found;
			}
		}
		if (max_len > *max_slots) {
			*max_slots = max_len;
			max_len = 0;
		}
=======
		de = &d->dentry[bit_pos];
		if (early_match_name(name->len, namehash, de) &&
			!memcmp(d->filename[bit_pos], name->name, name->len))
			goto found;

		if (max_slots && *max_slots >= 0 && max_len > *max_slots) {
			*max_slots = max_len;
			max_len = 0;
		}

		/* remain bug on condition */
		if (unlikely(!de->name_len))
			d->max = -1;

>>>>>>> 97c0eac... fs: add f2fs support
		bit_pos += GET_DENTRY_SLOTS(le16_to_cpu(de->name_len));
	}

	de = NULL;
<<<<<<< HEAD
	kunmap(dentry_page);
found:
	if (max_len > *max_slots)
=======
found:
	if (max_slots && max_len > *max_slots)
>>>>>>> 97c0eac... fs: add f2fs support
		*max_slots = max_len;
	return de;
}

static struct f2fs_dir_entry *find_in_level(struct inode *dir,
<<<<<<< HEAD
		unsigned int level, const char *name, size_t namelen,
			f2fs_hash_t namehash, struct page **res_page)
{
	int s = GET_DENTRY_SLOTS(namelen);
=======
			unsigned int level, struct qstr *name,
			f2fs_hash_t namehash, struct page **res_page)
{
	int s = GET_DENTRY_SLOTS(name->len);
>>>>>>> 97c0eac... fs: add f2fs support
	unsigned int nbucket, nblock;
	unsigned int bidx, end_block;
	struct page *dentry_page;
	struct f2fs_dir_entry *de = NULL;
	bool room = false;
<<<<<<< HEAD
	int max_slots = 0;

	f2fs_bug_on(level > MAX_DIR_HASH_DEPTH);
=======
	int max_slots;

	f2fs_bug_on(F2FS_I_SB(dir), level > MAX_DIR_HASH_DEPTH);
>>>>>>> 97c0eac... fs: add f2fs support

	nbucket = dir_buckets(level, F2FS_I(dir)->i_dir_level);
	nblock = bucket_blocks(level);

	bidx = dir_block_index(level, F2FS_I(dir)->i_dir_level,
					le32_to_cpu(namehash) % nbucket);
	end_block = bidx + nblock;

	for (; bidx < end_block; bidx++) {
		/* no need to allocate new dentry pages to all the indices */
		dentry_page = find_data_page(dir, bidx, true);
		if (IS_ERR(dentry_page)) {
			room = true;
			continue;
		}

<<<<<<< HEAD
		de = find_in_block(dentry_page, name, namelen,
					&max_slots, namehash, res_page);
=======
		de = find_in_block(dentry_page, name, &max_slots, res_page);
>>>>>>> 97c0eac... fs: add f2fs support
		if (de)
			break;

		if (max_slots >= s)
			room = true;
		f2fs_put_page(dentry_page, 0);
	}

	if (!de && room && F2FS_I(dir)->chash != namehash) {
		F2FS_I(dir)->chash = namehash;
		F2FS_I(dir)->clevel = level;
	}

	return de;
}

/*
 * Find an entry in the specified directory with the wanted name.
 * It returns the page where the entry was found (as a parameter - res_page),
 * and the entry itself. Page is returned mapped and unlocked.
 * Entry is guaranteed to be valid.
 */
struct f2fs_dir_entry *f2fs_find_entry(struct inode *dir,
			struct qstr *child, struct page **res_page)
{
<<<<<<< HEAD
	const char *name = child->name;
	size_t namelen = child->len;
=======
>>>>>>> 97c0eac... fs: add f2fs support
	unsigned long npages = dir_blocks(dir);
	struct f2fs_dir_entry *de = NULL;
	f2fs_hash_t name_hash;
	unsigned int max_depth;
	unsigned int level;

<<<<<<< HEAD
=======
	if (f2fs_has_inline_dentry(dir))
		return find_in_inline_dir(dir, child, res_page);

>>>>>>> 97c0eac... fs: add f2fs support
	if (npages == 0)
		return NULL;

	*res_page = NULL;

<<<<<<< HEAD
	name_hash = f2fs_dentry_hash(name, namelen);
	max_depth = F2FS_I(dir)->i_current_depth;

	for (level = 0; level < max_depth; level++) {
		de = find_in_level(dir, level, name,
				namelen, name_hash, res_page);
=======
	name_hash = f2fs_dentry_hash(child);
	max_depth = F2FS_I(dir)->i_current_depth;

	for (level = 0; level < max_depth; level++) {
		de = find_in_level(dir, level, child, name_hash, res_page);
>>>>>>> 97c0eac... fs: add f2fs support
		if (de)
			break;
	}
	if (!de && F2FS_I(dir)->chash != name_hash) {
		F2FS_I(dir)->chash = name_hash;
		F2FS_I(dir)->clevel = level - 1;
	}
	return de;
}

struct f2fs_dir_entry *f2fs_parent_dir(struct inode *dir, struct page **p)
{
	struct page *page;
	struct f2fs_dir_entry *de;
	struct f2fs_dentry_block *dentry_blk;

<<<<<<< HEAD
=======
	if (f2fs_has_inline_dentry(dir))
		return f2fs_parent_inline_dir(dir, p);

>>>>>>> 97c0eac... fs: add f2fs support
	page = get_lock_data_page(dir, 0);
	if (IS_ERR(page))
		return NULL;

	dentry_blk = kmap(page);
	de = &dentry_blk->dentry[1];
	*p = page;
	unlock_page(page);
	return de;
}

ino_t f2fs_inode_by_name(struct inode *dir, struct qstr *qstr)
{
	ino_t res = 0;
	struct f2fs_dir_entry *de;
	struct page *page;

	de = f2fs_find_entry(dir, qstr, &page);
	if (de) {
		res = le32_to_cpu(de->ino);
<<<<<<< HEAD
		kunmap(page);
=======
		f2fs_dentry_kunmap(dir, page);
>>>>>>> 97c0eac... fs: add f2fs support
		f2fs_put_page(page, 0);
	}

	return res;
}

void f2fs_set_link(struct inode *dir, struct f2fs_dir_entry *de,
		struct page *page, struct inode *inode)
{
<<<<<<< HEAD
	lock_page(page);
	f2fs_wait_on_page_writeback(page, DATA);
	de->ino = cpu_to_le32(inode->i_ino);
	set_de_type(de, inode);
	kunmap(page);
=======
	enum page_type type = f2fs_has_inline_dentry(dir) ? NODE : DATA;
	lock_page(page);
	f2fs_wait_on_page_writeback(page, type);
	de->ino = cpu_to_le32(inode->i_ino);
	set_de_type(de, inode);
	f2fs_dentry_kunmap(dir, page);
>>>>>>> 97c0eac... fs: add f2fs support
	set_page_dirty(page);
	dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	mark_inode_dirty(dir);

	f2fs_put_page(page, 1);
}

static void init_dent_inode(const struct qstr *name, struct page *ipage)
{
	struct f2fs_inode *ri;

<<<<<<< HEAD
=======
	f2fs_wait_on_page_writeback(ipage, NODE);

>>>>>>> 97c0eac... fs: add f2fs support
	/* copy name info. to this inode page */
	ri = F2FS_INODE(ipage);
	ri->i_namelen = cpu_to_le32(name->len);
	memcpy(ri->i_name, name->name, name->len);
	set_page_dirty(ipage);
}

int update_dent_inode(struct inode *inode, const struct qstr *name)
{
<<<<<<< HEAD
	struct f2fs_sb_info *sbi = F2FS_SB(inode->i_sb);
	struct page *page;

	page = get_node_page(sbi, inode->i_ino);
=======
	struct page *page;

	page = get_node_page(F2FS_I_SB(inode), inode->i_ino);
>>>>>>> 97c0eac... fs: add f2fs support
	if (IS_ERR(page))
		return PTR_ERR(page);

	init_dent_inode(name, page);
	f2fs_put_page(page, 1);

	return 0;
}

<<<<<<< HEAD
static int make_empty_dir(struct inode *inode,
		struct inode *parent, struct page *page)
{
	struct page *dentry_page;
	struct f2fs_dentry_block *dentry_blk;
	struct f2fs_dir_entry *de;
	void *kaddr;

	dentry_page = get_new_data_page(inode, page, 0, true);
	if (IS_ERR(dentry_page))
		return PTR_ERR(dentry_page);

	kaddr = kmap_atomic(dentry_page);
	dentry_blk = (struct f2fs_dentry_block *)kaddr;

	de = &dentry_blk->dentry[0];
	de->name_len = cpu_to_le16(1);
	de->hash_code = 0;
	de->ino = cpu_to_le32(inode->i_ino);
	memcpy(dentry_blk->filename[0], ".", 1);
	set_de_type(de, inode);

	de = &dentry_blk->dentry[1];
	de->hash_code = 0;
	de->name_len = cpu_to_le16(2);
	de->ino = cpu_to_le32(parent->i_ino);
	memcpy(dentry_blk->filename[1], "..", 2);
	set_de_type(de, inode);

	test_and_set_bit_le(0, &dentry_blk->dentry_bitmap);
	test_and_set_bit_le(1, &dentry_blk->dentry_bitmap);
	kunmap_atomic(kaddr);
=======
void do_make_empty_dir(struct inode *inode, struct inode *parent,
					struct f2fs_dentry_ptr *d)
{
	struct f2fs_dir_entry *de;

	de = &d->dentry[0];
	de->name_len = cpu_to_le16(1);
	de->hash_code = 0;
	de->ino = cpu_to_le32(inode->i_ino);
	memcpy(d->filename[0], ".", 1);
	set_de_type(de, inode);

	de = &d->dentry[1];
	de->hash_code = 0;
	de->name_len = cpu_to_le16(2);
	de->ino = cpu_to_le32(parent->i_ino);
	memcpy(d->filename[1], "..", 2);
	set_de_type(de, inode);

	test_and_set_bit_le(0, (void *)d->bitmap);
	test_and_set_bit_le(1, (void *)d->bitmap);
}

static int make_empty_dir(struct inode *inode,
		struct inode *parent, struct page *page)
{
	struct page *dentry_page;
	struct f2fs_dentry_block *dentry_blk;
	struct f2fs_dentry_ptr d;

	if (f2fs_has_inline_dentry(inode))
		return make_empty_inline_dir(inode, parent, page);

	dentry_page = get_new_data_page(inode, page, 0, true);
	if (IS_ERR(dentry_page))
		return PTR_ERR(dentry_page);

	dentry_blk = kmap_atomic(dentry_page);

	make_dentry_ptr(&d, (void *)dentry_blk, 1);
	do_make_empty_dir(inode, parent, &d);

	kunmap_atomic(dentry_blk);
>>>>>>> 97c0eac... fs: add f2fs support

	set_page_dirty(dentry_page);
	f2fs_put_page(dentry_page, 1);
	return 0;
}

<<<<<<< HEAD
static struct page *init_inode_metadata(struct inode *inode,
		struct inode *dir, const struct qstr *name)
=======
struct page *init_inode_metadata(struct inode *inode, struct inode *dir,
			const struct qstr *name, struct page *dpage)
>>>>>>> 97c0eac... fs: add f2fs support
{
	struct page *page;
	int err;

	if (is_inode_flag_set(F2FS_I(inode), FI_NEW_INODE)) {
<<<<<<< HEAD
		page = new_inode_page(inode, name);
=======
		page = new_inode_page(inode);
>>>>>>> 97c0eac... fs: add f2fs support
		if (IS_ERR(page))
			return page;

		if (S_ISDIR(inode->i_mode)) {
			err = make_empty_dir(inode, dir, page);
			if (err)
				goto error;
		}

<<<<<<< HEAD
		err = f2fs_init_acl(inode, dir, page);
=======
		err = f2fs_init_acl(inode, dir, page, dpage);
>>>>>>> 97c0eac... fs: add f2fs support
		if (err)
			goto put_error;

		err = f2fs_init_security(inode, dir, name, page);
		if (err)
			goto put_error;
	} else {
<<<<<<< HEAD
		page = get_node_page(F2FS_SB(dir->i_sb), inode->i_ino);
=======
		page = get_node_page(F2FS_I_SB(dir), inode->i_ino);
>>>>>>> 97c0eac... fs: add f2fs support
		if (IS_ERR(page))
			return page;

		set_cold_node(inode, page);
	}

<<<<<<< HEAD
	init_dent_inode(name, page);
=======
	if (name)
		init_dent_inode(name, page);
>>>>>>> 97c0eac... fs: add f2fs support

	/*
	 * This file should be checkpointed during fsync.
	 * We lost i_pino from now on.
	 */
	if (is_inode_flag_set(F2FS_I(inode), FI_INC_LINK)) {
		file_lost_pino(inode);
<<<<<<< HEAD
=======
		/*
		 * If link the tmpfile to alias through linkat path,
		 * we should remove this inode from orphan list.
		 */
		if (inode->i_nlink == 0)
			remove_orphan_inode(F2FS_I_SB(dir), inode->i_ino);
>>>>>>> 97c0eac... fs: add f2fs support
		inc_nlink(inode);
	}
	return page;

put_error:
	f2fs_put_page(page, 1);
<<<<<<< HEAD
	/* once the failed inode becomes a bad inode, i_mode is S_IFREG */
	truncate_inode_pages(&inode->i_data, 0);
	truncate_blocks(inode, 0);
	remove_dirty_dir_inode(inode);
error:
=======
error:
	/* once the failed inode becomes a bad inode, i_mode is S_IFREG */
	truncate_inode_pages(&inode->i_data, 0);
	truncate_blocks(inode, 0, false);
	remove_dirty_dir_inode(inode);
>>>>>>> 97c0eac... fs: add f2fs support
	remove_inode_page(inode);
	return ERR_PTR(err);
}

<<<<<<< HEAD
static void update_parent_metadata(struct inode *dir, struct inode *inode,
=======
void update_parent_metadata(struct inode *dir, struct inode *inode,
>>>>>>> 97c0eac... fs: add f2fs support
						unsigned int current_depth)
{
	if (is_inode_flag_set(F2FS_I(inode), FI_NEW_INODE)) {
		if (S_ISDIR(inode->i_mode)) {
			inc_nlink(dir);
			set_inode_flag(F2FS_I(dir), FI_UPDATE_DIR);
		}
		clear_inode_flag(F2FS_I(inode), FI_NEW_INODE);
	}
	dir->i_mtime = dir->i_ctime = CURRENT_TIME;
	mark_inode_dirty(dir);

	if (F2FS_I(dir)->i_current_depth != current_depth) {
		F2FS_I(dir)->i_current_depth = current_depth;
		set_inode_flag(F2FS_I(dir), FI_UPDATE_DIR);
	}

	if (is_inode_flag_set(F2FS_I(inode), FI_INC_LINK))
		clear_inode_flag(F2FS_I(inode), FI_INC_LINK);
}

<<<<<<< HEAD
static int room_for_filename(struct f2fs_dentry_block *dentry_blk, int slots)
=======
int room_for_filename(const void *bitmap, int slots, int max_slots)
>>>>>>> 97c0eac... fs: add f2fs support
{
	int bit_start = 0;
	int zero_start, zero_end;
next:
<<<<<<< HEAD
	zero_start = find_next_zero_bit_le(&dentry_blk->dentry_bitmap,
						NR_DENTRY_IN_BLOCK,
						bit_start);
	if (zero_start >= NR_DENTRY_IN_BLOCK)
		return NR_DENTRY_IN_BLOCK;

	zero_end = find_next_bit_le(&dentry_blk->dentry_bitmap,
						NR_DENTRY_IN_BLOCK,
						zero_start);
=======
	zero_start = find_next_zero_bit_le(bitmap, max_slots, bit_start);
	if (zero_start >= max_slots)
		return max_slots;

	zero_end = find_next_bit_le(bitmap, max_slots, zero_start);
>>>>>>> 97c0eac... fs: add f2fs support
	if (zero_end - zero_start >= slots)
		return zero_start;

	bit_start = zero_end + 1;

<<<<<<< HEAD
	if (zero_end + 1 >= NR_DENTRY_IN_BLOCK)
		return NR_DENTRY_IN_BLOCK;
	goto next;
}

=======
	if (zero_end + 1 >= max_slots)
		return max_slots;
	goto next;
}

void f2fs_update_dentry(struct inode *inode, struct f2fs_dentry_ptr *d,
				const struct qstr *name, f2fs_hash_t name_hash,
				unsigned int bit_pos)
{
	struct f2fs_dir_entry *de;
	int slots = GET_DENTRY_SLOTS(name->len);
	int i;

	de = &d->dentry[bit_pos];
	de->hash_code = name_hash;
	de->name_len = cpu_to_le16(name->len);
	memcpy(d->filename[bit_pos], name->name, name->len);
	de->ino = cpu_to_le32(inode->i_ino);
	set_de_type(de, inode);
	for (i = 0; i < slots; i++)
		test_and_set_bit_le(bit_pos + i, (void *)d->bitmap);
}

>>>>>>> 97c0eac... fs: add f2fs support
/*
 * Caller should grab and release a rwsem by calling f2fs_lock_op() and
 * f2fs_unlock_op().
 */
int __f2fs_add_link(struct inode *dir, const struct qstr *name,
						struct inode *inode)
{
	unsigned int bit_pos;
	unsigned int level;
	unsigned int current_depth;
	unsigned long bidx, block;
	f2fs_hash_t dentry_hash;
<<<<<<< HEAD
	struct f2fs_dir_entry *de;
=======
>>>>>>> 97c0eac... fs: add f2fs support
	unsigned int nbucket, nblock;
	size_t namelen = name->len;
	struct page *dentry_page = NULL;
	struct f2fs_dentry_block *dentry_blk = NULL;
<<<<<<< HEAD
	int slots = GET_DENTRY_SLOTS(namelen);
	struct page *page;
	int err = 0;
	int i;

	dentry_hash = f2fs_dentry_hash(name->name, name->len);
=======
	struct f2fs_dentry_ptr d;
	int slots = GET_DENTRY_SLOTS(namelen);
	struct page *page;
	int err = 0;

	if (f2fs_has_inline_dentry(dir)) {
		err = f2fs_add_inline_entry(dir, name, inode);
		if (!err || err != -EAGAIN)
			return err;
		else
			err = 0;
	}

	dentry_hash = f2fs_dentry_hash(name);
>>>>>>> 97c0eac... fs: add f2fs support
	level = 0;
	current_depth = F2FS_I(dir)->i_current_depth;
	if (F2FS_I(dir)->chash == dentry_hash) {
		level = F2FS_I(dir)->clevel;
		F2FS_I(dir)->chash = 0;
	}

start:
	if (unlikely(current_depth == MAX_DIR_HASH_DEPTH))
		return -ENOSPC;

	/* Increase the depth, if required */
	if (level == current_depth)
		++current_depth;

	nbucket = dir_buckets(level, F2FS_I(dir)->i_dir_level);
	nblock = bucket_blocks(level);

	bidx = dir_block_index(level, F2FS_I(dir)->i_dir_level,
				(le32_to_cpu(dentry_hash) % nbucket));

	for (block = bidx; block <= (bidx + nblock - 1); block++) {
		dentry_page = get_new_data_page(dir, NULL, block, true);
		if (IS_ERR(dentry_page))
			return PTR_ERR(dentry_page);

		dentry_blk = kmap(dentry_page);
<<<<<<< HEAD
		bit_pos = room_for_filename(dentry_blk, slots);
=======
		bit_pos = room_for_filename(&dentry_blk->dentry_bitmap,
						slots, NR_DENTRY_IN_BLOCK);
>>>>>>> 97c0eac... fs: add f2fs support
		if (bit_pos < NR_DENTRY_IN_BLOCK)
			goto add_dentry;

		kunmap(dentry_page);
		f2fs_put_page(dentry_page, 1);
	}

	/* Move to next level to find the empty slot for new dentry */
	++level;
	goto start;
add_dentry:
	f2fs_wait_on_page_writeback(dentry_page, DATA);

	down_write(&F2FS_I(inode)->i_sem);
<<<<<<< HEAD
	page = init_inode_metadata(inode, dir, name);
=======
	page = init_inode_metadata(inode, dir, name, NULL);
>>>>>>> 97c0eac... fs: add f2fs support
	if (IS_ERR(page)) {
		err = PTR_ERR(page);
		goto fail;
	}
<<<<<<< HEAD
	de = &dentry_blk->dentry[bit_pos];
	de->hash_code = dentry_hash;
	de->name_len = cpu_to_le16(namelen);
	memcpy(dentry_blk->filename[bit_pos], name->name, name->len);
	de->ino = cpu_to_le32(inode->i_ino);
	set_de_type(de, inode);
	for (i = 0; i < slots; i++)
		test_and_set_bit_le(bit_pos + i, &dentry_blk->dentry_bitmap);
=======

	make_dentry_ptr(&d, (void *)dentry_blk, 1);
	f2fs_update_dentry(inode, &d, name, dentry_hash, bit_pos);

>>>>>>> 97c0eac... fs: add f2fs support
	set_page_dirty(dentry_page);

	/* we don't need to mark_inode_dirty now */
	F2FS_I(inode)->i_pino = dir->i_ino;
	update_inode(inode, page);
	f2fs_put_page(page, 1);

	update_parent_metadata(dir, inode, current_depth);
fail:
	up_write(&F2FS_I(inode)->i_sem);

	if (is_inode_flag_set(F2FS_I(dir), FI_UPDATE_DIR)) {
		update_inode_page(dir);
		clear_inode_flag(F2FS_I(dir), FI_UPDATE_DIR);
	}
	kunmap(dentry_page);
	f2fs_put_page(dentry_page, 1);
	return err;
}

<<<<<<< HEAD
/*
 * It only removes the dentry from the dentry page,corresponding name
 * entry in name page does not need to be touched during deletion.
 */
void f2fs_delete_entry(struct f2fs_dir_entry *dentry, struct page *page,
						struct inode *inode)
{
	struct	f2fs_dentry_block *dentry_blk;
	unsigned int bit_pos;
	struct address_space *mapping = page->mapping;
	struct inode *dir = mapping->host;
	int slots = GET_DENTRY_SLOTS(le16_to_cpu(dentry->name_len));
	void *kaddr = page_address(page);
	int i;

	lock_page(page);
	f2fs_wait_on_page_writeback(page, DATA);

	dentry_blk = (struct f2fs_dentry_block *)kaddr;
	bit_pos = dentry - (struct f2fs_dir_entry *)dentry_blk->dentry;
=======
int f2fs_do_tmpfile(struct inode *inode, struct inode *dir)
{
	struct page *page;
	int err = 0;

	down_write(&F2FS_I(inode)->i_sem);
	page = init_inode_metadata(inode, dir, NULL, NULL);
	if (IS_ERR(page)) {
		err = PTR_ERR(page);
		goto fail;
	}
	/* we don't need to mark_inode_dirty now */
	update_inode(inode, page);
	f2fs_put_page(page, 1);

	clear_inode_flag(F2FS_I(inode), FI_NEW_INODE);
fail:
	up_write(&F2FS_I(inode)->i_sem);
	return err;
}

void f2fs_drop_nlink(struct inode *dir, struct inode *inode, struct page *page)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(dir);

	down_write(&F2FS_I(inode)->i_sem);

	if (S_ISDIR(inode->i_mode)) {
		drop_nlink(dir);
		if (page)
			update_inode(dir, page);
		else
			update_inode_page(dir);
	}
	inode->i_ctime = CURRENT_TIME;

	drop_nlink(inode);
	if (S_ISDIR(inode->i_mode)) {
		drop_nlink(inode);
		i_size_write(inode, 0);
	}
	up_write(&F2FS_I(inode)->i_sem);
	update_inode_page(inode);

	if (inode->i_nlink == 0)
		add_orphan_inode(sbi, inode->i_ino);
	else
		release_orphan_inode(sbi);
}

/*
 * It only removes the dentry from the dentry page, corresponding name
 * entry in name page does not need to be touched during deletion.
 */
void f2fs_delete_entry(struct f2fs_dir_entry *dentry, struct page *page,
					struct inode *dir, struct inode *inode)
{
	struct	f2fs_dentry_block *dentry_blk;
	unsigned int bit_pos;
	int slots = GET_DENTRY_SLOTS(le16_to_cpu(dentry->name_len));
	int i;

	if (f2fs_has_inline_dentry(dir))
		return f2fs_delete_inline_entry(dentry, page, dir, inode);

	lock_page(page);
	f2fs_wait_on_page_writeback(page, DATA);

	dentry_blk = page_address(page);
	bit_pos = dentry - dentry_blk->dentry;
>>>>>>> 97c0eac... fs: add f2fs support
	for (i = 0; i < slots; i++)
		test_and_clear_bit_le(bit_pos + i, &dentry_blk->dentry_bitmap);

	/* Let's check and deallocate this dentry page */
	bit_pos = find_next_bit_le(&dentry_blk->dentry_bitmap,
			NR_DENTRY_IN_BLOCK,
			0);
	kunmap(page); /* kunmap - pair of f2fs_find_entry */
	set_page_dirty(page);

	dir->i_ctime = dir->i_mtime = CURRENT_TIME;

<<<<<<< HEAD
	if (inode) {
		struct f2fs_sb_info *sbi = F2FS_SB(dir->i_sb);

		down_write(&F2FS_I(inode)->i_sem);

		if (S_ISDIR(inode->i_mode)) {
			drop_nlink(dir);
			update_inode_page(dir);
		}
		inode->i_ctime = CURRENT_TIME;
		drop_nlink(inode);
		if (S_ISDIR(inode->i_mode)) {
			drop_nlink(inode);
			i_size_write(inode, 0);
		}
		up_write(&F2FS_I(inode)->i_sem);
		update_inode_page(inode);

		if (inode->i_nlink == 0)
			add_orphan_inode(sbi, inode->i_ino);
		else
			release_orphan_inode(sbi);
	}
=======
	if (inode)
		f2fs_drop_nlink(dir, inode, NULL);
>>>>>>> 97c0eac... fs: add f2fs support

	if (bit_pos == NR_DENTRY_IN_BLOCK) {
		truncate_hole(dir, page->index, page->index + 1);
		clear_page_dirty_for_io(page);
<<<<<<< HEAD
		ClearPageUptodate(page);
		inode_dec_dirty_dents(dir);
=======
		ClearPagePrivate(page);
		ClearPageUptodate(page);
		inode_dec_dirty_pages(dir);
>>>>>>> 97c0eac... fs: add f2fs support
	}
	f2fs_put_page(page, 1);
}

bool f2fs_empty_dir(struct inode *dir)
{
	unsigned long bidx;
	struct page *dentry_page;
	unsigned int bit_pos;
<<<<<<< HEAD
	struct	f2fs_dentry_block *dentry_blk;
	unsigned long nblock = dir_blocks(dir);

	for (bidx = 0; bidx < nblock; bidx++) {
		void *kaddr;
=======
	struct f2fs_dentry_block *dentry_blk;
	unsigned long nblock = dir_blocks(dir);

	if (f2fs_has_inline_dentry(dir))
		return f2fs_empty_inline_dir(dir);

	for (bidx = 0; bidx < nblock; bidx++) {
>>>>>>> 97c0eac... fs: add f2fs support
		dentry_page = get_lock_data_page(dir, bidx);
		if (IS_ERR(dentry_page)) {
			if (PTR_ERR(dentry_page) == -ENOENT)
				continue;
			else
				return false;
		}

<<<<<<< HEAD
		kaddr = kmap_atomic(dentry_page);
		dentry_blk = (struct f2fs_dentry_block *)kaddr;
=======
		dentry_blk = kmap_atomic(dentry_page);
>>>>>>> 97c0eac... fs: add f2fs support
		if (bidx == 0)
			bit_pos = 2;
		else
			bit_pos = 0;
		bit_pos = find_next_bit_le(&dentry_blk->dentry_bitmap,
						NR_DENTRY_IN_BLOCK,
						bit_pos);
<<<<<<< HEAD
		kunmap_atomic(kaddr);
=======
		kunmap_atomic(dentry_blk);
>>>>>>> 97c0eac... fs: add f2fs support

		f2fs_put_page(dentry_page, 1);

		if (bit_pos < NR_DENTRY_IN_BLOCK)
			return false;
	}
	return true;
}

<<<<<<< HEAD
static int f2fs_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	unsigned long pos = file->f_pos;
	struct inode *inode = file->f_dentry->d_inode;
	unsigned long npages = dir_blocks(inode);
	unsigned char *types = NULL;
	unsigned int bit_pos = 0, start_bit_pos = 0;
	int over = 0;
	struct f2fs_dentry_block *dentry_blk = NULL;
	struct f2fs_dir_entry *de = NULL;
	struct page *dentry_page = NULL;
	unsigned int n = 0;
	unsigned char d_type = DT_UNKNOWN;
	int slots;

	types = f2fs_filetype_table;
	bit_pos = (pos % NR_DENTRY_IN_BLOCK);
	n = (pos / NR_DENTRY_IN_BLOCK);

=======
bool f2fs_fill_dentries(struct file *file, void *dirent, filldir_t filldir,
		struct f2fs_dentry_ptr *d, unsigned int n, unsigned int bit_pos)
{
	unsigned int start_bit_pos = bit_pos;
	unsigned char d_type;
	struct f2fs_dir_entry *de = NULL;
	unsigned char *types = f2fs_filetype_table;
	int over;

	while (bit_pos < d->max) {
		d_type = DT_UNKNOWN;
		bit_pos = find_next_bit_le(d->bitmap, d->max, bit_pos);
		if (bit_pos >= d->max)
			break;

		de = &d->dentry[bit_pos];
		if (types && de->file_type < F2FS_FT_MAX)
			d_type = types[de->file_type];

		over = filldir(dirent, d->filename[bit_pos],
					le16_to_cpu(de->name_len),
					(n * d->max) + bit_pos,
					le32_to_cpu(de->ino), d_type);
		if (over) {
			file->f_pos += bit_pos - start_bit_pos;
			return true;
		}

		bit_pos += GET_DENTRY_SLOTS(le16_to_cpu(de->name_len));
	}
	return false;
}

static int f2fs_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	unsigned long pos = file->f_pos;
	unsigned int bit_pos = 0;
	struct inode *inode = file_inode(file);
	unsigned long npages = dir_blocks(inode);
	struct f2fs_dentry_block *dentry_blk = NULL;
	struct page *dentry_page = NULL;
	struct file_ra_state *ra = &file->f_ra;
	struct f2fs_dentry_ptr d;
	unsigned int n = 0;

	if (f2fs_has_inline_dentry(inode))
		return f2fs_read_inline_dir(file, dirent, filldir);

	bit_pos = (pos % NR_DENTRY_IN_BLOCK);
	n = (pos / NR_DENTRY_IN_BLOCK);

	/* readahead for multi pages of dir */
	if (npages - n > 1 && !ra_has_index(ra, n))
		page_cache_sync_readahead(inode->i_mapping, ra, file, n,
				min(npages - n, (pgoff_t)MAX_DIR_RA_PAGES));

>>>>>>> 97c0eac... fs: add f2fs support
	for (; n < npages; n++) {
		dentry_page = get_lock_data_page(inode, n);
		if (IS_ERR(dentry_page))
			continue;

<<<<<<< HEAD
		start_bit_pos = bit_pos;
		dentry_blk = kmap(dentry_page);
		while (bit_pos < NR_DENTRY_IN_BLOCK) {
			d_type = DT_UNKNOWN;
			bit_pos = find_next_bit_le(&dentry_blk->dentry_bitmap,
							NR_DENTRY_IN_BLOCK,
							bit_pos);
			if (bit_pos >= NR_DENTRY_IN_BLOCK)
				break;

			de = &dentry_blk->dentry[bit_pos];
			if (types && de->file_type < F2FS_FT_MAX)
				d_type = types[de->file_type];

			over = filldir(dirent,
					dentry_blk->filename[bit_pos],
					le16_to_cpu(de->name_len),
					(n * NR_DENTRY_IN_BLOCK) + bit_pos,
					le32_to_cpu(de->ino), d_type);
			if (over) {
				file->f_pos += bit_pos - start_bit_pos;
				goto success;
			}
			slots = GET_DENTRY_SLOTS(le16_to_cpu(de->name_len));
			bit_pos += slots;
		}
=======
		dentry_blk = kmap(dentry_page);

		make_dentry_ptr(&d, (void *)dentry_blk, 1);

		if (f2fs_fill_dentries(file, dirent, filldir, &d, n, bit_pos))
			goto stop;

>>>>>>> 97c0eac... fs: add f2fs support
		bit_pos = 0;
		file->f_pos = (n + 1) * NR_DENTRY_IN_BLOCK;
		kunmap(dentry_page);
		f2fs_put_page(dentry_page, 1);
		dentry_page = NULL;
	}
<<<<<<< HEAD
success:
=======
stop:
>>>>>>> 97c0eac... fs: add f2fs support
	if (dentry_page && !IS_ERR(dentry_page)) {
		kunmap(dentry_page);
		f2fs_put_page(dentry_page, 1);
	}

	return 0;
}

const struct file_operations f2fs_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= f2fs_readdir,
	.fsync		= f2fs_sync_file,
	.unlocked_ioctl	= f2fs_ioctl,
};
