// SPDX-License-Identifier: GPL-2.0

#include "fuse_i.h"

#include <linux/fuse.h>
#include <linux/idr.h>

static DEFINE_SPINLOCK(passthrough_map_lock);
static DEFINE_IDR(passthrough_map);

int fuse_passthrough_open(struct fuse_dev *fud, struct fuse_passthrough_out *pto)
{
	int res;
	struct file *passthrough_filp;
	struct fuse_conn *fc = fud->fc;

	if (!fc->passthrough)
		return -EPERM;

	/* This field is reserved for future implementation */
	if (pto->len != 0)
		return -EINVAL;

	passthrough_filp = fget(pto->fd);
	if (!passthrough_filp) {
		pr_err("FUSE: invalid file descriptor for passthrough.\n");
		return -EBADF;
	}

	if (!passthrough_filp->f_op->read_iter ||
	    !passthrough_filp->f_op->write_iter) {
		pr_err("FUSE: passthrough file misses file operations.\n");
		return -EBADF;
	}

	idr_preload(GFP_KERNEL);
	spin_lock(&passthrough_map_lock);
	res = idr_alloc(&passthrough_map, passthrough_filp, 1, 0, GFP_ATOMIC);
	spin_unlock(&passthrough_map_lock);
	idr_preload_end();
	if (res <= 0)
		fput(passthrough_filp);

	return res;
}

struct file *fuse_passthrough_setup(struct fuse_conn *fc,
				    struct fuse_open_out *openarg)
{
	int fs_stack_depth;
	struct file *passthrough_filp;
	struct inode *passthrough_inode;
	struct super_block *passthrough_sb;
	int passthrough_fh = openarg->passthrough_fh;

	if (!fc->passthrough)
		return NULL;

	/* Default case, passthrough is not requested */
	if (passthrough_fh == 0)
		return NULL;

	spin_lock(&passthrough_map_lock);
	passthrough_filp = idr_remove(&passthrough_map, passthrough_fh);
	spin_unlock(&passthrough_map_lock);

	passthrough_inode = file_inode(passthrough_filp);
	passthrough_sb = passthrough_inode->i_sb;
	fs_stack_depth = passthrough_sb->s_stack_depth + 1;
	if (fs_stack_depth > FILESYSTEM_MAX_STACK_DEPTH) {
		pr_err("FUSE: maximum fs stacking depth exceeded for passthrough\n");
		goto out;
	}

	return passthrough_filp;
out:
	fput(passthrough_filp);
	return NULL;
}

void fuse_passthrough_release(struct fuse_file *ff)
{
	if (!ff->passthrough_filp)
		return;

	fput(ff->passthrough_filp);
	ff->passthrough_filp = NULL;
}
