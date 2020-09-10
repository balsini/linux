// SPDX-License-Identifier: GPL-2.0

#include "fuse_i.h"

#include <linux/fuse.h>
#include <linux/idr.h>
#include <linux/uio.h>

static DEFINE_SPINLOCK(passthrough_map_lock);
static DEFINE_IDR(passthrough_map);

static void fuse_copyattr(struct file *dst_file, struct file *src_file)
{
	struct inode *dst = file_inode(dst_file);
	struct inode *src = file_inode(src_file);

	i_size_write(dst, i_size_read(src));
}

static rwf_t iocbflags_to_rwf(int ifl)
{
	rwf_t flags = 0;

	if (ifl & IOCB_APPEND)
		flags |= RWF_APPEND;
	if (ifl & IOCB_DSYNC)
		flags |= RWF_DSYNC;
	if (ifl & IOCB_HIPRI)
		flags |= RWF_HIPRI;
	if (ifl & IOCB_NOWAIT)
		flags |= RWF_NOWAIT;
	if (ifl & IOCB_SYNC)
		flags |= RWF_SYNC;

	return flags;
}

static const struct cred *
fuse_passthrough_override_creds(const struct file *fuse_filp)
{
	struct inode *fuse_inode = file_inode(fuse_filp);
	struct fuse_conn *fc = fuse_inode->i_sb->s_fs_info;

	return override_creds(fc->creator_cred);
}

ssize_t fuse_passthrough_read_iter(struct kiocb *iocb_fuse,
				   struct iov_iter *iter)
{
	ssize_t ret;
	const struct cred *old_cred;
	struct file *fuse_filp = iocb_fuse->ki_filp;
	struct fuse_file *ff = fuse_filp->private_data;
	struct file *passthrough_filp = ff->passthrough_filp;

	if (!iov_iter_count(iter))
		return 0;

	old_cred = fuse_passthrough_override_creds(fuse_filp);
	if (is_sync_kiocb(iocb_fuse)) {
		ret = vfs_iter_read(passthrough_filp, iter, &iocb_fuse->ki_pos,
				    iocbflags_to_rwf(iocb_fuse->ki_flags));
	} else {
		ret = -EIO;
	}
	revert_creds(old_cred);

	return ret;
}

ssize_t fuse_passthrough_write_iter(struct kiocb *iocb_fuse,
				    struct iov_iter *iter)
{
	ssize_t ret;
	const struct cred *old_cred;
	struct file *fuse_filp = iocb_fuse->ki_filp;
	struct fuse_file *ff = fuse_filp->private_data;
	struct inode *fuse_inode = file_inode(fuse_filp);
	struct file *passthrough_filp = ff->passthrough_filp;

	if (!iov_iter_count(iter))
		return 0;

	inode_lock(fuse_inode);

	old_cred = fuse_passthrough_override_creds(fuse_filp);
	if (is_sync_kiocb(iocb_fuse)) {
		file_start_write(passthrough_filp);
		ret = vfs_iter_write(passthrough_filp, iter, &iocb_fuse->ki_pos,
				     iocbflags_to_rwf(iocb_fuse->ki_flags));
		file_end_write(passthrough_filp);
		if (ret > 0)
			fuse_copyattr(fuse_filp, passthrough_filp);
	} else {
		ret = -EIO;
	}
	revert_creds(old_cred);
	inode_unlock(fuse_inode);

	return ret;
}

int fuse_passthrough_open(struct fuse_dev *fud,
			  struct fuse_passthrough_out *pto)
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
