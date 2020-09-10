// SPDX-License-Identifier: GPL-2.0

#include "fuse_i.h"

#include <linux/fs_stack.h>
#include <linux/fsnotify.h>
#include <linux/uio.h>

static void fuse_copyattr(struct file *dst_file, struct file *src_file,
			  bool write)
{
	if (write) {
		struct inode *dst = file_inode(dst_file);
		struct inode *src = file_inode(src_file);

		fsnotify_modify(src_file);
		fsstack_copy_inode_size(dst, src);
	} else {
		fsnotify_access(src_file);
	}
}


ssize_t fuse_passthrough_read_iter(struct kiocb *iocb_fuse,
				   struct iov_iter *iter)
{
	ssize_t ret;
	struct file *fuse_filp = iocb_fuse->ki_filp;
	struct fuse_file *ff = fuse_filp->private_data;
	struct file *passthrough_filp = ff->passthrough_filp;

	if (!iov_iter_count(iter))
		return 0;

	if (is_sync_kiocb(iocb_fuse)) {
		struct kiocb iocb;

		kiocb_clone(&iocb, iocb_fuse, passthrough_filp);
		ret = call_read_iter(passthrough_filp, &iocb, iter);
		iocb_fuse->ki_pos = iocb.ki_pos;
		if (ret >= 0)
			fuse_copyattr(fuse_filp, passthrough_filp, false);

	} else {
		ret = -EIO;
	}

	return ret;
}

ssize_t fuse_passthrough_write_iter(struct kiocb *iocb_fuse,
				    struct iov_iter *iter)
{
	ssize_t ret;
	struct file *fuse_filp = iocb_fuse->ki_filp;
	struct fuse_file *ff = fuse_filp->private_data;
	struct inode *fuse_inode = file_inode(fuse_filp);
	struct file *passthrough_filp = ff->passthrough_filp;

	if (!iov_iter_count(iter))
		return 0;

	inode_lock(fuse_inode);

	if (is_sync_kiocb(iocb_fuse)) {
		struct kiocb iocb;

		kiocb_clone(&iocb, iocb_fuse, passthrough_filp);

		file_start_write(passthrough_filp);
		ret = call_write_iter(passthrough_filp, &iocb, iter);
		file_end_write(passthrough_filp);

		iocb_fuse->ki_pos = iocb.ki_pos;
		if (ret > 0)
			fuse_copyattr(fuse_filp, passthrough_filp, true);
	} else {
		ret = -EIO;
	}

	inode_unlock(fuse_inode);

	return ret;
}

int fuse_passthrough_setup(struct fuse_req *req, unsigned int fd)
{
	int ret;
	int fs_stack_depth;
	struct file *passthrough_filp;
	struct inode *passthrough_inode;
	struct super_block *passthrough_sb;

	/* Passthrough mode can only be enabled at file open/create time */
	if (req->in.h.opcode != FUSE_OPEN && req->in.h.opcode != FUSE_CREATE) {
		pr_err("FUSE: invalid OPCODE for request.\n");
		return -EINVAL;
	}

	passthrough_filp = fget(fd);
	if (!passthrough_filp) {
		pr_err("FUSE: invalid file descriptor for passthrough.\n");
		return -EINVAL;
	}

	ret = -EINVAL;
	if (!passthrough_filp->f_op->read_iter ||
	    !passthrough_filp->f_op->write_iter) {
		pr_err("FUSE: passthrough file misses file operations.\n");
		goto out;
	}

	passthrough_inode = file_inode(passthrough_filp);
	passthrough_sb = passthrough_inode->i_sb;
	fs_stack_depth = passthrough_sb->s_stack_depth + 1;
	ret = -EEXIST;
	if (fs_stack_depth > FILESYSTEM_MAX_STACK_DEPTH) {
		pr_err("FUSE: maximum fs stacking depth exceeded for passthrough\n");
		goto out;
	}

	req->args->passthrough_filp = passthrough_filp;
	return 0;
out:
	fput(passthrough_filp);
	return ret;
}

void fuse_passthrough_release(struct fuse_file *ff)
{
	if (!ff->passthrough_filp)
		return;

	fput(ff->passthrough_filp);
	ff->passthrough_filp = NULL;
}
