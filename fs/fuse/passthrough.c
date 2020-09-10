// SPDX-License-Identifier: GPL-2.0

#include "fuse_i.h"

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
