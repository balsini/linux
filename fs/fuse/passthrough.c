// SPDX-License-Identifier: GPL-2.0

#include "fuse_i.h"

#include <linux/aio.h>
#include <linux/fs_stack.h>
#include <linux/uio.h>

static struct kmem_cache *fuse_aio_request_cachep;

struct fuse_aio_req {
	struct kiocb iocb;
	struct kiocb *iocb_fuse;
};

static void fuse_copyattr(struct file *dst_file, struct file *src_file,
			  bool write)
{
	struct inode *dst = file_inode(dst_file);
	struct inode *src = file_inode(src_file);

	fsstack_copy_attr_times(dst, src);
	if (write)
		fsstack_copy_inode_size(dst, src);
}

static void fuse_aio_cleanup_handler(struct fuse_aio_req *aio_req)
{
	struct kiocb *iocb_fuse = aio_req->iocb_fuse;
	struct kiocb *iocb = &aio_req->iocb;

	if (iocb->ki_flags & IOCB_WRITE) {
		__sb_writers_acquired(file_inode(iocb->ki_filp)->i_sb,
				      SB_FREEZE_WRITE);
		file_end_write(iocb->ki_filp);
		fuse_copyattr(iocb_fuse->ki_filp, iocb->ki_filp, true);
	}

	iocb_fuse->ki_pos = iocb->ki_pos;
	kmem_cache_free(fuse_aio_request_cachep, aio_req);
}

static void fuse_aio_rw_complete(struct kiocb *iocb, long res, long res2)
{
	struct fuse_aio_req *aio_req =
		container_of(iocb, struct fuse_aio_req, iocb);
	struct kiocb *iocb_fuse = aio_req->iocb_fuse;

	fuse_aio_cleanup_handler(aio_req);
	iocb_fuse->ki_complete(iocb_fuse, res, res2);
}

ssize_t fuse_passthrough_read_iter(struct kiocb *iocb_fuse,
				   struct iov_iter *iter)
{
	struct file *fuse_filp = iocb_fuse->ki_filp;
	struct fuse_file *ff = fuse_filp->private_data;
	struct file *passthrough_filp = ff->passthrough_filp;
	ssize_t ret;

	if (!iov_iter_count(iter))
		return 0;

	if (is_sync_kiocb(iocb_fuse)) {
		struct kiocb iocb;

		kiocb_clone(&iocb, iocb_fuse, passthrough_filp);
		ret = call_read_iter(passthrough_filp, &iocb, iter);
		iocb_fuse->ki_pos = iocb.ki_pos;
	} else {
		struct fuse_aio_req *aio_req;

		aio_req =
			kmem_cache_zalloc(fuse_aio_request_cachep, GFP_KERNEL);
		if (!aio_req)
			return -ENOMEM;

		aio_req->iocb_fuse = iocb_fuse;
		kiocb_clone(&aio_req->iocb, iocb_fuse, passthrough_filp);
		aio_req->iocb.ki_complete = fuse_aio_rw_complete;
		ret = vfs_iocb_iter_read(passthrough_filp, &aio_req->iocb,
					 iter);
		if (ret != -EIOCBQUEUED)
			fuse_aio_cleanup_handler(aio_req);
	}

	fuse_copyattr(fuse_filp, passthrough_filp, false);

	return ret;
}

ssize_t fuse_passthrough_write_iter(struct kiocb *iocb_fuse,
				    struct iov_iter *iter)
{
	struct file *fuse_filp = iocb_fuse->ki_filp;
	struct fuse_file *ff = fuse_filp->private_data;
	struct file *passthrough_filp = ff->passthrough_filp;
	struct inode *passthrough_inode = file_inode(passthrough_filp);
	struct inode *fuse_inode = file_inode(fuse_filp);
	ssize_t ret;

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
		fuse_copyattr(fuse_filp, passthrough_filp, true);
	} else {
		struct fuse_aio_req *aio_req;

		aio_req =
			kmem_cache_zalloc(fuse_aio_request_cachep, GFP_KERNEL);
		if (!aio_req)
			return -ENOMEM;

		file_start_write(passthrough_filp);
		__sb_writers_release(passthrough_inode->i_sb, SB_FREEZE_WRITE);

		aio_req->iocb_fuse = iocb_fuse;
		kiocb_clone(&aio_req->iocb, iocb_fuse, passthrough_filp);
		aio_req->iocb.ki_complete = fuse_aio_rw_complete;
		ret = vfs_iocb_iter_write(passthrough_filp, &aio_req->iocb,
					  iter);
		if (ret != -EIOCBQUEUED)
			fuse_aio_cleanup_handler(aio_req);
	}

	inode_unlock(fuse_inode);

	return ret;
}

int fuse_passthrough_setup(struct fuse_conn *fc, struct fuse_req *req)
{
	struct super_block *passthrough_sb;
	struct inode *passthrough_inode;
	struct fuse_open_out *open_out;
	struct file *passthrough_filp;
	unsigned short open_out_index;
	int fs_stack_depth;

	req->passthrough_filp = NULL;

	if (!fc->passthrough)
		return 0;

	if (!(req->in.h.opcode == FUSE_OPEN && req->args->out_numargs == 1) &&
	    !(req->in.h.opcode == FUSE_CREATE && req->args->out_numargs == 2))
		return 0;

	open_out_index = req->args->out_numargs - 1;

	if (req->args->out_args[open_out_index].size != sizeof(*open_out))
		return 0;

	open_out = req->args->out_args[open_out_index].value;

	if (!(open_out->open_flags & FOPEN_PASSTHROUGH))
		return 0;

	passthrough_filp = fget(open_out->fd);
	if (!passthrough_filp) {
		pr_err("FUSE: invalid file descriptor for passthrough.\n");
		return -1;
	}

	if (!passthrough_filp->f_op->read_iter ||
	    !passthrough_filp->f_op->write_iter) {
		pr_err("FUSE: passthrough file misses file operations.\n");
		fput(passthrough_filp);
		return -1;
	}

	passthrough_inode = file_inode(passthrough_filp);
	passthrough_sb = passthrough_inode->i_sb;
	fs_stack_depth = passthrough_sb->s_stack_depth + 1;
	if (fs_stack_depth > FILESYSTEM_MAX_STACK_DEPTH) {
		pr_err("FUSE: maximum fs stacking depth exceeded for passthrough\n");
		fput(passthrough_filp);
		return -1;
	}

	req->passthrough_filp = passthrough_filp;
	return 0;
}

void fuse_passthrough_release(struct fuse_file *ff)
{
	if (ff->passthrough_filp) {
		fput(ff->passthrough_filp);
		ff->passthrough_filp = NULL;
	}
}

int __init fuse_passthrough_aio_request_cache_init(void)
{
	fuse_aio_request_cachep =
		kmem_cache_create("fuse_aio_req", sizeof(struct fuse_aio_req),
				  0, SLAB_HWCACHE_ALIGN, NULL);
	if (!fuse_aio_request_cachep)
		return -ENOMEM;

	return 0;
}

void fuse_passthrough_aio_request_cache_destroy(void)
{
	kmem_cache_destroy(fuse_aio_request_cachep);
}
