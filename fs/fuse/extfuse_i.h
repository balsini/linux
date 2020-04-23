#ifndef _EXTFUSE_I_H
#define _EXTFUSE_I_H

#include <asm-generic/errno.h>

#ifdef CONFIG_EXTFUSE

#include "fuse_i.h"

#include <linux/bpf.h>
#include <linux/extfuse.h>
#include <linux/filter.h>

struct extfuse_data {
	struct bpf_prog *prog;
};

/** The request input */
struct extfuse_in {
	/** The request header */
	struct fuse_in_header h;

	/** Number of arguments */
	unsigned numargs;

	/** Array of arguments */
	struct fuse_in_arg args[3];
};

/** The request output */
struct extfuse_out {
	/** Header returned from userspace */
	struct fuse_out_header h;

	/** Last argument is variable length (can be shorter than
	    arg->size) */
	unsigned argvar : 1;

	/** Number or arguments */
	unsigned numargs;

	/** Array of arguments */
	struct fuse_arg args[2];
};

struct extfuse_req {
	/** The request input */
	struct extfuse_in in;

	/** The request output */
	struct extfuse_out out;
};

#define EXTFUSE_ERROR(x)	(x < 0 && x != -ENOSYS)
#define EXTFUSE_UPCALL(x)	(x == -ENOSYS)
#define EXTFUSE_PASSTHRU(x)	(x > 0)
#define EXTFUSE_RETURN(x)	(x == 0)

#define EXTFUSE_FLAGS		FUSE_FS_EXTFUSE

extern int extfuse_load_prog(struct fuse_conn *fc, int fd);
extern void extfuse_unload_prog(struct fuse_conn *fc);
extern int extfuse_request_send(struct fuse_conn *fc, struct fuse_req *req);
#else

#define EXTFUSE_FLAGS		0

static inline int extfuse_load_prog(struct fuse_conn *fc, int fd)
{
	return -ENOSYS;
}

static inline void extfuse_unload_prog(struct fuse_conn *fc)
{
	return;
}

static inline int extfuse_request_send(struct fuse_conn *fc,
				       struct fuse_req *req)
{
	return -ENOSYS;
}
#endif /* CONFIG_EXTFUSE */

#endif /* _EXTFUSE_H */
