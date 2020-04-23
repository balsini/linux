#include "extfuse_i.h"

#undef pr_fmt
#define pr_fmt(fmt)	"ExtFUSE: " fmt

/* create a copy of args for extfuse request handlers */
static void fuse_to_extfuse_req(const struct fuse_req *req,
				struct extfuse_req *ereq)
{
	ereq->in.h.opcode = req->in.h.opcode;
	ereq->in.h.nodeid = req->in.h.nodeid;
	ereq->in.numargs = req->in.numargs;
	memcpy(ereq->in.args, req->in.args,
	       req->in.numargs * sizeof(struct fuse_in_arg));
	ereq->out.argvar = req->out.argvar;
	ereq->out.numargs = req->out.numargs;
	memcpy(ereq->out.args, req->out.args,
	       req->out.numargs * sizeof(struct fuse_arg));
}

/* only copy out args */
static void extfuse_to_fuse_req(struct extfuse_req *ereq,
		struct fuse_req *req)
{
	req->out.argvar = ereq->out.argvar;
	req->out.numargs = ereq->out.numargs;
	memcpy(req->out.args, ereq->out.args,
			ereq->out.numargs * sizeof(struct fuse_arg));
}


static int extfuse_run_prog(struct bpf_prog *eprog, struct extfuse_req *ereq)
{
	int ret = -ENOSYS;
	struct bpf_prog *prog;

	preempt_disable();
	prog = READ_ONCE(eprog);
	if (prog) {
		/* run program */
		rcu_read_lock();
		ret = BPF_PROG_RUN(prog, ereq);
		rcu_read_unlock();
	}
	preempt_enable();

	return ret;
}

int extfuse_request_send(struct fuse_conn *fc, struct fuse_req *req)
{
	struct extfuse_data *data = (struct extfuse_data *)fc->fc_priv;
	ssize_t ret = -ENOSYS;

	pr_info("handling req, fc_priv=%p\n", fc->fc_priv);

	if (data) {
		struct extfuse_req ereq;
		fuse_to_extfuse_req(req, &ereq);
		ret = extfuse_run_prog(data->prog, &ereq);
		if (ret != -ENOSYS) {
			extfuse_to_fuse_req(&ereq, req);
			req->out.h.error = (int)ret;
			ret = 0;
			pr_info("\tSUCCESS\n");
		} else {
			pr_err("\thandler unavailable (-ENOSYS)\n");
		}
	} else {
		pr_err("\tdata == NULL\n");
	}
	return ret;
}

void extfuse_unload_prog(struct fuse_conn *fc)
{
	struct extfuse_data *data = (struct extfuse_data *)fc->fc_priv;

	WARN_ON(data == NULL);

	if (data) {
		struct bpf_prog *old_prog;

		BUG_ON(data->prog == NULL);

		old_prog = xchg(&data->prog, NULL);
		bpf_prog_put(old_prog);
		pr_info("BPF prog unloaded\n");
		kfree(data);
		fc->fc_priv = NULL;
	}
}

int extfuse_load_prog(struct fuse_conn *fc, int fd)
{
	struct bpf_prog *prog = NULL;
	struct bpf_prog *old_prog;
	struct extfuse_data *data;

	BUG_ON(fc->fc_priv);

	data = kcalloc(1, sizeof(struct extfuse_data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	prog = bpf_prog_get_type(fd, BPF_PROG_TYPE_EXTFUSE);
	if (IS_ERR(prog)) {
		pr_err("BPF prog fd=%d failed: %ld\n",
			fd, PTR_ERR(prog));
		kfree(data);
		return -1;
	}

	old_prog = xchg(&data->prog, prog);
	if (old_prog)
		bpf_prog_put(old_prog);

	fc->fc_priv = (void *)data;

	pr_info("BPF prog loaded fd=%d, fc_priv=%p\n", fd, fc->fc_priv);
	return 0;
}

/**
 * int bpf_extfuse_read_args(): attempts to copy the requested src field to dst.
 * @src: a pointer to a extfuse_req data structure
 * @type: Specifies what field of the src data structure to be copied to dst
 * @dst: a pointer to the container that will be filled with the requested data
 * @size: size of the data chunk to be copied to dst
 */
BPF_CALL_4(bpf_extfuse_read_args, void *, src, u32, type, void *, dst, size_t, size)
{
	struct extfuse_req *req = (struct extfuse_req *)src;
	unsigned num_in_args = req->in.numargs;
	unsigned num_out_args = req->out.numargs;
	const void *inptr = NULL;
	int ret = -EINVAL;

	pr_info("BPF_CALL read_args (%u)\n", type);

	switch (type) {
	case OPCODE:
		if (size != sizeof(uint32_t))
			return -EINVAL;
		inptr = (void *)&req->in.h.opcode;
		break;
	case NODEID:
		if (size != sizeof(uint64_t))
			return -EINVAL;
		inptr = (void *)&req->in.h.nodeid;
		break;
	case NUM_IN_ARGS:
		if (size != sizeof(unsigned))
			return -EINVAL;
		inptr = (void *)&req->in.numargs;
		break;
	case NUM_OUT_ARGS:
		if (size != sizeof(unsigned))
			return -EINVAL;
		inptr = (void *)&req->out.numargs;
		break;
	case IN_PARAM_0_SIZE:
		if (size != sizeof(unsigned) || num_in_args < 1 ||
		    num_in_args > 3)
			return -EINVAL;
		inptr = &req->in.args[0].size;
		break;
	case IN_PARAM_0_VALUE:
		if (num_in_args < 1 || num_in_args > 3)
			return -EINVAL;
		if (size < req->in.args[0].size)
			return -E2BIG;
		size = req->in.args[0].size;
		inptr = req->in.args[0].value;
		break;
	case IN_PARAM_1_SIZE:
		if (size != sizeof(unsigned) || num_in_args < 2 ||
		    num_in_args > 3)
			return -EINVAL;
		inptr = &req->in.args[1].size;
		break;
	case IN_PARAM_1_VALUE:
		if (num_in_args < 2 || num_in_args > 3)
			return -EINVAL;
		if (size < req->in.args[1].size)
			return -E2BIG;
		size = req->in.args[1].size;
		inptr = req->in.args[1].value;
		break;
	case IN_PARAM_2_SIZE:
		if (size != sizeof(unsigned) || num_in_args != 3)
			return -EINVAL;
		inptr = &req->in.args[2].size;
		break;
	case IN_PARAM_2_VALUE:
		if (num_in_args != 3)
			return -EINVAL;
		if (size < req->in.args[2].size)
			return -E2BIG;
		size = req->in.args[2].size;
		inptr = req->in.args[2].value;
		break;
	case OUT_PARAM_0:
		if (num_out_args < 1 || num_out_args > 2)
			return -EINVAL;
		if (size != req->out.args[0].size)
			return -E2BIG;
		inptr = req->out.args[0].value;
		break;
	case OUT_PARAM_1:
		if (num_out_args != 2)
			return -EINVAL;
		if (size != req->out.args[1].size)
			return -E2BIG;
		inptr = req->out.args[1].value;
		break;
	default:
		return -EBADRQC;
		break;
	}

#if 0
	if (type == OPCODE && size == sizeof(uint32_t)) {
		inptr = (void *)&req->in.h.opcode;
	} else if (type == NODEID && size == sizeof(uint64_t)) {
		inptr = (void *)&req->in.h.nodeid;
	} else if (type == NUM_IN_ARGS && size == sizeof(unsigned)) {
		inptr = (void *)&req->in.numargs;
	} else if (type == NUM_OUT_ARGS && size == sizeof(unsigned)) {
		inptr = (void *)&req->out.numargs;
	} else if (type == IN_PARAM_0_SIZE && size == sizeof(unsigned) &&
		   num_in_args >= 1 && num_in_args <= 3) {
		inptr = &req->in.args[0].size;
	} else if (type == IN_PARAM_0_VALUE && num_in_args >= 1 &&
		   num_in_args <= 3) {
		ret = -E2BIG;
		if (size >= req->in.args[0].size) {
			size = req->in.args[0].size;
			inptr = req->in.args[0].value;
		}
	} else if (type == IN_PARAM_1_SIZE && size == sizeof(unsigned) &&
		   num_in_args >= 2 && num_in_args <= 3) {
		inptr = &req->in.args[1].size;
	} else if (type == IN_PARAM_1_VALUE && num_in_args >= 2 &&
		   num_in_args <= 3) {
		ret = -E2BIG;
		if (size >= req->in.args[1].size) {
			size = req->in.args[1].size;
			inptr = req->in.args[1].value;
		}
	} else if (type == IN_PARAM_2_SIZE && size == sizeof(unsigned) &&
		   num_in_args == 3) {
		inptr = &req->in.args[1].size;
	} else if (type == IN_PARAM_2_VALUE && num_in_args == 3) {
		ret = -E2BIG;
		if (size >= req->in.args[2].size) {
			size = req->in.args[2].size;
			inptr = req->in.args[2].value;
		}
	} else if (type == OUT_PARAM_0 && num_out_args >= 1 &&
		   num_out_args <= 2 && size == req->out.args[0].size) {
		inptr = req->out.args[0].value;
	} else if (type == OUT_PARAM_1 && num_out_args == 2 &&
		   size == req->out.args[1].size) {
		inptr = req->out.args[1].value;
	}
#endif

	if (!inptr) {
		pr_err("\tinvalid input to %s type: %d num_in_args: %d "
		       "num_out_args: %d size: %ld\n",
		       __func__, type, num_in_args, num_out_args, size);
		return ret;
	}

	ret = probe_kernel_read(dst, inptr, size);
	if (ret < 0)
		memset(dst, 0, size);

	return ret;
}

static const struct bpf_func_proto bpf_extfuse_read_args_proto = {
	.func		= bpf_extfuse_read_args,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING, //ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};

/**
 * int bpf_extfuse_write_args(): attempts to copy the src field to dst.
 * @src: a pointer to a extfuse_req data structure
 * @type: Specifies what field of the src data structure to be copied to dst
 * @dst: a pointer to the container that will be filled with the requested data
 * @size: size of the data chunk to be copied to dst
 */
BPF_CALL_4(bpf_extfuse_write_args, void *, dst, u32, type, const void *, src, u32,
	   size)
{
	struct extfuse_req *req = (struct extfuse_req *)dst;
	unsigned numargs = req->out.numargs;
	void *outptr = NULL;
	int ret = -EINVAL;

	pr_info("BPF_CALL write_args\n");

	if (type == OUT_PARAM_0 && numargs >= 1 && numargs <= 2 &&
	    size == req->out.args[0].size) {
		outptr = req->out.args[0].value;
	} else if (type == OUT_PARAM_1 && numargs == 2 &&
		   size == req->out.args[1].size) {
		outptr = req->out.args[1].value;
	}

	if (!outptr) {
		pr_err("\tinvalid input to %s type: %d "
			 "num_args: %d size: %d\n",
			 __func__, type, numargs, size);
		return ret;
	}

	ret = probe_kernel_write(outptr, src, size);
	if (ret < 0)
		memset(outptr, 0, size);

	return ret;
}

static const struct bpf_func_proto bpf_extfuse_write_args_proto = {
	.func		= bpf_extfuse_write_args,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING, //ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_PTR_TO_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};

static const struct bpf_func_proto *
bpf_extfuse_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_extfuse_read_args:
		return &bpf_extfuse_read_args_proto;
	case BPF_FUNC_extfuse_write_args:
		return &bpf_extfuse_write_args_proto;
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_tail_call:
		return &bpf_tail_call_proto;
	case BPF_FUNC_trace_printk:
		return bpf_get_trace_printk_proto();
	default:
		return NULL;
	}
}

/* bpf+fuse programs can access fields of 'struct pt_regs' */
static bool bpf_extfuse_is_valid_access(int off, int size,
		enum bpf_access_type type, const struct bpf_prog *prog,
		struct bpf_insn_access_aux *info)
{
	if (off < 0 || off >= sizeof(struct fuse_args))
		return false;
	if (type != BPF_READ)
		return false;
	if (off % size != 0)
		return false;
	/*
	 * Assertion for 32 bit to make sure last 8 byte access
	 * (BPF_DW) to the last 4 byte member is disallowed.
	 */
	if (off + size > sizeof(struct fuse_args))
		return false;

	return true;
}

const struct bpf_verifier_ops extfuse_verifier_ops = {
	.get_func_proto  = bpf_extfuse_func_proto,
	.is_valid_access = bpf_extfuse_is_valid_access,
};

const struct bpf_prog_ops extfuse_prog_ops = {
	.test_run = NULL,
};
