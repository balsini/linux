#include "extfuse_i.h"

#undef pr_fmt
#define pr_fmt(fmt)	"ExtFUSE: " fmt

/* create a copy of args for extfuse request handlers */
static void fuse_to_extfuse_req(struct fuse_req *req,
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

	prog = READ_ONCE(eprog);
	if (prog) {
		/* run program */
		rcu_read_lock();
		ret = BPF_PROG_RUN(prog, ereq);
		rcu_read_unlock();
	}

	return ret;
}

int extfuse_request_send(struct fuse_conn *fc, struct fuse_req *req)
{
	ssize_t ret = -ENOSYS;
	struct extfuse_data *data = (struct extfuse_data *)fc->fc_priv;
	if (data) {
		struct extfuse_req ereq;
		fuse_to_extfuse_req(req, &ereq);
		ret = extfuse_run_prog(data->prog, &ereq);
		if (ret != -ENOSYS) {
			extfuse_to_fuse_req(&ereq, req);
			req->out.h.error = (int)ret;
			ret = 0;
		}
	}
	return ret;
}

void extfuse_unload_prog(struct fuse_conn *fc)
{
	struct extfuse_data *data = (struct extfuse_data *)fc->fc_priv;
	if (data) {
		struct bpf_prog *old_prog;
		old_prog = xchg(&data->prog, NULL);
		if (old_prog) {
			bpf_prog_put(old_prog);
			pr_info("ExtFUSE bpf prog unloaded\n");
		}
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

	data = kmalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return -ENOMEM;

	prog = bpf_prog_get_type(fd, BPF_PROG_TYPE_EXTFUSE);
	if (IS_ERR(prog)) {
		pr_err("ExtFUSE bpf prog fd=%d failed: %ld\n",
			fd, PTR_ERR(prog));
		kfree(data);
		return -1;
	}

	old_prog = xchg(&data->prog, prog);
	if (old_prog)
		bpf_prog_put(old_prog);

	pr_info("ExtFUSE bpf prog loaded fd=%d\n", fd);
	return 0;
}

BPF_CALL_4(bpf_extfuse_read_args, void *, p, u32, type, void *, dst, u32, size)
{
	int ret = -EINVAL;
	const void *inptr = NULL;
	struct extfuse_req *req= (struct extfuse_req *)p;
	unsigned num_in_args = req->in.numargs;
	unsigned num_out_args = req->out.numargs;

	if (type == OPCODE && size == sizeof(uint32_t))
		inptr = (void *)&req->in.h.opcode;

	else if (type == NODEID && size == sizeof(uint64_t))
		inptr = (void *)&req->in.h.nodeid;

	else if (type == NUM_IN_ARGS && size == sizeof(unsigned))
		inptr = (void *)&req->in.numargs;

	else if (type == NUM_OUT_ARGS && size == sizeof(unsigned))
		inptr = (void *)&req->out.numargs;

	// input param 0
	else if (type == IN_PARAM_0_SIZE && size == sizeof(unsigned) &&
			num_in_args >= 1 && num_in_args <= 3)
		inptr = &req->in.args[0].size;

	else if (type == IN_PARAM_0_VALUE && num_in_args >= 1 &&
			num_in_args <= 3) {
		ret = -E2BIG;
		if (size >= req->in.args[0].size) {
			size = req->in.args[0].size;
			inptr = req->in.args[0].value;
		}
	}

	// input param 1
	else if (type == IN_PARAM_1_SIZE && size == sizeof(unsigned) &&
			num_in_args >= 2 && num_in_args <= 3)
		inptr = &req->in.args[1].size;

	else if (type == IN_PARAM_1_VALUE && num_in_args >= 2 &&
			num_in_args <= 3) {
		ret = -E2BIG;
		if (size >= req->in.args[1].size) {
			size = req->in.args[1].size;
			inptr = req->in.args[1].value;
		}
	}

	// input param 2
	else if (type == IN_PARAM_2_SIZE && size == sizeof(unsigned) &&
			num_in_args == 3)
		inptr = &req->in.args[1].size;

	else if (type == IN_PARAM_2_VALUE && num_in_args == 3) {
		ret = -E2BIG;
		if (size >= req->in.args[2].size) {
			size = req->in.args[2].size;
			inptr = req->in.args[2].value;
		}
	}

	// output param 2
	else if (type == OUT_PARAM_0 && num_out_args >= 1 &&
			num_out_args <= 2 && size == req->out.args[0].size)
		inptr = req->out.args[0].value;

	// output param 3
	else if (type == OUT_PARAM_1 && num_out_args == 2 &&
			size == req->out.args[1].size)
		inptr = req->out.args[1].value;

	if (!inptr) {
		pr_err("Invalid input to %s type: %d num_in_args: %d "
			"num_out_args: %d size: %d\n",
			__func__, type, num_in_args, num_out_args, size);
		return ret;
	}

	ret = probe_kernel_read(dst, inptr, size);
	if (unlikely(ret < 0))
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

BPF_CALL_4(bpf_extfuse_write_args, void *, p, u32, type, const void *,
		src, u32, size)
{
	int ret = -EINVAL;
	void *outptr = NULL;
	struct extfuse_req *req= (struct extfuse_req *)p;
	unsigned numargs = req->out.numargs;

	if (type == OUT_PARAM_0 && numargs >= 1 && numargs <= 2 &&
			size == req->out.args[0].size)
		outptr = req->out.args[0].value;

	else if (type == OUT_PARAM_1 && numargs == 2 &&
			size == req->out.args[1].size)
		outptr = req->out.args[1].value;

	if (!outptr) {
		pr_debug("Invalid input to %s type: %d "
				"num_args: %d size: %d\n",
				__func__, type, numargs, size);
		return ret;
	}

	ret = probe_kernel_write(outptr, src, size);
	if (unlikely(ret < 0))
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
	case BPF_FUNC_map_lookup_elem:
		return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem:
		return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem:
		return &bpf_map_delete_elem_proto;
	case BPF_FUNC_extfuse_read_args:
		return &bpf_extfuse_read_args_proto;
	case BPF_FUNC_extfuse_write_args:
		return &bpf_extfuse_write_args_proto;
	case BPF_FUNC_tail_call:
		return &bpf_tail_call_proto;
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
