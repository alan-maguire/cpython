#ifndef __BPF_STACK_H__
#define __BPF_STACK_H__


/* BPF declarations */

struct bpf_stack_args {
	unsigned long data;
	unsigned int flags;
	unsigned char depth;
	char str_sep;
	unsigned char  str_len;
	unsigned char __pad;
	char str[256];
};

enum {
        BPF_STACK_FLAGS_LONG = 0x1,
};

#define BPF_STACK_MAX_DEPTH  16
#define BPF_STACK_MAX_CHUNK  64

#ifdef __bpf__

#ifndef __BPF_HELPERS__
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) =
        (void *)(long)BPF_FUNC_probe_read_user;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) =
        (void *)(long)BPF_FUNC_probe_read_user_str;
#endif /* __BPF_HELPERS__ */

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

#ifndef EFAULT
#define EFAULT 14
#endif
#ifndef ENOSPC
#define ENOSPC 28
#endif
#ifndef EINVAL
#define EINVAL 22
#endif

typedef __SIZE_TYPE__ size_t;

static __always_inline int
bpf_stack_append_char(struct bpf_stack_args *args, char ch)
{
	if (!args)
		return -EINVAL;

	if (args->str_len + 1 >= sizeof(args->str))
		return -ENOSPC;

	args->str[args->str_len++] = ch;
	return 0;
}

static __always_inline int
bpf_stack_append_str(struct bpf_stack_args *args, const char *str, size_t len)
{
	char *end;
	int ret;

	if (!args)
		return -EINVAL;

	if (len == 0)
		return 0;

	/* verifier */
	end = args->str + (args->str_len & (sizeof(args->str) - 1));

	if (BPF_STACK_MAX_CHUNK > sizeof(args->str) - args->str_len)
		return -ENOSPC;
	ret = bpf_probe_read_user_str(end, BPF_STACK_MAX_CHUNK, str);
	if (ret < 0)
		return ret;

	if (len > BPF_STACK_MAX_CHUNK)
		args->str_len += BPF_STACK_MAX_CHUNK;
        else
                args->str_len += len;

	return 0;
}
#endif /* __bpf__ */

#endif /* __BPP_STACK_H__ */
