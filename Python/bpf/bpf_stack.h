/* BPF declarations */

struct bpf_stack_args {
	__u64 data;
	__u32 flags;
	__u8 depth;
	char str_sep;
	__u8 str_len;
	__u8 __pad;
	char str[256];
};

enum {
        BPF_STACK_FLAGS_LONG = 0x1,
};

static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) =
	(void *)(long)BPF_FUNC_probe_read_user;
static long (*bpf_probe_read_user_str)(void *dst, __u32 size, const void *unsafe_ptr) =
	(void *)(long)BPF_FUNC_probe_read_user_str;


