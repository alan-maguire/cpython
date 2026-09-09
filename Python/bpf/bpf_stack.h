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

#endif /* __BPP_STACK_H__ */
