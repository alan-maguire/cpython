/*
 * CPython BPF stack unwinder.
 *
 */

#include <linux/bpf.h>

#include "bpf_stack.h"
#include "bpf_stack_offsets.h"

#define SEC(NAME) __attribute__((section(NAME), used))
#define EFAULT 14
#define ENOSPC 28
#define EINVAL 22

typedef __SIZE_TYPE__ size_t;

#define PY_BPF_STACK_MAX_DEPTH	16
#define PY_BPF_STACK_MAX_CHUNK	64

static __always_inline int
append_char(struct bpf_stack_args *args, char ch)
{
	if (!args)
		return -EINVAL;

	if (args->str_len + 1 >= sizeof(args->str))
		return -ENOSPC;

	args->str[args->str_len++] = ch;
	return 0;
}

static __always_inline int
append_unicode(struct bpf_stack_args *args, void *unicode)
{
	int nospace = 0;
	size_t count;
	__s64 length;
	__u32 state;
	char *str;
	int ret;

	if (!args)
		return -EINVAL;

	if (bpf_probe_read_user(&length, sizeof(length),
				unicode + PY_BPF_UNICODE_LENGTH) ||
	    bpf_probe_read_user(&state, sizeof(state),
				unicode + PY_BPF_UNICODE_STATE))
		return -EFAULT;

	if (length < 0 || !(state & PY_BPF_UNICODE_STATE_ASCII_MASK))
		return append_char(args, '?');

	count = (size_t)length;
	if (count == 0)
		return 0;

	/* verifier */
	str = args->str + (args->str_len & (sizeof(args->str) - 1));

	if (PY_BPF_STACK_MAX_CHUNK > sizeof(args->str) - args->str_len)
		return -ENOSPC;
	ret = bpf_probe_read_user_str(str, PY_BPF_STACK_MAX_CHUNK,
				      unicode + PY_BPF_UNICODE_ASCII_DATA);
	if (ret < 0)
		return ret;

	if (count > PY_BPF_STACK_MAX_CHUNK)
		args->str_len += PY_BPF_STACK_MAX_CHUNK;
	else
		args->str_len += count;

	return nospace ? -ENOSPC : 0;
}

/*
 * BPF-to-BPF replacement for a loader-provided bpf_stack() extension point.
 * data is the current PyThreadState pointer supplied by the USDT handler.
 * Write "[filename:]qualname<sep>" records from the current frame outwards.
 * Return 0 on success or a negative errno value.
 */
SEC("freplace/bpf_stack")
int
bpf_stack(struct bpf_stack_args *args)
{
	void *tstate;
	char *str;
	unsigned short depth;
	void *frame, *base_frame;
	unsigned short i;

	if (!args)
		return -EINVAL;

	tstate = (void *)(unsigned long)args->data;
	str = args->str;
	args->str_len = 0;
	depth = args->depth;

	str[0] = '\0';

	if (bpf_probe_read_user(&frame, sizeof(frame),
				 tstate + PY_BPF_TSTATE_CURRENT_FRAME) ||
	    bpf_probe_read_user(&base_frame, sizeof(base_frame),
				 tstate + PY_BPF_TSTATE_BASE_FRAME))
		return -EFAULT;

	if (depth > PY_BPF_STACK_MAX_DEPTH)
		depth = PY_BPF_STACK_MAX_DEPTH;

	for (i = 0; i < depth && frame && frame != base_frame; i++) {
		void *previous, *code, *qualname;
		__u64 executable;
		int err = 0;

		if (bpf_probe_read_user(&executable, sizeof(executable),
					frame + PY_BPF_FRAME_EXECUTABLE) ||
		    bpf_probe_read_user(&previous, sizeof(previous),
					frame + PY_BPF_FRAME_PREVIOUS))
			return -EFAULT;

		code = (void *)(executable & ~(__u64)PY_BPF_STACKREF_REFCNT_MASK);
		if (!code)
			return -EFAULT;

		/* For optional long display, add "filename:" */
		if (args->flags & BPF_STACK_FLAGS_LONG) {
			void *filename;

			if (bpf_probe_read_user(&filename, sizeof(filename),
						code + PY_BPF_CODE_FILENAME))
				return -EFAULT;

			err = append_unicode(args, filename);
			if (!err)
				err = append_char(args, ':');
		}
		if (!err) {
			if (bpf_probe_read_user(&qualname, sizeof(qualname),
						code + PY_BPF_CODE_QUALNAME))
				return -EFAULT;
			err = append_unicode(args, qualname);
		}
		if (!err)
			err = append_char(args, args->str_sep);
		str[args->str_len] = '\0';
		if (err)
			return err == -ENOSPC ? 0 : err;
		frame = previous;
	}
	return 0;
}

char py_stack_license[] SEC("license") = "GPL";
