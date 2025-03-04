#ifndef __BPF_HELPERS_H__
#define __BPF_HELPERS_H__

#include <linux/bpf.h>
#include <stdint.h>

typedef uint32_t u32;
typedef uint64_t u64;

#ifndef SEC
#define SEC(NAME) __attribute__((section(NAME), used))
#endif

// Provide a complete definition for bpf_map_def.
struct bpf_map_def {
    u32 type;
    u32 key_size;
    u32 value_size;
    u32 max_entries;
    u32 flags;
};

// Inline wrappers for BPF helper functions. (These rely on clang’s __builtin_bpf_call.)
static __always_inline unsigned long bpf_get_current_pid_tgid(void)
{
    return __builtin_bpf_call(BPF_FUNC_get_current_pid_tgid);
}

static __always_inline int bpf_get_current_comm(char *buf, int buf_size)
{
    return __builtin_bpf_call(BPF_FUNC_get_current_comm, buf, buf_size);
}

static __always_inline int bpf_probe_read_user_str(char *dst, int size, const char *unsafe_ptr)
{
    return __builtin_bpf_call(BPF_FUNC_probe_read_user_str, dst, size, unsafe_ptr);
}

static __always_inline int bpf_perf_event_output(void *ctx, void *map, unsigned int flags, void *data, u
