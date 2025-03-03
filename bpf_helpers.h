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

/* Inline assembly fallback for BPF helper calls.
 * The BPF calling convention passes arguments in registers r1-r5 and returns the result in r0.
 * These wrappers generate a call to the BPF helper using inline assembly.
 */

static __always_inline unsigned long bpf_get_current_pid_tgid(void)
{
    unsigned long ret;
    asm volatile ("call %1"
                  : "=r"(ret)
                  : "i"(BPF_FUNC_get_current_pid_tgid)
                  : "r0", "r1", "r2", "r3", "r4", "r5", "memory");
    return ret;
}

static __always_inline int bpf_get_current_comm(char *buf, int buf_size)
{
    int ret;
    register void *r1 asm("r1") = buf;
    register int r2 asm("r2") = buf_size;
    asm volatile ("call %1"
                  : "=r"(ret)
                  : "i"(BPF_FUNC_get_current_comm), "r"(r1), "r"(r2)
                  : "r0", "r3", "r4", "r5", "memory");
    return ret;
}

static __always_inline int bpf_probe_read_user_str(char *dst, int size, const char *unsafe_ptr)
{
    int ret;
    register void *r1 asm("r1") = dst;
    register int r2 asm("r2") = size;
    register const char *r3 asm("r3") = unsafe_ptr;
    asm volatile ("call %1"
                  : "=r"(ret)
                  : "i"(BPF_FUNC_probe_read_user_str), "r"(r1), "r"(r2), "r"(r3)
                  : "r0", "r4", "r5", "memory");
    return ret;
}

static __always_inline int bpf_perf_event_output(void *ctx, void *map, unsigned int flags, void *data, unsigned int size)
{
    int ret;
    register void *r1 asm("r1") = ctx;
    register void *r2 asm("r2") = map;
    register unsigned int r3 asm("r3") = flags;
    register void *r4 asm("r4") = data;
    register unsigned int r5 asm("r5") = size;
    asm volatile ("call %1"
                  : "=r"(ret)
                  : "i"(BPF_FUNC_perf_event_output), "r"(r1), "r"(r2), "r"(r3), "r"(r4), "r"(r5)
                  : "r0", "memory");
    return ret;
}

#endif /* __BPF_HELPERS_H__ */
