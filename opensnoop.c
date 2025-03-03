//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include "bpf_helpers.h"

// For ARM64, the standard headers often only forward-declare struct pt_regs.
// Provide a minimal definition needed for our eBPF program.
#if defined(__TARGET_ARCH_arm64)
struct pt_regs {
    unsigned long regs[31];
    unsigned long sp;
    unsigned long pc;
    unsigned long pstate;
};
#else
#include <linux/ptrace.h>
#endif

#define TASK_COMM_LEN 16
#define FILENAME_MAX 256

struct event {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[FILENAME_MAX];
};

struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 128,
    .flags = 0,
};

SEC("kprobe/sys_enter_openat")
int trace_openat(struct pt_regs *ctx) {
    struct event evt = {};
    const char *filename;

    // Force the 64-bit return value into memory using a volatile union.
    volatile union {
        u64 full;
        struct {
            u32 low;
            u32 high;
        } parts;
    } pid_val = { .full = bpf_get_current_pid_tgid() };

    // Now read the high 32 bits
    evt.pid = pid_val.parts.high;

    bpf_get_current_comm(evt.comm, sizeof(evt.comm));
    // For ARM64, the second syscall parameter is in regs[1]
    filename = (const char *)ctx->regs[1];
    bpf_probe_read_user_str(evt.filename, sizeof(evt.filename), filename);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}








char _license[] SEC("license") = "GPL";
