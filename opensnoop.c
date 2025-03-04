//go:build ignore
// +build ignore

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include "bpf_helpers.h"

#define TASK_COMM_LEN 16
#define FILENAME_MAX 256

struct event {
    u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[FILENAME_MAX];
};

struct bpf_map_def SEC("maps") events = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(u32),
    .max_entries = 128,
    .flags = 0,
};

SEC("kprobe/sys_enter_openat")
int trace_openat(struct pt_regs *ctx) {
    struct event evt = {};
    const char *filename;

    // Use the lower 32 bits as a workaround (ARM64 verifier complains on shifting)
    evt.pid = (u32)bpf_get_current_pid_tgid();

    bpf_get_current_comm(evt.comm, sizeof(evt.comm));

    // On ARM64, syscall parameters are in the regs[] array; the second parameter is in regs[1]
    filename = (const char *)ctx->regs[1];
    bpf_probe_read_user_str(evt.filename, sizeof(evt.filename), filename);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &evt, sizeof(evt));
    return 0;
}

char _license[] SEC("license") = "GPL";
