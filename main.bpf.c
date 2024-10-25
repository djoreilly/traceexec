// +build ignore
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define FILENAME_LEN 512
#define TASK_COMM_LEN 16  // sched.h
#define ARGV_LEN 4096     // limits.h has ARG_MAX 128KB that also includes environ

struct event_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[FILENAME_LEN];
    u32 argv_size;
    char argv[ARGV_LEN];
};

// BPF ringbuf map
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, int);
    __type(value, struct event_t);
} heap SEC(".maps");

SEC("tracepoint/sched/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct trace_event_raw_sched_process_exec *ctx) {
    const int zero = 0;

    struct event_t *event;
    event = bpf_map_lookup_elem(&heap, &zero);
    if (!event) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->ppid = BPF_CORE_READ(task, real_parent, tgid);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));

    void *arg_start = (void *)BPF_CORE_READ(task, mm, arg_start);
    void *arg_end = (void *)BPF_CORE_READ(task, mm, arg_end);
    unsigned long arg_sz = arg_end - arg_start;
    arg_sz = arg_sz < ARGV_LEN ? arg_sz : ARGV_LEN;
    int arg_ret = bpf_probe_read_user(&event->argv, arg_sz, arg_start);
    if (!arg_ret) {
        event->argv_size = arg_sz;
    }

    unsigned int filename_loc = BPF_CORE_READ(ctx, __data_loc_filename) & 0xFFFF;
    bpf_probe_read_kernel_str(&event->filename, sizeof(event->filename), (void *)ctx + filename_loc);

    // calculate the total bytes to send to userspace
    uint total = sizeof(*event) - ARGV_LEN + arg_sz;
    if (total > sizeof(*event))
        return 0;

    bpf_ringbuf_output(&rb, event, total, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";
