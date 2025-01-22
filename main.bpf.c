// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define NAME_MAX 255   // limits.h
#define PATH_MAX 4096  // limits.h
#define CWD_MAX 4096
#define MAX_PATH_COMPONENTS 16
#define TASK_COMM_LEN 16  // sched.h
#define ARGV_LEN 4096     // limits.h has ARG_MAX 128KB which also includes environ
#define BUF_MAX (ARGV_LEN + PATH_MAX + CWD_MAX)

struct event_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    u32 path_size;
    u32 argv_size;
    u32 cwd_size;
    u8 buf[BUF_MAX];  // argv followed by path followed by cwd
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

// Append dentry name to buf at buf_off
static __always_inline int
process_dentry(u8 *buf, int buf_off, struct dentry *dentry) {
    struct qstr d_name = BPF_CORE_READ(dentry, d_name);
    uint len = d_name.len;

    if (len > NAME_MAX)
        return -1;
    // also read the trailing \0
    int sz = bpf_probe_read_kernel_str(&buf[buf_off], len + 1, (void *)d_name.name);
    if (sz < 0)
        return -1;

    buf_off += len + 1;
    return buf_off;
}

// Walk path up to / appending each component to buf.
// The components will be in reverse order, e.g. dir2\0dir1\0mnt\0
// Reversing and replacing the \0s with slashes will be done in userspace.
static __always_inline u32
get_path_str(struct path *path, u8 *buf) {
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    struct vfsmount *vfsmnt = BPF_CORE_READ(path, mnt);
    struct dentry *mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);
    struct mount *mnt_p = container_of(vfsmnt, struct mount, mnt);
    struct mount *mnt_parent_p = BPF_CORE_READ(mnt_p, mnt_parent);
    int buf_off = 0;

#pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {
        struct dentry *d_parent = BPF_CORE_READ(dentry, d_parent);

        if (dentry == mnt_root || dentry == d_parent) {
            if (dentry != mnt_root) {
                // We reached root, but not mount root - escaped?
                break;
            }
            if (mnt_p != mnt_parent_p) {
                // We reached root, but not global root - continue with mount point path
                dentry = BPF_CORE_READ(mnt_p, mnt_mountpoint);
                mnt_p = BPF_CORE_READ(mnt_p, mnt_parent);
                mnt_parent_p = BPF_CORE_READ(mnt_p, mnt_parent);
                vfsmnt = &mnt_p->mnt;
                mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);
                continue;
            }
            // Global root - path fully parsed
            break;
        }

        buf_off = process_dentry(buf, buf_off, dentry);
        if (buf_off < 0)
            break;

        dentry = d_parent;
    }

    return buf_off;
}

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
    int arg_ret = bpf_probe_read_user(&event->buf, arg_sz, arg_start);
    if (!arg_ret) {
        event->argv_size = arg_sz;
    }

    unsigned int filename_loc = BPF_CORE_READ(ctx, __data_loc_filename) & 0xFFFF;
    int file_sz = bpf_probe_read_kernel_str(&event->buf[arg_sz], PATH_MAX, (void *)ctx + filename_loc);
    if (file_sz < 0) {
        return 0;
    }
    event->path_size = file_sz;

    // find the cwd path components and append to buf
    struct fs_struct *fsp = BPF_CORE_READ(task, fs);
    struct path *p = __builtin_preserve_access_index(&fsp->pwd);
    uint cwd_start = arg_sz + file_sz;
    if (cwd_start > ARGV_LEN + PATH_MAX)
        return 0;
    int cwd_sz = get_path_str(p, &event->buf[cwd_start]);
    if (cwd_sz < 0)
        return 0;
    event->cwd_size = cwd_sz;

    // calculate the total bytes to send to userspace
    uint total = sizeof(*event) + arg_sz + file_sz + cwd_sz - (BUF_MAX);
    if (total > sizeof(*event))
        return 0;

    bpf_ringbuf_output(&rb, event, total, 0);

    return 0;
}

char _license[] SEC("license") = "GPL";
