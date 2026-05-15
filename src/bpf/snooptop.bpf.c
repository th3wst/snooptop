#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "../core/process_event.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); //256 KB
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter* ctx) {
    struct process_event_t *e;
    
    //reserve memory in the ring buffer directly
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0; //drop event if system is overwhelmed

    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);
    
    e->ts_ns = bpf_ktime_get_ns();
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    //read user-space arguments
    const char **args = (const char **)(ctx->args[1]);
    const char *argp;
    
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        bpf_probe_read_user(&argp, sizeof(argp), &args[i]);
        if (!argp) break;
        bpf_probe_read_user_str(&e->args[i], ARGSIZE, argp);
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
