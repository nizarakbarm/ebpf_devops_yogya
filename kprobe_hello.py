#!/usr/bin/python3
from bcc import BPF

program=r"""
#include <uapi/linux/ptrace.h>

int hello_kprobe(void *ctx) {
    bpf_trace_printk("Hello world kprobe!");
    return 0;
}
int hello_kretprobe(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
        
    if (ret !=0 ) {
        bpf_trace_printk("Hello world kretprobe return %d\\n", ret);
        return 0;
    }
    
    bpf_trace_printk("Hello world kretprobe return 0\\n");
    return 0;
}
"""

b = BPF(text=program)

# get syscall
syscall_execve = b.get_syscall_fnname("execve")

# attach kprobe to execve syscall
b.attach_kprobe(event=syscall_execve, fn_name="hello_kprobe")

# attach kretprobe to execve syscall
b.attach_kprobe(event=syscall_execve, fn_name="hello_kretprobe")

# continually reads the globally shared /sys/kernel/debug/tracing/trace_pipe file and prints its contents
# This file can be written to via BPF and the bpf_trace_printk() function
# has limitations: lack of concurrent tracing support
# preferred BPF_PERF_OUTPUT
b.trace_print()