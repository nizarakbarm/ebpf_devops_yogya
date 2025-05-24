#!/usr/bin/python3  
from bcc import BPF
import ctypes as ct

program = r"""
#include <uapi/linux/ptrace.h>
#define ARGSIZE 256

BPF_PROG_ARRAY(syscall, 500);

int hello(struct bpf_raw_tracepoint_args *ctx) {
    int id = ctx->args[1];
    int arg0_number = ctx->args[0];

    if (id != 59)
        return 0;
    
    //struct pt_regs *regs = (struct pt_regs *)PT_REGS_PARAM1_CORE_READ(ctx, args[0]);

    //char *filename = (char *)PT_REGS_PARAM1_CORE(regs);
    
    //struct pt_regs *args0 = (struct pt_regs *)ctx->args[0];
    //const char *filename = (const char *)PT_REGS_PARM1(args0);

    char buf[ARGSIZE] = {};
    struct pt_regs *regs;
    bpf_probe_read(&regs, sizeof(regs), &ctx->args[0]);

    const char __user *filename;
    bpf_probe_read(&filename, sizeof(filename), &regs->di);
    
    //bpf_core_read_user_str(buf, sizeof(buf), filename);
    bpf_probe_read_user_str(buf, sizeof(buf), filename);

    syscall.call(ctx, id);
    bpf_trace_printk("Another syscall: %d with argument zero in number %d string %s\n", id, arg0_number, buf);
    return 0;
}
"""

b = BPF(text=program)
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

prog_array = b.get_table("syscall")

b.trace_print()
