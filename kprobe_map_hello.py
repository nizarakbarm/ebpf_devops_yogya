#!/usr/bin/python3
from bcc import BPF
from time import sleep

program = r"""
#include <uapi/linux/ptrace.h>

BPF_HASH(counter_table_kprobe);
BPF_HASH(counter_table_kretprobe);

int hello_kprobe(void *ctx) {
    u64 uid;
    u64 counter = 0;
    u64 *p;

    uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    p = counter_table_kprobe.lookup(&uid);
    if ( p != 0) {
        counter = *p;
    }
    counter++;
    counter_table_kprobe.update(&uid, &counter);
    return 0;
}
int hello_kretprobe(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);

    u64 uid;
    u64 counter = 0;
    u64 *p;

    if (ret == 0) {
        uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
        p = counter_table_kretprobe.lookup(&uid);
        if ( p != 0) {
            counter = *p;
        }
        counter++;
        counter_table_kretprobe.update(&uid, &counter);
        return 0;
    }
    return 0;
}
"""

b = BPF(text=program)

syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello_kprobe")
b.attach_kretprobe(event=syscall, fn_name="hello_kretprobe")

while True:
    sleep(2)
    s_k = ""
    for k,v in b["counter_table_kprobe"].items():
        s_k += f"kprobe execve: ID {k.value}: {v.value}\t"
    print(s_k)

    s_kr = ""
    for k,v in b["counter_table_kretprobe"].items():
        s_kr += f"kretprobe execve: ID {k.value}: {v.value}\t"
    print(s_kr)