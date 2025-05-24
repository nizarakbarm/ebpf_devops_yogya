#!/usr/bin/python3

program = r"""
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(output_kprobe);
BPF_PERF_OUTPUT(output_kretprobe);

struct data_t {
    int pid;
    int uid;
    char command[16];
    char message[12];
}

int hello_kprobe(void *ctx) {
    struct data_t data = {};
    char message[12] = "Hello World Kprobe";

    data.pid = bpf_get_current_pid_tgid() >> 32;
    data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    bpf_get_current_comm(&data.command, sizeof(data.command));
    bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
    
    output_kprobe.perf_submit(ctx, &data, sizeof(data));

    return 0;
}

int hello_kretprobe(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    char message[12] = "Hello World Kretprobe";

    if (ret == 0) {
        data.pid = bpf_get_current_pid_tgid() >> 32;
        data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

        output_kretprobe.perf_submit(ctx, &data, sizeof(data));

        return 0;
    }
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello_kprobe")
b.attach_kretprobe(event=syscall, fn_name="hello_kretprobe")

def print_event_kprobe(cpu, data, size):
    data = b["output_kprobe"].event(data)
    print(f"kprobe execve {data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")

def print_event_kretprobe(cpu, data, size):
    data = b["output_kretprobe"].event(data)
    print(f"kretprobe execve {data.pid} {data.uid} {data.command.decode()} {data.message.decode()}")


b["output_kprobe"].open_perf_buffer(print_event_kprobe)
b["output_kretprobe"].open_perf_buffer(print_event_kretprobe)

while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
