#!/usr/bin/python
from bcc import BPF

program = """
BPF_PERF_OUTPUT(sugar);
struct data_t {
    u32 pid;
    char command[16];
    char message[12];
};
int hello(void *ctx) {
    struct data_t data = {};
    char message[12] = "Hello World";
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.command, sizeof(data.command));
    bpf_probe_read_kernel(&data.message, sizeof(data.message), message);
    sugar.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""
print("1234")

b = BPF(text=program)

print("1234")

syscall = b.get_syscall_fnname("execve")

print("1234")

b.attach_kprobe(event=syscall, fn_name="hello")

print("1234")

def print_event(cpu, data, size):
    data = b["sugar"].event(data)
    print("{0} {1} {2}".format(data.pid, data.command.decode(), data.message.decode()))

print("1234")

b["sugar"].open_perf_buffer(print_event)

while True:
    b.perf_buffer_poll()

