#!/usr/bin/python
from bcc import BPF
program = """
int hello(void *ctx) {
    bpf_trace_printk("Hello World!\\n"); 
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
b.trace_print()
print("1234-final")

