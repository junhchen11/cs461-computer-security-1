.global _main
.section .text

_main:

push    %ebp
mov     %esp,%ebp

# Your code here
# exec_ve
mov $11, %eax
mov $filename, %ebx
push $0
mov %esp, %edx
push $filename
mov %esp, %ecx
int $0x80

leave
ret

filename: .string "/bin/sh"
