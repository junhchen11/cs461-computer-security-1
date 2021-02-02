.global your_asm_fn
.section .text

your_asm_fn:

push    %ebp
mov     %esp,%ebp

# Your code here
mov %esp, %ebx
push $0
push $0x646f6f66 
push $0x6c6f6f63

push %esp
push $sec
push $0xacce55ed
call practice

leave
ret

sec: .8byte 0xc105ed
