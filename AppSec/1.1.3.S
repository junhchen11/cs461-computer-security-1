.global your_asm_fn
.section .text

your_asm_fn:

push    %ebp
mov     %esp,%ebp

# Your code here
;push $0xc001f00d
push $mp
push $0xc105ed
push $0xacce55ed
call practice


leave
ret

mp: .8byte 0xc001f00d
