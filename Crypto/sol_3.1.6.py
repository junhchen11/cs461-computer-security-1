#!/usr/bin/env python3

import sys

def wha(inp):
    mask = 0x3fffffff
    outHash = 0
    for b in inp:
        tmp = ((b ^ 0xcc) << 24) | ((b ^ 0x33) << 16) | ((b ^ 0xaa) << 8) | (b ^ 0x55)
        outHash = (outHash & mask) + (tmp & mask)
    return outHash

_, in_filename, out_filename = sys.argv
with open(in_filename, 'rb') as infile:
    inp = infile.read()

outHash = wha(inp)
with open(out_filename, 'w') as outfile:
    outfile.write(hex(outHash)[2:])
