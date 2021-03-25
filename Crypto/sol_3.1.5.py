#!/usr/bin/env python3

import sys

_, ct_filename, d_filename, n_filename, out_filename = sys.argv
with open(ct_filename) as ct_file, open(d_filename) as d_file, open(n_filename) as n_file:
    ct = ct_file.read().strip()
    d = d_file.read().strip()
    n = n_file.read().strip()

ct = int(ct, 16)
d = int(d, 16)
n = int(n, 16)

m = ct ** d % n
m = hex(m)[2:]

with open(out_filename, 'w') as out_file:
    out_file.write(m)
