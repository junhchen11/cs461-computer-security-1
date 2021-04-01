import pbp
import numpy as np
import itertools,os
from multiprocessing import Pool

lines = open('moduli.hex').readlines()
lines = list(map(lambda x: int(x, 16), lines))
N = lines
P = np.array(lines)

'''
def product_and_remainder(arr):
    if len(arr) % 2:
        extra = arr[-1]
        arr = arr[:-1]
    arr = arr.reshape([-1, 2])
    product1, to_remain1 = product_and_remainder(arr[:,0]) 
    product2, to_remain2 = product_and_remainder(arr[:,1]) 
'''

product_tree = [P.copy()]
while np.prod(P.shape) > 1:
    if len(P) % 2:
        extra = P[-1]
        P = P[:-1]
    else:
        extra = None
    P = P.reshape([-1, 2])
    P = np.prod(P, axis=1)
    if extra is not None:
        P = np.append(P, extra)
    product_tree.append(P.copy())
    print(P.shape)
print('P found')

'''
gcds = []
for i, n in enumerate(N):
    gcd = np.gcd((P % (n**2))/n, n)
    gcds.append(gcd)
    print(gcd)
    print(f'{12*i/len(N)}')
'''

Z = P.copy()
for layer in reversed(product_tree):
    print(f'{Z.shape=}')
    print(f'{layer.shape=}')
    layer = layer**2
    if len(layer) % 2:
        extra = layer[-1]
        extraZ = Z[-1]
        layer = layer[:-1]
        Z = Z[:-1]
    else:
        extra = None
        extraZ = None
    Z = np.repeat(Z, 2)
    Z = np.mod(Z, layer)
    if extraZ is not None:
        Z = np.append(Z, extraZ % extra)

print('All Z calculated')

final = np.gcd(N, Z/N)
