import pbp
import numpy as np
import itertools
import os
from multiprocessing import Pool

lines = open('moduli.hex').readlines()
lines = list(map(lambda x: int(x, 16), lines))
N = lines
try:
    loaded = np.load('3.2.4_cached.npz', allow_pickle=True)
    P, Z = loaded['P'], loaded['Z']
    print('Cached:')
    print(f'{P.shape=}')
    print(f'{Z.shape=}')
    # for i in reversed(range(len(N))):
        # assert(Z[i] == np.mod(P, N[i]**2))
except Exception as e:
    print(f'unable to load cache: {e}')
    P = np.array(lines)
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

    np.savez_compressed('./3.2.4_cached', P=P, Z=Z)


gcds = np.gcd(N, Z/N)
print(f'{gcds.shape=}')

for i in reversed(range(len(N))):
    assert(np.gcd(N[i],gcds[i])==gcds[i])
gcds = list(filter(lambda x: x != 0, gcds))
print(len(gcds))
