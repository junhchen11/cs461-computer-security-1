from Crypto.PublicKey import RSA
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

gcds = np.gcd(N, Z//N)
assert(0==N[0]%gcds[0])

for i in reversed(range(len(N))):
    assert(np.gcd(N[i], gcds[i]) == gcds[i])

enc = open('3.2.4_ciphertext.enc.asc').read()

# cite: https://crypto.stackexchange.com/questions/19444/rsa-given-q-p-and-e
def invmod(a, m):
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m

    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (
            u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m

for i in range(len(N)):
    if(gcds[i]==1):continue
    n = (N[i])
    p = (gcds[i])
    q = (n//p)
    e = 65537
    taut = (p-1)*(q-1)
    d = (invmod(int(e), int(taut)))
    '''
    print(f'{n=}')
    print(f'{p=}')
    print(f'{q=}')
    print(f'{taut=}')
    assert(np.gcd(n,p) == p)
    assert(np.gcd(n,q) == q)
    assert(n==p*q)
    assert(is_prime(p))
    assert(is_prime(q))
    print(f'{d=}')
    '''
    assert(np.mod(d*e, taut) == 1)
    key = RSA.construct((n, e, d))
    try:
        dec = pbp.decrypt(key, enc)
        print(dec)
    except: pass
