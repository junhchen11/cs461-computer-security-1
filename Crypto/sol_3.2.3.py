#!/usr/bin/env python3

import urllib.request, urllib.error
import sys

def get_status(u):
    try:
        resp = urllib.request.urlopen(u)
        return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return True
        else:
            return False

def split_blocks(data, bs=16):
    return [data[i : i + bs] for i in range(0, len(data), bs)]

def bytes_xor(s1, s2):
    return bytearray([b1 ^ b2 for b1, b2 in zip(s1, s2)])

def find_block(blocks, url):
    plaintext = bytearray(b'\0' * 16)
    for byte_index in range(16):
        expected_padding = bytearray([0 for _ in range(16 - byte_index)] + [15 - j for j in range(byte_index)])
        c_prime = bytes_xor(blocks[-2], plaintext)
        c_prime = bytes_xor(c_prime, expected_padding)
        found = False
        for byte in list(range(blocks[-2][-1] + 1, 256)) + list(range(blocks[-2][-1] + 1)):
            c_prime[15 - byte_index] = byte
            trial = c_prime + blocks[-1]
            trial = trial.hex()
            if get_status(url + trial):
                plaintext[15 - byte_index] = byte ^ 16 ^ blocks[-2][15 - byte_index]
                found = True
                break
        print(plaintext)
        if not found:
            exit(1)
    return plaintext

def find_plaintext(ciphertext, url):
    plaintext = bytearray(b'\0' * len(ciphertext))
    blocks = split_blocks(ciphertext)
    plaintext = b''
    for block_index in range(len(blocks) - 2, -1, -1):
        plaintext = find_block(blocks[block_index : block_index + 2], url) + plaintext
    return plaintext


if len(sys.argv) < 3:
    print("Usage: {} ciphertext server_url".format(sys.argv[0]))
    exit(1)

ct_filename = sys.argv[1]
server_url = sys.argv[2]

with open(ct_filename) as ct_file:
    ciphertext = ct_file.read().strip()

ciphertext = bytes.fromhex(ciphertext)
plaintext = find_plaintext(ciphertext, server_url)
plaintext = bytes(plaintext)
print(plaintext)
