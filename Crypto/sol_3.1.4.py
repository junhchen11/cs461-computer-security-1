import sys
from Crypto.Cipher import AES

in_file = sys.argv[1]
with open(in_file) as inf:
    input = inf.read().strip()
input = bytes.fromhex(input)
iv = b'\0' * 16
key = b'\0' * 31
for candidate_int in range(32):
    candidate_byte = candidate_int.to_bytes(1, 'big')
    candidate_key = key + candidate_byte
    print(candidate_key)
    cipher = AES.new(candidate_key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(input)
    print(plaintext)
