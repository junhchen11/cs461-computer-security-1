import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

_, in_file, key_file, iv_file, out_file = sys.argv
with open(in_file) as inf, open(key_file) as keyf, open(iv_file) as ivf, open(out_file, 'w') as outf:
    input = inf.read().strip()
    input = bytes.fromhex(input)
    key = keyf.read().strip()
    key = bytes.fromhex(key)
    iv = ivf.read().strip()
    iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(input)
    # plaintext = unpad(plaintext, AES.block_size)
    plaintext = (plaintext).decode('ascii')
    print(plaintext)
    outf.write(plaintext)
