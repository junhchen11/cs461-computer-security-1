import sys

_, in_file, key_file, out_file = sys.argv
with open(in_file) as inf, open(key_file) as keyf, open(out_file,'w') as outf:
    input = inf.read().strip()
    key = keyf.read().strip()
    output = ''.join(list(map(lambda x:chr(key.index(x)+ord('A')) if str.isalpha(x) else x,input)))
    outf.write(output)
