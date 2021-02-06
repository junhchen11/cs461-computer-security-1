my_str = '/bin////bash'

# my_str= my_str+(4 - len(my_str)%4)*'/'

tp= ''

for i in range(len(my_str)//4):
    sub = my_str[i*4:(i+1)*4]
    print(sub)
    top = '0x'
    for i in range(4):
        top+=format(ord(sub[-1-i]), "x")
    tp = f'push ${top}\n' + tp
print(tp)
