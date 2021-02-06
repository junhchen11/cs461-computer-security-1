gcc -m32 -static -nostartfiles -Wl,--section-start=.text=0xfffecef8 1.2.11_helper.S -o 1.2.11_helper.o
objcopy -j .text -O binary 1.2.11_helper.o 1.2.11_helper
python3 -c 'print(repr(open("1.2.11_helper", "rb").read()),end=None)'

hd 1.2.11_helper | grep ' 00 '
