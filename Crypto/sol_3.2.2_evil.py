#!/usr/bin/env python3
# -*- coding: latin-1 -*-
blob = """

   _�;ۮspE
��t2%�`bg�����0�������8���ᒱ;�I_us_-�ʢ�OeO��K����Mǝt��Zk�ӕtZ��K� :`���;0��/4
S|��س��%�:����>H��
"""

from hashlib import sha256
dig = sha256(blob.encode()).hexdigest()
if int(ord(dig[0]))%2: print("I come in peace.")
else: print("Prepare to be destroyed!")
