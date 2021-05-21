#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# Enciphering with AES-128

from Cryptodome.Cipher import AES 
from binascii import hexlify, unhexlify

# Define the cipher
def Encipher(plaintext, key):
    assert(type(plaintext) == bytes)
    temp = AES.new(bytes.fromhex(key), AES.MODE_ECB)
    ct = temp.encrypt(plaintext)
    return hexlify(ct)

# An example Encipher call
def exampleCall():
    print(Encipher(b'hello worldworld', b"sixteen byte key".hex()) == b'212fb79e1569d9585a78dd4b76a9af35')
    print(Encipher(b'hellohello world', b"sixteen byte key".hex()) == b'146a31238a8a448ffe4c7db3e3767cab')

three_letter_words = ['all', 'and', 'any', 'but', 'can', 'day', 'for', 'get', 'her', 'him', 'his', 'how', 'its', 'new', 'not', 'now', 'one', 'our', 'out', 'say', 'see', 'she', 'the', 'two', 'use', 'way', 'who', 'you']

words = """a about after all also an and any as at back be because but by can
    come could day do even first for from get give go good have he her him his how
    i if in into it its just know like look make me most my new no not now of on
    one only or other our out over people say see she so some take than that the
    their them then there these they think this time to two up us use want way we
    well what when which who will with work would year you your""".split()
