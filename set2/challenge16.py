import binascii
import logging
import sys
import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import random

def challenge15(p):
    enc = oracle(p)
    data = b'comment1=cooking%20MCs;userdata=' + b'\;admi\=true\;' + b';comment2=%20like%20a%20pound%20of%20bacon'
    l = [data[x:x+16] for x in range(0, len(data), 16)]
    print(l)
    enc = bytearray(enc)
    enc[44] = enc[44] ^ ord(b'\\') ^ ord(b';')
    enc[38] = enc[38] ^ ord(b'\\') ^ ord(b'n')
    enc = bytes(enc)
    return check(enc)

def check(inp):
    c = AES.new(key, AES.MODE_CBC, iv)
    d = c.decrypt(inp[16:])
    print(d)
    return d.find(b';admin=true;') != -1

def oracle(inp):
    inp = inp.replace(b';',b'\;')
    inp = inp.replace(b'=',b'\=')
    data = b'comment1=cooking%20MCs;userdata=' + inp + b';comment2=%20like%20a%20pound%20of%20bacon'
    length = 16 - (len(data) % 16)
    data += bytes([length])*length
    return iv + c.encrypt(data)

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    rf = Random.new()
    key = rf.read(16)
    iv = rf.read(16)
    c = AES.new(key, AES.MODE_CBC, iv)
    print(challenge15(b';admi=true;'))
