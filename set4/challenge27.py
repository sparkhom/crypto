import binascii
import logging
import sys
import base64
import os
from Crypto.Cipher import AES

def challenge27(p):
    enc = oracle(p)
    data = b'comment1=cooking%20MCs;userdata=' + b'whipple_it' + b';comment2=%20like%20a%20pound%20of%20bacon'
    l = [data[x:x+16] for x in range(0, len(data), 16)]
    print(l)
    cl = [enc[x:x+16] for x in range(0, len(data), 16)]
    print(cl)
    modified = enc[0:16] + b'\x00'*16 + enc[0:16]
    decrypted = check(modified)
    pprime1 = decrypted[0:16]
    pprime3 = decrypted[32:48]
    found_key = bytes([x ^ y for x, y in zip(pprime1, pprime3)])
    print(key)
    return found_key

def check(inp):
    c = AES.new(key, AES.MODE_CBC, iv)
    d = c.decrypt(inp)
    for c in d:
        if c > 127:
            return d

def oracle(inp):
    inp = inp.replace(b';',b'\;')
    inp = inp.replace(b'=',b'\=')
    data = b'comment1=cooking%20MCs;userdata=' + inp + b';comment2=%20like%20a%20pound%20of%20bacon'
    length = 16 - (len(data) % 16)
    data += bytes([length])*length
    return c.encrypt(data)

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    key = iv = os.urandom(16)
    c = AES.new(key, AES.MODE_CBC, iv)
    print(challenge27(b'whipple_it'))
