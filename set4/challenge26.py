import binascii
import logging
import sys
import base64
import os
import array
from Crypto.Cipher import AES

key = os.urandom(16)

class Secret:
    def __init__(self, secret=None):
        self.secret = b'\x00'*16
        self.reset()
    def counter(self):
        for i, c in enumerate(self.current):
            self.current[i] = c + 1
            if self.current: break
        return self.current.tostring()
    def set(self, offset):
        self.current = array.array('B', offset)
    def reset(self):
        self.current = array.array('B', self.secret)

def challenge26(p):
    enc = oracle(p)
    data = b'comment1=cooking%20MCs;userdata=' + b'\\;admi\\=true' + b';comment2=%20like%20a%20pound%20of%20bacon'
    l = [data[x:x+16] for x in range(0, len(data), 16)]
    orig_str = b'\\;admi\\=true;com'
    target_str = b' ;admin=true;com'
    xored = bytes([x ^ y for x, y in zip(orig_str, target_str)])
    print(l)
    enc = bytearray(enc)
    encpart = enc[32:48]
    xored_encpart = bytes([x ^ y for x, y in zip(encpart, xored)])
    enc[32:48] = xored_encpart
    enc = bytes(enc)
    return check(enc)

def check(inp):
    s = Secret()
    c = AES.new(key, AES.MODE_CTR, counter=s.counter)
    d = c.decrypt(inp)
    print(d)
    return d.find(b';admin=true;') != -1

def oracle(inp):
    s = Secret()
    c = AES.new(key, AES.MODE_CTR, counter=s.counter)
    inp = inp.replace(b';',b'\;')
    inp = inp.replace(b'=',b'\=')
    data = b'comment1=cooking%20MCs;userdata=' + inp + b';comment2=%20like%20a%20pound%20of%20bacon'
    length = 16 - (len(data) % 16)
    data += bytes([length])*length
    return c.encrypt(data)

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge26(b';admi=true'))

