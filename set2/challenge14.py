import binascii
import logging
import sys
import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import random

def challenge14():
    initial = getaligned(b'')
    decrypted = bytearray()
    block_size = 16
    for i in range(0, len(initial), block_size):
        for j in reversed(range(0,16)):
            unknown = bytearray(b'A'*j)
            test = getaligned(bytes(unknown))[i:i+16]
            for k in range(0, 256):
                arr = getaligned(bytes(unknown + decrypted + bytes([k])))[i:i+16]
                if (arr == test):
                    decrypted.append(k)
                    break
    return decrypted

def getaligned(inp):
    while True:
        b = oracle(b'*'*16 + bytes(inp))
        if b[16:32] == b'\xb3\xf4\\yL\xb7\xb4\xff[\xaa>\x92\xcb)\xb3\x98':
            return b[32:]

def oracle(inp):
    key = b'\x8b4\x80#\xc5\x1c\x95i\xeb\x9d\xeb\xd0\t\xec\x0fj'
    plaintextappend = base64.b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
    rf = Random.new()
    randombytes = rf.read(random.randint(1,16))
    c = AES.new(key)
    data = randombytes + inp + plaintextappend
    length = 16 - (len(data) % 16)
    data += bytes([length])*length
    return c.encrypt(data)

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge14())
