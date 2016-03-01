import binascii
import logging
import sys
import base64
import os
import array
from Crypto.Cipher import AES

key = os.urandom(16)
iv = os.urandom(16)

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

def challenge25():

    with open("challenge25.txt", "r") as myfile:
        data = myfile.read().replace('\n', '')

    data = base64.b64decode(data)
    aes = AES.new("YELLOW SUBMARINE", AES.MODE_ECB)
    data = aes.decrypt(data)

    ctr = Secret()
    aes_ctr = AES.new(key, AES.MODE_CTR, counter=ctr.counter)


    # XOR against nulls reveals the key
    a = edit(b'A'*16, key, b'\x00'*16, b'\x00'*16)
    b = edit(b'A'*16, key, b'\x00'*16, b'B'*16)

    key_found = xor_strings(a, b'\x00'*16)

    print(key)
    print(key_found)

    return aes_ctr.encrypt(data)

def xor_strings(xs, ys):
    return bytes([x ^ y for x, y in zip(xs, ys)])

def edit(ciphertext, key, offset, newtext):
    ctr = Secret()
    ctr.set(offset)
    aes_ctr = AES.new(key, AES.MODE_CTR, counter=ctr.counter)

    return aes_ctr.encrypt(newtext)

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge25())

