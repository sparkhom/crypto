import binascii
import logging
import sys
import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import random

# Implement CTR mode

#key=YELLOW SUBMARINE
#nonce=0
#format=64 bit unsigned little endian nonce,
     #64 bit little endian block count (byte count / 16)

key = "YELLOW SUBMARINE"
nonce = 0

def challenge18():
    return decrypt(base64.b64decode(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='))

def decrypt(inp):
    c = AES.new(key, AES.MODE_ECB)
    blocks = len(inp) // 16
    decrypted = bytearray() 
    # Should probably do the check code better
    for b in range(0, blocks + 1):
        print('Block: {0}, Stream: {1}'.format(b, b'\x00'*8 + bytes([b]) + b'\x00'*7))
        stream = c.encrypt(b'\x00'*8 + bytes([b]) + b'\x00'*7)
        decrypted += bytes([x ^ y for x, y in zip(stream, inp[b*16:(b+1)*16])])
    return decrypted


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge18())
