import binascii
import logging
import sys
import base64
import os
import struct
import random
import math
import hashlib
from Crypto.Util import number

def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient * x, x
        y, lasty = lasty - quotient * y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

def invmod(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return x % m

def int_to_bytes(i):
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='big')

def get_keys():
    d = 0
    e = 3
    while d == 0:
        p = number.getPrime(1024)
        q = number.getPrime(1024)

        n = p * q
        et = (p - 1) * (q - 1)

        try:
            d = invmod(e, et)
        except ValueError:
            pass

    return [e, n], [d, n]

def encrypt_rsa(plain, e, n):
    plain = int.from_bytes(plain, byteorder='big')
    return pow(plain, e, n)

def decrypt_rsa(c, d, n):
    return int_to_bytes(pow(c, d, n))

def floorRoot(n, s):
    b = n.bit_length()
    p = math.ceil(b/s)
    x = 2**p
    while x > 1:
        y = (((s - 1) * x) + (n // (x**(s-1)))) // s
        if y >= x:
            return x
        x = y
    return 1
        
def challenge42():
    pub, priv = get_keys()
    to_sign = b'hi mom'
    signature = hashlib.sha1(to_sign).digest()
    print(signature)
    padding = b'\x00\x01\xff\x00' + signature

    s = encrypt_rsa(padding, priv[0], priv[1])
    p = decrypt_rsa(s, pub[0], pub[1])
    print(p)
    
    padding = padding + b'\x00'*64
    padint = int.from_bytes(padding, byteorder='big')
    forged = floorRoot(padint, 3) + 1

    p = decrypt_rsa(forged, pub[0], pub[1])
    print(p)

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge42())
