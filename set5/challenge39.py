import binascii
import logging
import sys
import base64
import os
import struct
import random
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

def challenge39():
    p = 272351428677984184282405353551156620163
    q = 220213159460115106331707006455692690339

    n = p * q

    et = (p - 1) * (q - 1)

    e = 3

    d = invmod(e, et)
    public = [e, n]
    private = [d, n]

    i = input('Text to encrypt> ')
    plain = int.from_bytes(i.encode('utf-8'), byteorder='big')

    c = pow(plain, e, n)
    m = pow(c, d, n)

    print(int_to_bytes(c))
    print(int_to_bytes(m))

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge39())
