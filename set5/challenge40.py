import binascii
import logging
import sys
import base64
import os
import struct
import random
import math
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

def encrypt_rsa():
    d = 0
    e = 3
    while d == 0:
        p = number.getPrime(128)
        q = number.getPrime(128)

        n = p * q
        et = (p - 1) * (q - 1)

        try:
            d = invmod(e, et)
        except ValueError:
            pass

    plain = int.from_bytes(b'WHIPPLE THE POWER', byteorder='big')
    return n, pow(plain, e, n)

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
        
def challenge40():
    n1, c1 = encrypt_rsa()
    n2, c2 = encrypt_rsa()
    n3, c3 = encrypt_rsa()
    print(c1)
    print(c2)
    print(c3)

    n = [n1, n2, n3]
    c = [c1, c2, c3]

    ms1 = n2 * n3
    ms2 = n1 * n3
    ms3 = n1 * n2
    N = n1 * n2 * n3
    r1 = (c1 * ms1 * invmod(ms1, n1))
    r2 = (c2 * ms2 * invmod(ms2, n2))
    r3 = (c3 * ms3 * invmod(ms3, n3))

    r = (r1 + r2 + r3) % N

    rf = floorRoot(r, 3)
    print(int_to_bytes(int(rf)))

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge40())
