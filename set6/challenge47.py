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
    return i.to_bytes((i.bit_length() + 7) // 8 + 1, byteorder='big')

def get_keys():
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

    return [e, n], [d, n]

def encrypt_rsa(plain, e, n):
    plain = int.from_bytes(plain, byteorder='big')
    return pow(plain, e, n)

def decrypt_rsa(c, d, n):
    return int_to_bytes(pow(c, d, n))

def rsa_oracle(c, d, n):
    p = decrypt_rsa(c, d, n)
    return p[0] == 0 and p[1] == 2

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

def randnonzerobytes(k):
    return bytes(random.sample(range(1, 256), k))

def ceildiv(a, b):
    return -(-a // b)
        
def challenge47():
    pub, priv = get_keys()
    (e, n) = pub
    m = b'whipple it'
    padded = b'\x00\x02' + randnonzerobytes(19) + b'\x00' + m
    enc = encrypt_rsa(padded, pub[0], pub[1])
    print(decrypt_rsa(enc, priv[0], priv[1]))
    # start search
    k = (n.bit_length() + 7) // 8
    B = 2**(8*(k-2))
    s = (n + 3*B - 1) // (3 * B)
    a = 2*B
    b = 3*B - 1
    # compute first s
    while True:
        c = (enc * pow(s, e, n)) % n
        if rsa_oracle(c, priv[0], priv[1]):
            break
        s += 1
    # found first s, narrow ranges (step 3)
    while a != b:
        # get next interval
        ra = (a * s - 3 * B + 1 + n - 1) // n
        rb = (b * s - 2 * B) // n
        if ra > rb:
            print(ra)
            print(rb)
            raise Exception('unexpected R')
        r = ra
        a = max(a, (2*B + r*n + s - 1) // s)
        b = min(b, (3*B - 1 + r*n) // s)
        if a > b:
            print(a)
            print(b)
            raise Exception('unexpected')

        r = (2 * (b * s - 2 * B) + n - 1) // n
        r = ceildiv(2 * (b * s - 2 * B), n)
        while True:
            reallybreak = False
            sa = (2*B + r*n + b - 1) // b
            sb = (3*B + r*n + a - 1) // a
            for s in range(sa, sb):
                c = (enc * pow(s, e, n)) % n
                if rsa_oracle(c, priv[0], priv[1]):
                    reallybreak = True
                    break
            if reallybreak:
                break
            r += 1
        print(int_to_bytes(a))

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge47())
