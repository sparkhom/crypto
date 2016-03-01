import logging
import os
import math
import hashlib
import sys
import binascii
from Crypto.Util import number
from Crypto.Random import random

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

p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1

q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b

g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

g = p + 1

def get_keys():
    x = random.randint(1, q)
    y = pow(g, x, p)
    pubkey = [p, q, g, y]
    return pubkey, x

def dsa_sign(key, message):
    f = True
    while f:
        k = random.randint(1, q)
        r = pow(g, k, p) % q
        s = invmod(k, q)*(int.from_bytes(hashlib.sha1(message).digest(), byteorder='big') + key * r) % q
        f = (r == 0 or s == 0)
    return r, s, k

def dsa_verify(r, s, message, pub):
    if 0 > r or r > q:
        return False
    if 0 > s or s > q:
        return False
    w = invmod(s, q)
    u1 = (int.from_bytes(hashlib.sha1(message).digest(), byteorder='big') * w) % q
    u2 = (r * w) % q
    v = (pow(g, u1, p) * pow(pub[3], u2, p) % p) % q
    return v == r

def dsa_recover_x(k, message, r, s):
    h = int.from_bytes(hashlib.sha1(message).digest(), byteorder='big')
    x = invmod(r, q) * ((s * k) - h) % q
    return x

def dsa_recover_x_int(k, h, r, s):
    x = invmod(r, q) * ((s * k) - h) % q
    return x
 
def challenge45():
    pub, priv = get_keys()
    message = b'Hello, world'
    z = random.randint(1, q)
    r = pow(g, z, p) % q
    s = (invmod(z, q) * r) % q
    print(r)
    print(s)
    print(dsa_verify(r, s, message, pub))
    print(dsa_verify(r, s, b'adsadhasoidhoai', pub))

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge45())
