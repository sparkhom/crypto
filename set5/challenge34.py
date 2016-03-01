import binascii
import logging
import sys
import base64
import os
import struct
import random
import hashlib
from Crypto.Cipher import AES

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = p - 1

def challenge34():
    a_or_b = sys.argv[1]
    if a_or_b == 'A':
        a()
    elif a_or_b == 'B':
        b()
    elif a_or_b == 'M':
        m()

def a():
    a = int.from_bytes(os.urandom(128), byteorder='big')
    A = pow(g, a, p)
    print('(A) p: {0}'.format(int_to_b64(p)))
    print('(A) g: {0}'.format(int_to_b64(g)))
    print('(A) A: {0}'.format(int_to_b64(A)))
    B = b64_to_int(input('(A) B> '))

    s = pow(B, a, p)
    print(s)

    iv = os.urandom(16)
    print('(A) iv: {0}'.format(base64.b64encode(iv)))
    key = int_to_bytes(s)[0:16]
    aes = AES.new(key, AES.MODE_CBC, iv)
    m = aes.encrypt('YELLOW SUBMARINE') + iv
    print('(A) m: {0}'.format(base64.b64encode(m)))

def b():
    b = int.from_bytes(os.urandom(128), byteorder='big')
    p = b64_to_int(input('(B) p> '))
    g = b64_to_int(input('(B) g> '))
    A = b64_to_int(input('(B) A> '))
    B = pow(g, b, p)
    print('(B) B: {0}'.format(int_to_b64(B)))

    s = pow(A, b, p)
    key = int_to_bytes(s)[0:16]
    a_m = base64.b64decode(input('(B) m> '))
    iv = a_m[-16:]
    print('(B) iv: {0}'.format(base64.b64encode(iv)))
    a_m = a_m[:-16]

    aes = AES.new(key, AES.MODE_CBC, iv)
    m = aes.decrypt(a_m)
    aes = AES.new(key, AES.MODE_CBC, iv)
    enc_m = aes.encrypt(m) + iv
    print('(B) m: {0}'.format(base64.b64encode(enc_m)))

def m():
    p = b64_to_int(input('(A->M) p> '))
    g = b64_to_int(input('(A->M) g> '))
    A = b64_to_int(input('(A->M) A> '))
    print('(M->B) p: {0}'.format(int_to_b64(p)))
    print('(M->B) g: {0}'.format(int_to_b64(g)))
    print('(M->B) A (really p): {0}'.format(int_to_b64(p)))
    B = b64_to_int(input('(B->M) B> '))
    print('(M->A) B (really p): {0}'.format(int_to_b64(p)))

def int_to_bytes(i):
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='big')

def int_to_b64(i):
    return base64.b64encode(int_to_bytes(i))

def b64_to_int(b):
    return int.from_bytes(base64.b64decode(b), byteorder='big')

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge34())
