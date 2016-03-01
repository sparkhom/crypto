import binascii
import logging
import sys
import base64
import os
import struct
import random

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2

def challenge33():
    a = random.getrandbits(1024)
    A = pow(g, a, p)
    b = random.getrandbits(1024)
    B = pow(g, b, p)

    s1 = pow(B, a, p)
    s2 = pow(A, b, p)

    print(s1.to_bytes(192, 'big'))
    print(s2.to_bytes(192, 'big'))


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge33())
