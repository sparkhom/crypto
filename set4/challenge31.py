import binascii
import logging
import sys
import base64
import os
import struct
import random
import requests
import itertools
from datetime import timedelta

def challenge31():
    # 16 byte HMAC
    guess = bytearray(b'0'*32)
    for i in range(32):
        for j in itertools.chain(range(48, 58), range(97, 103)):
            guess[i] = j
            if time_url(guess, i):
                break
    return guess

def time_url(guess, i):
    d = timedelta(milliseconds=50)
    nf = requests.get('http://127.0.0.1:5000/test/a/' + guess.decode('utf-8'))
    nf2 = requests.get('http://127.0.0.1:5000/test/a/' + guess.decode('utf-8'))
    print(nf.elapsed)
    if ((nf.elapsed + nf2.elapsed) / 2 > (d * (i + 1))):
        return True
    else:
        return False

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge31())
