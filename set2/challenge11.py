import binascii
import logging
import sys
import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import random

def challenge11(inp):
    crypted = list(chunks(binascii.hexlify(genkeyenc(inp)), 16))
    if len(crypted) != len(set(crypted)):
        return 'ECB'
    else:
        return 'CBC'

def chunks(l, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in range(0, len(l), n):
        yield l[i:i+n]

def genkeyenc(inp):
    rf = Random.new()
    randomkey = rf.read(16)
    begin_pad = rf.read(random.randint(5,10))
    end_pad = rf.read(random.randint(5,10))
    mode = random.randint(0,1)
    if mode == 1: # ECB
        logging.debug('ECB')
        c = AES.new(randomkey)
    else: # CBC
        logging.debug('CBC')
        c = AES.new(randomkey, AES.MODE_CBC, rf.read(16))

    data = begin_pad + inp + end_pad
    length = 16 - (len(data) % 16)
    data += bytes([length])*length
    return c.encrypt(data)

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge11(b'A'*64))
