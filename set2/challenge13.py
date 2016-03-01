import binascii
import logging
import sys
import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import random


def challenge13(email):
    oldprof = decrypt(encrypt(profile_for(email)))
    # Strip padding
    # Find index of user
    bytes_to_strip = oldprof[-1]
    oldprof = oldprof[:-bytes_to_strip]
    padlen = 16 - (oldprof.index(b'user') % 16)
    halves = email.split('@')
    if padlen > 0:
        halves[0] += '+' # Doesn't change the email functionality
    if padlen > 1:
        halves[0] += 'A'*(padlen-1)
    email = '@'.join(halves)

    # Create chunk with admin
    adminchunk = encrypt(profile_for('A'*10 + 'admin' + '\x0b'*11))
    adminchunk = adminchunk[16:32]

    prof = encrypt(profile_for(email))[:-16] + adminchunk

    return decrypt(prof)


def profile_for(email):
    email = email.translate({ord('&'): None, ord('='): None})
    kv = "email=" + email + "&uid=10&role=user"
    return kv

def chunks(l, n):
    """ Yield successive n-sized chunks from l.
    """
    for i in range(0, len(l), n):
        yield l[i:i+n]

def kvdict(kv):
    props = dict()
    nvp = kv.split('&')
    for nv in nvp:
        nv = nv.split('=')
        props[nv[0]] = nv[1]
    return props

def encrypt(inp):
    inp = bytes(inp.encode("utf-8"))
    key = b'\x8b4\x80#\xc5\x1c\x95i\xeb\x9d\xeb\xd0\t\xec\x0fj'
    c = AES.new(key)
    data = inp
    length = 16 - (len(data) % 16)
    data += bytes([length])*length
    return c.encrypt(data)

def decrypt(data):
    key = b'\x8b4\x80#\xc5\x1c\x95i\xeb\x9d\xeb\xd0\t\xec\x0fj'
    c = AES.new(key)
    return c.decrypt(data)

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    i = ''
    while True:
        print('Enter email, or q to quit> ',end="")
        i = input()
        if i == 'q':
            break
        print(challenge13(i))

