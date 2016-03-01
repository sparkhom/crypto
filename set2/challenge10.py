import binascii
import logging
import sys
import base64
from Crypto.Cipher import AES

def challenge10():
    f = open('challenge10.txt', 'r')
    block_size = 16
    decrypted = ''
    encrypted = base64.b64decode(f.read())
    prevblock = b'\x00' * block_size
    c = AES.new('YELLOW SUBMARINE')
    for i in range(0, len(encrypted) - block_size + 1, block_size):
        d = c.decrypt(encrypted[i:i+block_size]) # Decrypt a block
        d = [a ^ b for a,b in zip(d, prevblock)]
        prevblock = encrypted[i:i+block_size]
        decrypted += ''.join([chr(x) for x in d])
    return decrypted


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge10())
