import binascii
import logging
import sys
import base64
import os
import struct
import random
import md4sha1

word_file = "/usr/share/dict/words"
WORDS = open(word_file).read().splitlines()
key = random.choice(WORDS).encode("ascii")

def md_padding(message):
    original_byte_len = len(message)
    original_bit_len = original_byte_len * 8
    padding = b''
    # append the bit '1' to the message
    padding += b'\x80'
    
    # append 0 <= k < 512 bits '0', so that the resulting message length (in bits)
    #    is congruent to 448 (mod 512)
    padding += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
    
    # append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    # little endian for MD4!!!
    padding += struct.pack(b'<Q', original_bit_len)

    return padding

def challenge30(p):
    prefix_mac = bytes(md4sha1.MD4(key + p))
    h = struct.unpack("<4I", prefix_mac)
    print(h)
    correct_mac = bytes(md4sha1.MD4(key + p + md_padding(key + p) + b';admin=true'))


    for i in range(64):
        # The padding needs the new length of our full message, but SHA1 should still operate on the message
        # Basically, we are starting from the end of the last SHA1, but continuing to add stuff
        MD4_STATE = md4sha1.make_md_hash_64(md4sha1.md4_compress, lambda state: md4sha1.little_endian_bytes(h, 4), lambda length: md4sha1.little_endian_bytes([i + len(p + md_padding(b'\x00'*i + p) + b';admin=true')], 8))
        forged_mac = MD4_STATE(b';admin=true')
        if bytes(forged_mac) == correct_mac:
            return forged_mac

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge30(b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'))
