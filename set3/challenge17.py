import binascii
import logging
import sys
import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import random

strings = [
        'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
        ]

rf = Random.new()
key = rf.read(16)
iv = rf.read(16)

def challenge17():
    # Strip out IV
    enc = oracle()
    print(len(enc))
    num_blocks = (len(enc) // 16)
    final_decrypted = []
    for b in range(num_blocks, 0, -1):
        last_block_start = b * 16
        cur_block_start = last_block_start - 16
        clast = enc[cur_block_start:last_block_start]
        print('{0}:{1}'.format(cur_block_start, last_block_start))
        decrypted = []
        cprimenew = []
        for i in range(15, -1, -1):
            #print('new loop!')
            cprime = b'\x00'*i
            for j in range(0,256):
                concated = iv + cprime + bytes([j]) + bytes(cprimenew) + clast
                checked = check(concated)
                if checked == True:
                    #print('checked!')
                    #print(concated)
                    #print('{0}: {1}'.format(j, checked))
                    dec = (16 - i) ^ enc[cur_block_start - 16 + i] ^ j
                    decrypted.insert(0, dec)
                    cprimenew = []
                    for c, d in reversed(list(enumerate(decrypted))):
                        #print('cprimenew({0}): P`2({1}) = {2}, P2({1}) = {3}, C1({1}) = {4}'.format(c, i + c, (16 - i + 1), d, enc[32 + i]))
                        cprimenew.insert(0, (16 - i + 1) ^ d ^ enc[cur_block_start - 16 + i + c])
                    break
        print('Decrypt success for block {0}: {1}'.format(b, bytes(decrypted)))
        final_decrypted = decrypted + final_decrypted
    return bytearray(final_decrypted)


def check(inp):
    c = AES.new(key, AES.MODE_CBC, iv)
    d = c.decrypt(inp[16:])
    # Should probably do the check code better
    padbyte = d[-1]
    if padbyte == 0:
        return False
    for l in range(1, padbyte + 1):
        if d[-l] != padbyte:
            return False
    return True

def oracle():
    c = AES.new(key, AES.MODE_CBC, iv)
    data = base64.b64decode(random.choice(strings))
    length = 16 - (len(data) % 16)
    data += bytes([length])*length
    return iv + c.encrypt(data)

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge17())
