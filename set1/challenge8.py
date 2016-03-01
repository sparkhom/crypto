import binascii
import logging
import sys

def challenge8():
    f = open('challenge8.txt','r')
    for line in f:
        bytearr = bytearray.fromhex(line.rstrip())
        blocks = [binascii.hexlify(bytearr[i:i + 16]) for i in range(0, len(bytearr), 16)]
        if len(blocks) != len(set(blocks)):
            return line

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge8())
