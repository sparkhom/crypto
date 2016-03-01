import binascii
import logging
import sys

def challenge9(inp, pad_length):
    pad_bytes = pad_length - len(inp)
    byte = chr(pad_bytes)
    bytearr = bytearray((inp + byte*pad_bytes).encode("utf-8"))
    return bytearr

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge9('YELLOW SUBMARINERAR', 25))
