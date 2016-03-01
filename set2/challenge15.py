import logging
import sys

def challenge15(p):
    c = p[-1]
    if bytes([c])*c == p[-c:]:
        return True
    else:
        return False

if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge15(b'ICE ICE BABY\x04\x04\x04\x04'))
