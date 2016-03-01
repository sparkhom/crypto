import binascii
import logging
import sys
import base64
import time
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import random

# Clone MT generator

class Mersenne:
    def __init__(self, seed, state=[]):
        if len(state) > 0:
            self.mt = state
            self.index = 0
            return

        self.mt = [None]*624
        self.index = 0
        self.mt[0] = seed
        for i in range(1, 624):
            self.mt[i] = (0x6c078965 * (self.mt[i-1] ^ (self.mt[i-1] >> 30)) + i) & 0xffffffff

    def extract_number(self):
        if self.index == 0:
            self.generate_numbers()

        y = self.mt[self.index]
        y = y ^ (y >> 11) # U
        y = y ^ ((y << 7) & 0x9d2c5680) # S
        y = y ^ ((y << 15) & 0xefc60000) # L
        y = y ^ (y >> 18) # T

        self.index = (self.index + 1) % 624
        return y

    def generate_numbers(self):
        for i in range(0, 624):
            y = (self.mt[i] & 0x80000000) + (self.mt[(i+1) % 624] & 0x7fffffff)
            self.mt[i] = self.mt[(i + 397) % 624] ^ (y >> 1)
            if (y % 2) != 0:
                self.mt[i] = self.mt[i] ^ 0x9908b0df

    def splice(self, state):
        self.mt = state

    def extract_state(self):
        return self.mt[:]

'''
    The following functions are based on http://b10l.com/?p=24
    I worked the basic maths on paper, but was finding a bit hard to get the
    math specifics right.
'''
def untemperA(y):
    return y ^ (y >> 18)

def untemperB(y):
    return y ^ ((y << 15) & 4022730752)

def untemperC(y):
    mask = 2636928640
    a = y << 7
    b = y ^ (a & mask)

    c = b << 7
    d = y ^ (c & mask)

    e = d << 7
    f = y ^ (e & mask)

    g = f << 7
    h = y ^ (g & mask)

    i = h << 7
    k = y ^ (i & mask)

    return k

def untemperD(y):
    a = y >> 11
    b = y ^ a
    c = b >> 11
    return y ^ c

def untemper(n):
    n = untemperA(n)
    n = untemperB(n)
    n = untemperC(n)
    n = untemperD(n)
    return n

def challenge23():
    cur_time = int(time.time()) + random.randint(40, 1000)
    state = []
    m = Mersenne(0)
    for i in range(0, 624):
        val = m.extract_number()
        val = untemper(val)
        state.append(val)

    n = Mersenne(0, state)
    assert(n.extract_state() == m.extract_state())

    print('m 1: {0}'.format(m.extract_number()))
    print('m 2: {0}'.format(m.extract_number()))
    print('n 1: {0}'.format(n.extract_number()))
    print('n 2: {0}'.format(n.extract_number()))
    return None


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge23())
