import binascii
import logging
import sys
import base64
import time
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import random

# Crack MT seed

class Mersenne:
    def __init__(self, seed):
        self.mt = [None]*624
        self.index = 0
        self.mt[0] = seed
        for i in range(1, 624):
            self.mt[i] = (0x6c078965 * (self.mt[i-1] ^ (self.mt[i-1] >> 30)) + i) & 0xffffffff

    def extract_number(self):
        if self.index == 0:
            self.generate_numbers()

        y = self.mt[self.index]
        y = y ^ (y >> 11)
        y = y ^ ((y << 7) & 0x9d2c5680)
        y = y ^ ((y << 15) & 0xefc60000)
        y = y ^ (y >> 18)

        self.index = (self.index + 1) % 624
        return y

    def generate_numbers(self):
        for i in range(0, 624):
            y = (self.mt[i] & 0x80000000) + (self.mt[(i+1) % 624] & 0x7fffffff)
            self.mt[i] = self.mt[(i + 397) % 624] ^ (y >> 1)
            if (y % 2) != 0:
                self.mt[i] = self.mt[i] ^ 0x9908b0df

def challenge22():
    cur_time = int(time.time()) + random.randint(40, 1000)
    m = Mersenne(cur_time)
    cur_time += random.randint(40, 1000)
    num = m.extract_number()
    for i in range(int(time.time()) - 4000, int(time.time()) + 4000):
        m = Mersenne(i)
        if m.extract_number() == num:
            print("Seed: {0}".format(i))
            return


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge22())
