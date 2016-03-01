import binascii
import logging
import sys

freq = dict(zip("etaoinshrdlucmfwypvbgkjqxz"[::-1], range(26)))

def challenge6():
    f = open('challenge6u.txt','rb')
    keysize = findkeysize(f)
    blocks = [bytearray() for i in range(keysize)]
    decoded = [bytearray() for i in range(keysize)]
    finalstr = ''
    key = ''
    while True:
        buf = f.read(keysize)
        if not buf: break
        for i in range(keysize):
            try:
                blocks[i].append(buf[i])
            except IndexError:
                continue
    for i in range(keysize):
        k = breaksingle(blocks[i])
        key += k
        decoded[i] = bytearray(x ^ ord(k) for x in blocks[i]).decode("utf-8")

    for i in range(keysize):
        for j in decoded:
            finalstr += j[i]
        
    print('Key: %s' % key)
    return finalstr

def findkeysize(f):
    keysize = 0
    mindist = float('Inf')

    for size in range(2,40):
        f.seek(0)
        first = f.read(size)
        second = f.read(size)
        third = f.read(size)
        fourth = f.read(size)
        dist = hamming(first, second) / size
        dist2 = hamming(second, third) / size
        dist3 = hamming(third, fourth) / size
        dist4 = hamming(first, fourth) / size
        dist5 = hamming(second, fourth) / size
        dist6 = hamming(first, third) / size
        dist = (dist + dist2 + dist3 + dist4 + dist5 + dist6) / 6.0
        if dist < mindist:
            mindist = dist
            keysize = size
    f.seek(0)
    return keysize

def hamming(bytes1, bytes2):
    dist = 0
    for a, b in zip(bytes1, bytes2):
        dist += popcount(a ^ b)
    return dist

def popcount(x):
    x -= (x >> 1) & 0x5555555555555555
    x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333)
    x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f
    return ((x * 0x0101010101010101) & 0xffffffffffffffff ) >> 56

def breaksingle(enc):
    maxscore = 0
    char = ''
    scoredstr = ''
    for i in range(32, 127):
        try:
            string = bytearray(x ^ i for x in enc).decode("utf-8")
        except UnicodeDecodeError:
            break
        curscore = score2(string)
        if curscore > maxscore:
            maxscore = curscore
            scoredstr = string
            char = chr(i)
    return char 

def score(string):
    string = string.lower()
    score = 0
    mostfreq = "etaoin"
    leastfreq = "vkjxqz"
    for s in string:
        if s in mostfreq:
            score += 1
        elif s in leastfreq:
            score -= 1
    return score

def score2(string):
    string = string.lower()
    score = 0
    for s in string:
        try:
            score += freq[s]
        except KeyError:
            continue
    return score
        
if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge6())
