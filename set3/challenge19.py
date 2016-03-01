import binascii
import logging
import sys
import base64
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import random

# Implement CTR mode

#key=YELLOW SUBMARINE
#nonce=0
#format=64 bit unsigned little endian nonce,
     #64 bit little endian block count (byte count / 16)

strings = [
       'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
'U2hlIHJvZGUgdG8gaGFycmllcnM/',
'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
        ]

rf = Random.new()
key = rf.read(16)
nonce = 0
freq = dict(zip("etaoinshrdlucmfwypvbgkjqxz"[::-1], range(26)))

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

def breaksingle(string):
    maxscore = 0
    maxstring = '' 
    maxi = 0
    for i in range(0, 256):
        try:
            decrypted = ''.join(bytes([x ^ i for x in string]).decode('utf-8'))
        except UnicodeDecodeError:
            continue
        decscore = (score(decrypted) + score2(decrypted)) / 2
        if (decscore > maxscore):
            maxscore = decscore
            maxstring = decrypted
            maxi = i
    return maxi 

def challenge19():
    # 16 byte key stream
    key = [] 
    pivot = [[] for x in range(0,16)]
    encrypted = encrypt(strings)
    for e in encrypted:
        for i, c in enumerate(e):
            pivot[i % 16].append(c)
    for p in pivot:
        key.append(breaksingle(p))
    for e in encrypted:
        print(bytes([x ^ y for x, y in zip(e, key)]).decode('utf-8').upper())

def encrypt(inp):
    c = AES.new(key, AES.MODE_ECB)
    encrypted = []
    # Should probably do the check code better
    for i, text in enumerate(inp):
        dec = base64.b64decode(text)
        stream = c.encrypt(b'\x00'*16)
        encrypted.append(bytes([x ^ y for x, y in zip(stream, dec)]))
    return encrypted


if __name__ == '__main__':
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG)
    print(challenge19())
