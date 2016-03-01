import binascii
import logging
import sys
import base64
import os
import struct
import random
import hmac
import time
from flask import Flask
app = Flask(__name__)

@app.route('/')
def challenge31():
    return "Hello, world!"

@app.route('/test/<file>/<signature>')
def test(file, signature):
    digest = hmac.new(b'YELLOW SUBMARINE', file.encode('utf-8')).hexdigest()
    print(digest)
    if insecure_compare(digest, signature):
        return 'Yay!'
    else:
        return 'Nay!'

def insecure_compare(a, b):
    for c1, c2 in zip(a, b):
        if c1 != c2:
            return False
        time.sleep(0.05)
    return True


if __name__ == '__main__':
    app.debug = True
    app.run()
