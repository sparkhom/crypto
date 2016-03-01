import os
import hmac
import hashlib
from twisted.internet import protocol, reactor
from twisted.protocols import basic
from challenge36const import *
from enum import Enum

word_file = "/usr/share/dict/words"
WORDS = open(word_file).read().splitlines()

def int_to_bytes(i):
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='big')

class State(Enum):
    email = 1
    initial = 2
    verify = 3

class SimplifiedSRPProtocol(basic.NetstringReceiver):
    def connectionMade(self):
        self.state = State.email
        #self.salt = os.urandom(16)
        self.salt = b''
        """
        xH = hashlib.sha256(self.salt + P).digest()
        x = int.from_bytes(xH, byteorder='big')
        self.v = pow(g, x, N)
        """

    def stringReceived(self, line):
        print('[S] [{0}] Received: {1}'.format(self.state.name, line))
        if self.state == State.email:
            self.emailHandler(line)
        elif self.state == State.initial:
            self.initialHandler(line)
        else:
            self.verifyHandler(line)

    def emailHandler(self, line):
        if I != line:
            self.transport.loseConnection()
        self.state = State.initial

    def initialHandler(self, line):
        self.sendString(self.salt)
        #self.b = int.from_bytes(os.urandom(128), byteorder='big')
        self.b = 1
        self.B = pow(g, self.b, N)
        self.sendString(int_to_bytes(self.B))
        self.A = int.from_bytes(line, byteorder='big')

        uH = os.urandom(16)
        #self.u = int.from_bytes(uH, byteorder='big')
        self.u = 1
        self.sendString(int_to_bytes(self.u))

        """
        S = pow(self.A * pow(self.v, self.u, N), self.b, N)
        K = hashlib.sha256(int_to_bytes(S)).digest()
        self.h = hmac.new(K, self.salt, 'sha256').digest()
        """

        self.state = State.verify

    def verifyHandler(self, line):
        self.transport.loseConnection()
        for i, word in enumerate(WORDS):
            word = word.encode('utf-8')
            xH = hashlib.sha256(self.salt + word).digest()
            x = int.from_bytes(xH, byteorder='big')
            self.v = pow(g, x, N)
            S = pow(self.A * pow(self.v, self.u, N), self.b, N)
            K = hashlib.sha256(int_to_bytes(S)).digest()
            h = hmac.new(K, self.salt, 'sha256').digest()
            if line == h:
                print(word)
                return
        """
        if line == self.h:
            self.sendString(b'OK')
            print('[S] OK')
            """

class SRPFactory(protocol.ServerFactory):
    protocol = SimplifiedSRPProtocol

reactor.listenTCP(1079, SRPFactory())
reactor.run()
