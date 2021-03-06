from twisted.internet import protocol, reactor
from twisted.protocols import basic
from challenge36const import *
from enum import Enum
import hashlib
import hmac
import os

def int_to_bytes(i):
    return i.to_bytes((i.bit_length() + 7) // 8, byteorder='big')

class State(Enum):
    salt = 1
    initial = 2
    verify = 3

class SRPProtocol(basic.NetstringReceiver):
    def connectionMade(self):
        self.state = State.salt
        self.a = int.from_bytes(os.urandom(128), byteorder='big')
        self.A = pow(g, self.a, N)
        self.sendString(I)
        self.sendString(int_to_bytes(self.A))

    def stringReceived(self, line):
        print('[C] [{0}] Received: {1}'.format(self.state.name, line))
        if self.state == State.salt:
            self.saltHandler(line)
        elif self.state == State.initial:
            self.initialHandler(line)
        else:
            self.verifyHandler(line)

    def saltHandler(self, line):
        self.salt = line
        self.state = State.initial

    def initialHandler(self, line):
        print('initial!')
        self.B = int.from_bytes(line, byteorder='big')
        print(self.B)
        uH = hashlib.sha256(int_to_bytes(self.A) + int_to_bytes(self.B)).digest()
        self.u = int.from_bytes(uH, byteorder='big')
        print('[C] [initial] U: {0}'.format(self.u))

        xH = hashlib.sha256(self.salt + P).digest()
        self.x = int.from_bytes(xH, byteorder='big')
        S = pow(self.B - (k * pow(g, self.x, N)), self.a + self.u * self.x, N)
        K = hashlib.sha256(int_to_bytes(S)).digest()
        h = hmac.new(K, self.salt, 'sha256').digest()
        self.sendString(h)
        self.state = State.verify

    def verifyHandler(self, line):
        if line == b'OK':
            print('[C] OK')
        else:
            print('[C] Something went wrong...')

class SRPFactory(protocol.ClientFactory):
    protocol = SRPProtocol
    def clientConnectionLost(self, connector, reason):
        print('[C] Connection lost!')
        reactor.stop()

reactor.connectTCP('localhost', 1079, SRPFactory())
reactor.run()
