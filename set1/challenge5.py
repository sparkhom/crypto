import binascii

def challenge5(key, message):
    message = bytearray(message.encode("utf-8"))
    key = bytearray(key.encode("utf-8"))
    for i, c in enumerate(message):
        message[i] = c ^ key[i % 3]
    return binascii.hexlify(message)

if __name__ == '__main__':
    print(challenge5("ICE", "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"))
