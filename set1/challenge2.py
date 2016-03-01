def challenge2(inp, arg):
    return hex(inp ^ arg)

if __name__ == '__main__':
    print(challenge2(0x1c0111001f010100061a024b53535009181c, 0x686974207468652062756c6c277320657965))
