def challenge3(inp):
    inp = bytearray.fromhex(inp)
    maxscore = 0
    scoredstr = ''
    for i in range(ord('0'),ord('Z')):
        string = bytearray(x ^ i for x in inp).decode("utf-8")
        curscore = score(string)
        if curscore > maxscore:
            maxscore = curscore
            scoredstr = string
    return scoredstr

def score(string):
    score = 0
    mostfreq = "etaoin"
    leastfreq = "vkjxqz"
    for s in string:
        if s in mostfreq:
            score += 1
        elif s in leastfreq:
            score -= 1
    return score

if __name__ == '__main__':
    print(challenge3("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
