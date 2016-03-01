def challenge4():
    f = open('challenge4.txt','r')
    maxscore = 0
    scoredstr = ''
    for line in f:
        inp = bytearray.fromhex(line.rstrip())
        for i in range(ord('0'),ord('Z')):
            try:
                string = bytearray(x ^ i for x in inp).decode("utf-8")
            except UnicodeDecodeError:
                break
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
    print(challenge4())
