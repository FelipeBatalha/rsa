import random

p = random.getrandbits(512)
q = random.getrandbits(512)

print(p)

n = p * q

def miller_rabin(n):
    r = 0
    d = n - 1
    while d % 2 == 0:
        d //= 2
        r += 1

    a = random.randint(1, n)
    x = pow(a, d, n)

    k = 1000
    for i in range(1, k):
        a = random.randint(1, n)
        print(f"O a é {a}")
        x = pow(a, d, n)
        print(f"O x é {x}")
        if (x == 1 % n) or (x == -1 % n):
            print("Pode ser primo ainda")
            pass    #cuz it could be prime
        else:
            for j in range(1, r - 1):
                x = pow(x, 2, n)
                if x == 1 % n:
                    print(f"j: {j}")
                    print("É composto, game over")
                    return False    #cuz its composite
                if x == -1 % n:
                    print("Pode ser primo ainda")
                    pass    #cuz it could be prime

miller_rabin(324319)