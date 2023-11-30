import random
import threading
from queue import Queue

def miller_rabin(n):

    if n % 2 == 0:
        return False
    
    r = 0
    d = n - 1

    while d % 2 == 0:
        d //= 2
        r += 1

    a = random.randint(1, n)
    x = pow(a, d, n)

    k = 100000000
    for i in range(1, k):
        a = random.randint(1, n)
        #pritn(f"O a é {a}")
        x = pow(a, d, n)
        #pritn(f"O x é {x}")

        if (x == 1 % n) or (x == -1 % n):
            pass
            #pritn("Pode ser primo")
        else:
            for j in range(1, r - 1):
                x = pow(x, 2, n)
                if x == 1 % n:
                    #pritn("É composto")
                    return False    #cuz its composite
                elif x == -1 % n:
                    pass
                    #pritn("Pode ser primo")
    return True

def get_prime_number(queue):
    is_prime = False
    while is_prime is False:
        if is_prime:
            break
        else:
            number = random.getrandbits(128)
            is_prime = miller_rabin(number)
    queue.put(number)

def main():

    result_queue_p = Queue()
    result_queue_q = Queue()

    p_thread = threading.Thread(target=get_prime_number,args=(result_queue_p,))
    q_thread = threading.Thread(target=get_prime_number, args=(result_queue_q,))

    p_thread.start()
    q_thread.start()

    p_thread.join()
    q_thread.join()

    p = result_queue_p.get()
    q = result_queue_q.get()

    print(f"O p é {p}")
    print(f"O q é {q}")

    n = p * q
    print(n)

main()