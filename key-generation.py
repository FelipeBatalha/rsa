import random
import threading
from queue import Queue
import concurrent.futures


def miller_rabin(n):

    #eliminar fatores obvios
    for i in range(2,10):
        if n % i == 0:
            return False
    
    r = 0
    d = n - 1

    while d % 2 == 0:
        d //= 2
        r += 1

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []

        k = 64
        for i in range(1, k):
            a = random.randint(2, n -2)
            future = executor.submit(check_primality, a, d, n, r)
            futures.append(future)
            
        
        results = [future.result() for future in concurrent.futures.as_completed(futures)]
        return any(results)

def check_primality(a, d, n, r):
    x = pow(a, d, n)
    if x == 1 or x == n - 1:
        return True
    
    for j in range(1, r):
        x = pow(x, 2, n)
        if x == 1:
            return False
        if x == n - 1:
            return True
    
    return False  # Number is composite

def get_prime_number(queue):
    is_prime = False
    while is_prime is False:
        number = random.getrandbits(512)
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
    print(f"O n é {n}")

    phi = (p - 1) * (q - 1)
    print(f"o phi é {phi}")
    e = 65537

    d = pow(e, -1, phi)
    #print((e * d) % phi == 1)
    print(f"O d é {d}")

main()