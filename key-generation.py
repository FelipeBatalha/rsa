import random
import threading
from queue import Queue
import concurrent.futures
import base64


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

def decipher(cipher, n, d):
    return pow(cipher, d, n)

def cipher(msg, n, e):
    return pow(msg, e, n)


def text_to_number(text):
    text_bytes = text.encode('utf-8')
    num = int.from_bytes(text_bytes, byteorder='big')
    return num

def number_to_text(num):
    num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')
    text = num_bytes.decode('utf-8')
    return text


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
    print(f"O d é {hex(d)}")

    msg = 'pqp man, que situação difícil'
    msg = text_to_number(msg)
    ciphered_msg = cipher(msg, n, e)
    print(ciphered_msg)
    deciphered_msg = decipher(ciphered_msg, n, d)
    print(number_to_text(deciphered_msg))



    '''public_key_str = f"{0x9a11485bccb9569410a848fb1afdf2a81b17c1fa9f9eb546fd1deb873b49b693a4edf20eb8362c085cd5b28ba109dbad2bd257a013f57f745402e245b0cc2d553c7b2b8dbba57ebda7f84cfb32b7d9c254f03dbd0188e4b8e40c47b64c1bd2572834b936ffc3da9953657ef8bee80c49c2c12933c8a34804a00eb4c81248e01f}"
    public_key_b64 = base64.b64encode(public_key_str.encode())
    print(public_key_b64)'''
main()