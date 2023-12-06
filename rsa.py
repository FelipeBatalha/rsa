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
        number = random.getrandbits(1024)
        is_prime = miller_rabin(number)
    queue.put(number)

def rsa_decipher(cipher, private_key):
    d, n = private_key
    return pow(cipher, d, n)

def rsa_cipher(msg, public_key):
    e, n = public_key
    return pow(msg, e, n)


def text_to_number(text):
    text_bytes = text.encode('utf-8')
    num = int.from_bytes(text_bytes, byteorder='big')
    return num

def number_to_text(num):
    num_bytes = num.to_bytes((num.bit_length() + 7) // 8, byteorder='big')
    text = num_bytes.decode('utf-8')
    return text

def generate_keys():

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

    n = p * q

    phi = (p - 1) * (q - 1)

    e = 65537

    d = pow(e, -1, phi)

    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

if __name__ == "__main__":

    public_key, private_key = generate_keys()

    msg = 'apenas uma mensagem de teste'

    msg = text_to_number(msg)

    encrypted_message = rsa_cipher(msg, public_key)
    decrypted_message = rsa_decipher(encrypted_message, private_key)

    decrypted_message = number_to_text(decrypted_message)

    print("Mensagem cifrada: \n", base64.b64encode(encrypted_message.to_bytes((encrypted_message.bit_length() + 7) // 8, 'big')))
    print("Mensagem decifrada: \n", decrypted_message)