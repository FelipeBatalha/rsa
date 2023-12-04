import random
import threading
from queue import Queue
import concurrent.futures
import base64
import hashlib

def sha3_256(message):
    if isinstance(message, str):  # Check if the input is a string
        message = message.encode()  # Encode the string to bytes if it's a string
        
    if isinstance(message, bytes):  # Check if the input is bytes
        hashed = hashlib.sha3_256(message).digest()  # Get the hash of the bytes
    else:
        hashed = hashlib.sha3_256(int.to_bytes(message, (message.bit_length() + 7) // 8, 'big')).digest()

    return int.from_bytes(hashed, 'big')  # Convert the hashed bytes to an integer


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

def oaep_encrypt(message, public_key):
    e, n = public_key
    k = len(bin(n)[2:]) // 8 - 2 * 32
    message = int.from_bytes(message.encode(), 'big')

    hashed_message = sha3_256(message)
    padded = (message << (k * 8)) | hashed_message

    return cipher(padded, n, e)

def oaep_decrypt(ciphertext, private_key):
    d, n = private_key

    decrypted = decipher(ciphertext, n, d)

    # Extracting the message and hash
    message = decrypted >> 256
    hash_check = decrypted & ((1 << 256) - 1)

    # Convert message to bytes
    message_bytes = message.to_bytes((message.bit_length() + 7) // 8, 'big')

    # Extract the hash (last 32 bytes)
    extracted_hash = message_bytes[-32:]

    # Extract the message (excluding the hash)
    extracted_message = message_bytes[:-32]

    # Recalculate the hash of the extracted message
    recalculated_hash = hashlib.sha3_256(extracted_message).digest()

    print("Hash Check:", hash_check)
    print("Extracted Hash:", int.from_bytes(extracted_hash, 'big'))
    print("Recalculated Hash:", int.from_bytes(recalculated_hash, 'big'))

    return extracted_message.decode()


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

    #print(f"O p é {p}")
    #print(f"O q é {q}")

    n = p * q
    #print(f"O n é {n}")

    phi = (p - 1) * (q - 1)
    #print(f"o phi é {phi}")
    e = 65537

    d = pow(e, -1, phi)
    ##print((e * d) % phi == 1)
    #print(f"O d é {hex(d)}")

    msg = 'pqp man, que situação difícil'
    public_key = (e, n)
    private_key = (d, n)

    encrypted_message = oaep_encrypt(msg, public_key)
    decrypted_message = oaep_decrypt(encrypted_message, private_key)

    print(encrypted_message)
    print(decrypted_message)

    '''msg = text_to_number(msg)
    ciphered_msg = cipher(msg, n, e)
    #print(ciphered_msg)
    deciphered_msg = decipher(ciphered_msg, n, d)
    #print(number_to_text(deciphered_msg))'''


main()