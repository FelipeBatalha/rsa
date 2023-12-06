import os
import threading
from queue import Queue
import base64
import hashlib
from rsa import *

def hash(message):
    if isinstance(message, str):
        message = message.encode()
        
    if isinstance(message, bytes):
        hashed = hashlib.sha3_256(message).digest()
    else:
        hashed = hashlib.sha3_256(int.to_bytes(message, (message.bit_length() + 7) // 8, 'big')).digest()

    return hashed


def oaep_encrypt(message, public_key, private_key):
    e, n = public_key

    k = (n.bit_length() + 7) // 8

    message_bytes = message.encode('utf-8')

    hash_length = hashlib.sha256().digest_size 

    size_limit = len(message_bytes) > k - 2 * hash_length - 2

    if size_limit:
        raise ValueError("Message too long for OAEP padding")
    
    #random nonce
    seed = os.urandom(hash_length)

    #mask for the message
    seed_hash = hash(seed)
    masked_seed = int.from_bytes(seed, 'big') ^ int.from_bytes(seed_hash, 'big')
    masked_seed = masked_seed.to_bytes(hash_length, 'big')
    
    #OAEP padding
    padding_length = k - size_limit
    padded_message = (
        b'\x00' * padding_length +
        b'\x01' +
        masked_seed +
        hash(masked_seed + message_bytes) +
        message_bytes
    )

    # RSA encryption
    encrypted = pow(int.from_bytes(padded_message, 'big'), e, n)
    number_to_text(oaep_decrypt(encrypted, private_key))
    return encrypted


def oaep_decrypt(ciphertext, private_key):
    d, n = private_key

    hash_length = hashlib.sha256().digest_size 

    k = (n.bit_length() + 7) // 8  # Length of the modulus in bytes

    decrypted = pow(ciphertext, d, n)
    
    padded_message = decrypted.to_bytes(k, 'big')

    # extract masked padded message
    masked_padded_message = padded_message[hash_length:]

    # extract masked seed from masked padded message
    masked_seed = masked_padded_message[:hash_length]
    masked_message = masked_padded_message[hash_length:]

    # unmask the seed
    seed = int.from_bytes(masked_seed, 'big') ^ int.from_bytes(hash(masked_message), 'big')
    seed = seed.to_bytes(hash_length, 'big')
    # Unmask the padded message
    padded_message = int.from_bytes(masked_message, 'big') ^ int.from_bytes(hash(seed.to_bytes(k - hash_length, 'big')), 'big')

    # remove padding and get original message
    original_message = padded_message.to_bytes(k - hash_length, 'big')
    idx = original_message.find(b'\x01')
    if idx == -1:
        raise ValueError("Invalid padding")
    
    return original_message[idx + 1:].decode('utf-8')


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

    n = p * q

    phi = (p - 1) * (q - 1)

    e = 65537

    d = pow(e, -1, phi)

    msg = 'pqp man, que situação difícil'
    public_key = (e, n)
    private_key = (d, n)

    encrypted_message = oaep_encrypt(msg, public_key, private_key)
    decrypted_message = oaep_decrypt(encrypted_message, private_key)

    print(encrypted_message)
    #print(decrypted_message)


main()