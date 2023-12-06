import os
import threading
from queue import Queue
import base64
import hashlib
from rsa import *

def mgf1(seed: bytes, length: int, hash_func=hashlib.sha3_256) -> bytes:
    """Mask generation function."""
    hLen = hash_func().digest_size
    
    if length > (hLen << 32):
        raise ValueError("mask too long")
    
    T = b""
    
    counter = 0
    while len(T) < length:
        C = int.to_bytes(counter, 4, "big")
        T += hash_func(seed + C).digest()
        counter += 1
    return T[:length]

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

    size_limit = (len(message_bytes) > k - 2 * hash_length - 2)

    if size_limit:
        raise ValueError("File too long for OAEP padding")
    
    padding_length = k - len(message_bytes) - 2 * hash_length - 2
    padding = b'\x00' * padding_length + b'\x01'
    data_block = padding + message_bytes
    
    
    seed = os.urandom(hash_length)
    data_block_length = k - hash_length - 1
    data_block_mask = mgf1(seed, data_block_length)

    masked_data_block = int.from_bytes(data_block, 'big') ^ int.from_bytes(data_block_mask, 'big')
    masked_data_block = masked_data_block.to_bytes(data_block_length, 'big')

    #mask for the message
    seed_mask = mgf1(masked_data_block, hash_length) #pode precisar ver se é bytes e tal
    masked_seed = int.from_bytes(seed, 'big') ^ int.from_bytes(seed_mask, 'big')
    masked_seed = masked_seed.to_bytes(hash_length, 'big')
    
    #OAEP padding
    
    message_to_encrypt = b'\x00' + masked_seed + masked_data_block

    # RSA encryption
    encrypted = pow(int.from_bytes(message_to_encrypt, 'big'), e, n)
    print(encrypted)
    oaep_decrypt(encrypted, private_key)
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
    padded_message = int.from_bytes(masked_message, 'big') ^ int.from_bytes(hash(seed), 'big')

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
    #decrypted_message = oaep_decrypt(encrypted_message, private_key)

    print(encrypted_message)
    #print(decrypted_message)


main()