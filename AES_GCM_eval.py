import timeit
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def encrypt_aes_gcm():
    key = get_random_bytes(32)  # AES-256 key
    nonce = get_random_bytes(12)  # Recommended nonce size for GCM
    plaintext = b"A" * 2000  # ~250-word plaintext

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    return ciphertext, tag

# Measure encryption time
execution_time = timeit.timeit(encrypt_aes_gcm, number=1000) / 1000  # Average over 1000 runs

execution_time *= 1000

print(f"Average AES-GCM encryption time: {execution_time:.6f} milliseconds")
