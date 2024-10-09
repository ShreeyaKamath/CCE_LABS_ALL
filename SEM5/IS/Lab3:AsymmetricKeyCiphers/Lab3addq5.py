import time
import os
from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Function to generate random message
def generate_random_message(size_kb):
    return os.urandom(size_kb * 1024)

# RSA Implementation
def rsa_encrypt_decrypt(message):
    # Key Generation
    start_time = time.time()
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    key_gen_time = time.time() - start_time

    # AES Encryption
    aes_key = get_random_bytes(16)  # Generate a random AES key
    cipher_aes = AES.new(aes_key, AES.MODE_CBC)
    ciphertext = cipher_aes.encrypt(pad(message, AES.block_size))
    iv = cipher_aes.iv  # Store the IV

    # Encrypt the AES key with RSA
    start_time = time.time()
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypt_time = time.time() - start_time

    # Decrypt the AES key with RSA
    start_time = time.time()
    decrypted_aes_key = private_key.decrypt(encrypted_aes_key)
    decrypt_time = time.time() - start_time

    # AES Decryption
    cipher_aes_decrypt = AES.new(decrypted_aes_key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher_aes_decrypt.decrypt(ciphertext), AES.block_size)

    return key_gen_time, encrypt_time, decrypt_time

# ElGamal Implementation
def elgamal_encrypt_decrypt(message):
    # Key Generation
    start_time = time.time()
    key = ElGamal.generate(2048, get_random_bytes)
    private_key = key.x
    public_key = key.y
    key_gen_time = time.time() - start_time

    # Encryption
    start_time = time.time()
    ciphertext = key.encrypt(message)
    encrypt_time = time.time() - start_time

    # Decryption
    start_time = time.time()
    decrypted_message = key.decrypt(ciphertext)
    decrypt_time = time.time() - start_time

    return key_gen_time, encrypt_time, decrypt_time

# Main Function to run the tests
def run_tests():
    message_sizes = [1, 10]  # Sizes in KB
    results = {
        'RSA': {'key_gen': [], 'encrypt': [], 'decrypt': []},
        'ElGamal': {'key_gen': [], 'encrypt': [], 'decrypt': []}
    }

    for size in message_sizes:
        message = generate_random_message(size)

        # Test RSA
        key_gen_time, encrypt_time, decrypt_time = rsa_encrypt_decrypt(message)
        results['RSA']['key_gen'].append(key_gen_time)
        results['RSA']['encrypt'].append(encrypt_time)
        results['RSA']['decrypt'].append(decrypt_time)

        # Test ElGamal
        key_gen_time, encrypt_time, decrypt_time = elgamal_encrypt_decrypt(message)
        results['ElGamal']['key_gen'].append(key_gen_time)
        results['ElGamal']['encrypt'].append(encrypt_time)
        results['ElGamal']['decrypt'].append(decrypt_time)

    # Display Results
    for algo in results:
        print(f"{algo} Results:")
        for size_kb, times in zip(message_sizes, results[algo].values()):
            print(f"Message Size: {size_kb} KB - Key Generation Time: {times[0]:.6f}s, Encryption Time: {times[1]:.6f}s, Decryption Time: {times[2]:.6f}s")
        print()

# Run the tests
run_tests()
