import os
import time
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import DSS
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Helper function to generate files of given size (in MB)
def generate_file(filename, size_in_mb):
    with open(filename, 'wb') as f:
        f.write(os.urandom(size_in_mb * 1024 * 1024))  # Write random data to file

# RSA Key Generation (2048-bit)
def generate_rsa_keys():
    start_time = time.time()
    rsa_key = RSA.generate(2048)
    private_key = rsa_key.export_key()
    public_key = rsa_key.publickey().export_key()
    keygen_time = time.time() - start_time
    return private_key, public_key, keygen_time

# ECC Key Generation (secp256r1)
def generate_ecc_keys():
    start_time = time.time()
    ecc_key = ECC.generate(curve='P-256')
    private_key = ecc_key.export_key(format='PEM')
    public_key = ecc_key.public_key().export_key(format='PEM')
    keygen_time = time.time() - start_time
    return private_key, public_key, keygen_time

# RSA Encryption (Hybrid: RSA for key, AES for data)
def rsa_encrypt_file(public_key, filename):
    with open(filename, 'rb') as f:
        file_data = f.read()

    rsa_key = RSA.import_key(public_key)
    session_key = get_random_bytes(16)  # AES session key

    # Encrypt session key using RSA
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_session_key = rsa_cipher.encrypt(session_key)

    # Encrypt the file data using AES
    aes_cipher = AES.new(session_key, AES.MODE_CBC)
    encrypted_data = aes_cipher.encrypt(pad(file_data, AES.block_size))

    return encrypted_session_key, aes_cipher.iv, encrypted_data

# RSA Decryption
def rsa_decrypt_file(private_key, encrypted_session_key, iv, encrypted_data):
    rsa_key = RSA.import_key(private_key)

    # Decrypt session key using RSA
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    session_key = rsa_cipher.decrypt(encrypted_session_key)

    # Decrypt the file data using AES
    aes_cipher = AES.new(session_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(aes_cipher.decrypt(encrypted_data), AES.block_size)

    return decrypted_data

# ECC Encryption (Hybrid: ECC for key, AES for data)
def ecc_encrypt_file(public_key, filename):
    with open(filename, 'rb') as f:
        file_data = f.read()

    ecc_key = ECC.import_key(public_key)
    session_key = get_random_bytes(16)  # AES session key

    # Derive shared secret (Hybrid Encryption)
    shared_key = SHA256.new(session_key).digest()[:16]

    # Encrypt the file data using AES
    aes_cipher = AES.new(shared_key, AES.MODE_CBC)
    encrypted_data = aes_cipher.encrypt(pad(file_data, AES.block_size))

    return session_key, aes_cipher.iv, encrypted_data

# ECC Decryption
def ecc_decrypt_file(private_key, session_key, iv, encrypted_data):
    ecc_key = ECC.import_key(private_key)

    # Derive shared secret (Hybrid Encryption)
    shared_key = SHA256.new(session_key).digest()[:16]

    # Decrypt the file data using AES
    aes_cipher = AES.new(shared_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(aes_cipher.decrypt(encrypted_data), AES.block_size)

    return decrypted_data

# Performance Testing
def measure_performance(algorithm_name, keygen_time, enc_time, dec_time):
    print(f"\nPerformance of {algorithm_name}:")
    print(f"Key Generation Time: {keygen_time:.4f} seconds")
    print(f"Encryption Time: {enc_time:.4f} seconds")
    print(f"Decryption Time: {dec_time:.4f} seconds")

# Main Testing Function
def test_file_encryption(filename):
    # Generate RSA and ECC Keys
    rsa_priv_key, rsa_pub_key, rsa_keygen_time = generate_rsa_keys()
    ecc_priv_key, ecc_pub_key, ecc_keygen_time = generate_ecc_keys()

    # RSA Encryption/Decryption
    start_time = time.time()
    rsa_encrypted_key, rsa_iv, rsa_encrypted_data = rsa_encrypt_file(rsa_pub_key, filename)
    rsa_enc_time = time.time() - start_time

    start_time = time.time()
    rsa_decrypted_data = rsa_decrypt_file(rsa_priv_key, rsa_encrypted_key, rsa_iv, rsa_encrypted_data)
    rsa_dec_time = time.time() - start_time

    # ECC Encryption/Decryption
    start_time = time.time()
    ecc_encrypted_key, ecc_iv, ecc_encrypted_data = ecc_encrypt_file(ecc_pub_key, filename)
    ecc_enc_time = time.time() - start_time

    start_time = time.time()
    ecc_decrypted_data = ecc_decrypt_file(ecc_priv_key, ecc_encrypted_key, ecc_iv, ecc_encrypted_data)
    ecc_dec_time = time.time() - start_time

    # Ensure correctness
    assert rsa_decrypted_data == ecc_decrypted_data, "Decrypted data does not match!"

    # Performance results
    measure_performance("RSA", rsa_keygen_time, rsa_enc_time, rsa_dec_time)
    measure_performance("ECC", ecc_keygen_time, ecc_enc_time, ecc_dec_time)

# Generate test files (1MB, 10MB)
generate_file('testfile_1MB.bin', 1)
generate_file('testfile_10MB.bin', 10)

# Test file encryption with 1MB and 10MB files
print("\nTesting with 1MB file:")
test_file_encryption('testfile_1MB.bin')

print("\nTesting with 10MB file:")
test_file_encryption('testfile_10MB.bin')