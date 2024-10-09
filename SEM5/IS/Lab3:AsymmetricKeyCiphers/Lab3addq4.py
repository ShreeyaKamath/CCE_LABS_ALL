import os
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes


# Function to generate private and public keys
def generate_keys():
    # Generate a private key for use in the exchange
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    return private_key, public_key


# Function to encrypt the data
def elgamal_encrypt(public_key, plaintext):
    # Generate a random ephemeral key
    ephemeral_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public_key = ephemeral_key.public_key()

    # Compute the shared secret
    shared_secret = ephemeral_key.exchange(ec.ECDH(), public_key)

    # Derive a symmetric key from the shared secret
    symmetric_key = hashes.Hash(hashes.SHA256())
    symmetric_key.update(shared_secret)
    derived_key = symmetric_key.finalize()

    # Encrypt the plaintext using the derived symmetric key
    cipher_text = bytes((b1 ^ b2) for b1, b2 in zip(plaintext, derived_key))

    return ephemeral_public_key, cipher_text


# Function to decrypt the data
def elgamal_decrypt(private_key, ephemeral_public_key, cipher_text):
    # Compute the shared secret using the ephemeral public key
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)

    # Derive the symmetric key from the shared secret
    symmetric_key = hashes.Hash(hashes.SHA256())
    symmetric_key.update(shared_secret)
    derived_key = symmetric_key.finalize()

    # Decrypt the plaintext using the derived symmetric key
    decrypted_text = bytes((b1 ^ b2) for b1, b2 in zip(cipher_text, derived_key))

    return decrypted_text


# Example patient data (sensitive information)
patient_data = b"Patient Name: John Doe, Diagnosis: Hypertension, Medication: Amlodipine"

# Generate public and private keys
private_key, public_key = generate_keys()

# Measure encryption time
start_time = time.time()
ephemeral_public_key, encrypted_data = elgamal_encrypt(public_key, patient_data)
encryption_time = time.time() - start_time

# Measure decryption time
start_time = time.time()
decrypted_data = elgamal_decrypt(private_key, ephemeral_public_key, encrypted_data)
decryption_time = time.time() - start_time

# Output results
print("Public Key:", public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo).decode())
print("Ephemeral Public Key:", ephemeral_public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo).decode())
print("Encrypted Data:", encrypted_data.hex())
print("Decrypted Data:", decrypted_data.decode())
print(f"Encryption Time: {encryption_time:.6f} seconds")
print(f"Decryption Time: {decryption_time:.6f} seconds")