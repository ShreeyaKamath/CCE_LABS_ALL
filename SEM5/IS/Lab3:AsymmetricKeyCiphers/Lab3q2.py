from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import os

# Step 1: Generate ECC key pair (for both sender and receiver)
def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Step 2: Derive shared secret using private key and peer's public key (ECDH)
def derive_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

# Step 3: Derive AES key from shared secret using HKDF
def derive_aes_key(shared_secret):
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'encryption context',
        backend=default_backend()
    ).derive(shared_secret)
    return derived_key

# Step 4: Encrypt message using AES (with the derived key)
def aes_encrypt(aes_key, plaintext):
    iv = os.urandom(16)  # AES Initialization vector (IV)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = PKCS7(128).padder()  # PKCS7 padding to make the plaintext multiple of block size
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    return iv, ciphertext

# Step 5: Decrypt AES ciphertext using the same AES key
def aes_decrypt(aes_key, iv, ciphertext):
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    decrypted_padded_message = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = PKCS7(128).unpadder()  # Remove padding
    decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

    return decrypted_message

# Example Usage
# Generate key pairs for two parties (sender and receiver)
private_key_sender, public_key_sender = generate_ecc_key_pair()
private_key_receiver, public_key_receiver = generate_ecc_key_pair()

# Derive shared secret (receiver's private key, sender's public key)
shared_secret = derive_shared_secret(private_key_receiver, public_key_sender)

# Derive AES key from the shared secret
aes_key = derive_aes_key(shared_secret)

# Encrypt message
message = b"Secure Transactions"
iv, ciphertext = aes_encrypt(aes_key, message)
print(f"Ciphertext (Hex): {ciphertext.hex()}")

# Decrypt message
decrypted_message = aes_decrypt(aes_key, iv, ciphertext)
print(f"Decrypted Message: {decrypted_message.decode()}")

