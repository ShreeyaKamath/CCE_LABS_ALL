from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.kbkdf import KBKDFHMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


# Encrypt a message using the recipient's public key
def ecc_encrypt(public_key, message):
    # Generate a shared secret using ECDH
    ephemeral_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    shared_key = ephemeral_key.exchange(ec.ECDH(), public_key)

    # Derive a key for symmetric encryption from the shared key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

    # Encrypt the message using AES GCM
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

    return ephemeral_key.public_key(), iv, ciphertext, encryptor.tag


# Decrypt a message using the recipient's private key
def ecc_decrypt(private_key, ephemeral_public_key, iv, ciphertext, tag):
    # Generate the shared secret using ECDH
    shared_key = private_key.exchange(ec.ECDH(), ephemeral_public_key)

    # Derive a key for symmetric decryption from the shared key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

    # Decrypt the message using AES GCM
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_message.decode()


# Example usage
if __name__ == "__main__":
    # Generate a private-public key pair for the recipient
    private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
    public_key = private_key.public_key()

    # Message to be encrypted
    message = "Secure Transactions"

    # Encrypt the message
    ephemeral_public_key, iv, ciphertext, tag = ecc_encrypt(public_key, message)
    print(f"Ciphertext: {ciphertext.hex()}")

    # Decrypt the message
    decrypted_message = ecc_decrypt(private_key, ephemeral_public_key, iv, ciphertext, tag)
    print(f"Decrypted message: {decrypted_message}")

