import os
import time
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


class KeyManagement:
    def __init__(self):
        self.keys = {}  # To store public/private keys for each subsystem

    def generate_rsa_keys(self, name):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        self.keys[name] = {
            'private': private_key,
            'public': public_key
        }

        return private_key, public_key

    def get_public_key(self, name):
        return self.keys[name]['public']

    def get_private_key(self, name):
        return self.keys[name]['private']


class SecureCommunication:
    def __init__(self):
        self.key_management = KeyManagement()

    def establish_secure_channel(self, system_a, system_b):
        # Generate keys for both systems
        self.key_management.generate_rsa_keys(system_a)
        self.key_management.generate_rsa_keys(system_b)

        # Generate Diffie-Hellman keys for both systems
        dh_private_a = ec.generate_private_key(ec.SECP256R1(), default_backend())
        dh_private_b = ec.generate_private_key(ec.SECP256R1(), default_backend())

        dh_public_a = dh_private_a.public_key()
        dh_public_b = dh_private_b.public_key()

        # Exchange public keys
        shared_secret_a = dh_private_a.exchange(ec.ECDH(), dh_public_b)
        shared_secret_b = dh_private_b.exchange(ec.ECDH(), dh_public_a)

        # Verify that both shared secrets are the same
        assert shared_secret_a == shared_secret_b, "Shared secrets do not match"

        return shared_secret_a

    def rsa_encrypt(self, message, public_key):
        ciphertext = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def rsa_decrypt(self, ciphertext, private_key):
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode()


def main():
    # Create an instance of SecureCommunication
    secure_comm = SecureCommunication()

    # Define subsystems
    system_a = "Finance System"
    system_b = "HR System"

    # Establish secure channel
    print("Establishing secure channel...")
    shared_secret = secure_comm.establish_secure_channel(system_a, system_b)
    print(f"Shared Secret Established: {shared_secret.hex()}")

    # Sample document to encrypt
    message = "Confidential Financial Report"

    # Encrypt message using RSA
    public_key_b = secure_comm.key_management.get_public_key(system_b)
    encrypted_message = secure_comm.rsa_encrypt(message, public_key_b)
    print(f"Encrypted Message: {encrypted_message.hex()}")

    # Decrypt message using RSA
    private_key_b = secure_comm.key_management.get_private_key(system_b)
    decrypted_message = secure_comm.rsa_decrypt(encrypted_message, private_key_b)
    print(f"Decrypted Message: {decrypted_message}")


if __name__ == "__main__":
    main()


#Explanation of the Code

""" Key Management Class: This class is responsible for generating and storing RSA keys for different systems in the enterprise.
    Secure Communication Class: This class handles:
        Establishing secure channels using the Diffie-Hellman key exchange.
        Encrypting and decrypting messages using RSA.
    Main Function:
        It creates instances of the systems (e.g., Finance and HR).
        Establishes a secure communication channel between the systems.
        Demonstrates RSA encryption and decryption of a sample document."""
