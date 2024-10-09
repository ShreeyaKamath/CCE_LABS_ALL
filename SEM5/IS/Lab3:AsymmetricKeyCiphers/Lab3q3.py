from Crypto.Util.number import getPrime, inverse, GCD, bytes_to_long, long_to_bytes
from Crypto.Random import random
import hashlib


# Step 1: Key Generation for ElGamal encryption
def elgamal_keygen(bit_length):
    # Generate a large prime number p
    p = getPrime(bit_length)

    # Choose a random generator g
    g = random.randint(2, p - 1)

    # Choose a private key x such that 1 < x < p-1
    x = random.randint(2, p - 2)

    # Compute public key component h = g^x mod p
    h = pow(g, x, p)

    # Return public key (p, g, h) and private key x
    return (p, g, h), x


# Step 2: ElGamal encryption
def elgamal_encrypt(public_key, plaintext):
    p, g, h = public_key

    # Convert plaintext to integer (numeric encoding of the message)
    plaintext_int = bytes_to_long(plaintext)

    # Generate a random session key y such that 1 < y < p-1
    y = random.randint(2, p - 2)

    # Compute c1 = g^y mod p
    c1 = pow(g, y, p)

    # Compute c2 = (plaintext * h^y) mod p
    s = pow(h, y, p)  # s = h^y mod p (shared secret)
    c2 = (plaintext_int * s) % p

    # Ciphertext is the pair (c1, c2)
    return (c1, c2)


# Step 3: ElGamal decryption
def elgamal_decrypt(private_key, public_key, ciphertext):
    p, g, h = public_key
    c1, c2 = ciphertext
    x = private_key

    # Compute the shared secret s = c1^x mod p
    s = pow(c1, x, p)

    # Compute the inverse of s mod p
    s_inv = inverse(s, p)

    # Recover the plaintext as plaintext = (c2 * s_inv) mod p
    plaintext_int = (c2 * s_inv) % p

    # Convert integer back to bytes (decode the numeric message)
    plaintext = long_to_bytes(plaintext_int)
    return plaintext


# Main
# Generate public and private keys
bit_length = 2048  # Key size in bits
public_key, private_key = elgamal_keygen(bit_length)

# Original message
message = b"Confidential Data"

# Encrypt the message
ciphertext = elgamal_encrypt(public_key, message)
print(f"Ciphertext: {ciphertext}")

# Decrypt the ciphertext
decrypted_message = elgamal_decrypt(private_key, public_key, ciphertext)
print(f"Decrypted Message: {decrypted_message.decode('utf-8')}")