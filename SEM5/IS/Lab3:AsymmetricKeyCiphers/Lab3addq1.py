import random

# ElGamal Encryption
def elgamal_encrypt(p, g, h, message):
    encrypted_message = []
    for char in message:
        # Convert each character to its ASCII representation
        m = ord(char)

        # Random integer for encryption (should be kept secret)
        y = random.randint(1, p-2)

        # Compute the components of the ciphertext
        c1 = pow(g, y, p)
        c2 = (m * pow(h, y, p)) % p

        encrypted_message.append((c1, c2))

    return encrypted_message

# ElGamal Decryption
def elgamal_decrypt(p, x, encrypted_message):
    decrypted_message = ''
    for (c1, c2) in encrypted_message:
        s = pow(c1, x, p)
        m = (c2 * pow(s, p-2, p)) % p  # Using modular inverse

        # Convert back to the character from ASCII
        decrypted_message += chr(m)

    return decrypted_message

# Given values
p = 7919
g = 2
h = 6465
x = 2999

# Message to encrypt
message = "Asymmetric Algorithms"

# Encryption
encrypted_message = elgamal_encrypt(p, g, h, message)
print("Encrypted message:", encrypted_message)

# Decryption to verify the original message
decrypted_message = elgamal_decrypt(p, x, encrypted_message)
print("Decrypted message:", decrypted_message)
