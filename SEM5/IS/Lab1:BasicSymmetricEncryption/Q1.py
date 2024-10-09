#1) Encrypt the message "I am learning information security" using one of the
#following ciphers. Ignore the space between words. Decrypt the message to
#get the original plaintext:
#a) Additive cipher with key = 20
#b) Multiplicative cipher with key = 15
#c) Affine cipher with key = (15, 20)

# Helper functions to encrypt and decrypt using different ciphers
def char_to_num(c):
    return ord(c.upper()) - ord('A')

def num_to_char(n):
    return chr((n % 26) + ord('A'))

def encrypt_additive(plaintext, key):
    return ''.join(num_to_char((char_to_num(c) + key) % 26) if c.isalpha() else c for c in plaintext)

def decrypt_additive(ciphertext, key):
    return ''.join(num_to_char((char_to_num(c) - key) % 26) if c.isalpha() else c for c in ciphertext)

def encrypt_multiplicative(plaintext, key):
    return ''.join(num_to_char((char_to_num(c) * key) % 26) if c.isalpha() else c for c in plaintext)

def multiplicative_inverse(a, mod=26):
    # Using the extended Euclidean algorithm to find the inverse
    for i in range(1, mod):
        if (a * i) % mod == 1:
            return i
    return None

def decrypt_multiplicative(ciphertext, key):
    inverse_key = multiplicative_inverse(key)
    if inverse_key is None:
        return "No inverse exists for this key."
    return ''.join(num_to_char((char_to_num(c) * inverse_key) % 26) if c.isalpha() else c for c in ciphertext)

def encrypt_affine(plaintext, key1, key2):
    return ''.join(num_to_char((key1 * char_to_num(c) + key2) % 26) if c.isalpha() else c for c in plaintext)

def decrypt_affine(ciphertext, key1, key2):
    inverse_key1 = multiplicative_inverse(key1)
    if inverse_key1 is None:
        return "No inverse exists for this key."
    return ''.join(num_to_char((inverse_key1 * (char_to_num(c) - key2)) % 26) if c.isalpha() else c for c in ciphertext)

# Main data
plaintext = "I am learning information security".replace(" ", "")  # Ignoring spaces

# Additive Cipher with key 20
key_additive = 20
ciphertext_additive = encrypt_additive(plaintext, key_additive)
decrypted_additive = decrypt_additive(ciphertext_additive, key_additive)

# Multiplicative Cipher with key 15
key_multiplicative = 15
ciphertext_multiplicative = encrypt_multiplicative(plaintext, key_multiplicative)
decrypted_multiplicative = decrypt_multiplicative(ciphertext_multiplicative, key_multiplicative)

# Affine Cipher with keys 15 and 20
key1_affine = 15
key2_affine = 20
ciphertext_affine = encrypt_affine(plaintext, key1_affine, key2_affine)
decrypted_affine = decrypt_affine(ciphertext_affine, key1_affine, key2_affine)

# Results
print("Additive Cipher:")
print("Ciphertext:", ciphertext_additive)
print("Decrypted:", decrypted_additive)

print("\nMultiplicative Cipher:")
print("Ciphertext:", ciphertext_multiplicative)
print("Decrypted:", decrypted_multiplicative)

print("\nAffine Cipher:")
print("Ciphertext:", ciphertext_affine)
print("Decrypted:", decrypted_affine)
