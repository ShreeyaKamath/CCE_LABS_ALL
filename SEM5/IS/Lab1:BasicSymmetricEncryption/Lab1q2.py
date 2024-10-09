#2) Encrypt the message "the house is being sold tonight" using one of the
#following ciphers. Ignore the space between words. Decrypt the message to
#get the original plaintext:
#a) Vigenere cipher with key: "dollars"
#b) Autokey cipher with key = 7


# Helper functions for Vigenère and Autokey cipher
def char_to_num(c):
    return ord(c.upper()) - ord('A')

def num_to_char(n):
    return chr((n % 26) + ord('A'))

def repeat_key_to_length(key, length):
    return (key * (length // len(key))) + key[:length % len(key)]

# Vigenère Cipher
def encrypt_vigenere(plaintext, key):
    key = repeat_key_to_length(key, len(plaintext)).upper()
    return ''.join(num_to_char((char_to_num(p) + char_to_num(k)) % 26) if p.isalpha() else p
                   for p, k in zip(plaintext, key))

def decrypt_vigenere(ciphertext, key):
    key = repeat_key_to_length(key, len(ciphertext)).upper()
    return ''.join(num_to_char((char_to_num(c) - char_to_num(k)) % 26) if c.isalpha() else c
                   for c, k in zip(ciphertext, key))

# Autokey Cipher
def encrypt_autokey(plaintext, key):
    # Start with the initial key (integer value)
    key_stream = [key] + [char_to_num(p) for p in plaintext[:-1]]
    return ''.join(num_to_char((char_to_num(p) + k) % 26) for p, k in zip(plaintext, key_stream))

def decrypt_autokey(ciphertext, key):
    plaintext = []
    key_stream = [key]
    for c in ciphertext:
        p = (char_to_num(c) - key_stream[-1]) % 26
        plaintext.append(num_to_char(p))
        key_stream.append(p)  # Use the decrypted plaintext as part of the key stream
    return ''.join(plaintext)

# Main data
plaintext = "thehouseisbeingsoldtonight".replace(" ", "").upper()  # Ignoring spaces and converting to uppercase

# Vigenère Cipher with key "dollars"
key_vigenere = "dollars"
ciphertext_vigenere = encrypt_vigenere(plaintext, key_vigenere)
decrypted_vigenere = decrypt_vigenere(ciphertext_vigenere, key_vigenere)

# Autokey Cipher with key = 7
key_autokey = 7
ciphertext_autokey = encrypt_autokey(plaintext, key_autokey)
decrypted_autokey = decrypt_autokey(ciphertext_autokey, key_autokey)

# Printing the results
print("Vigenère Cipher:")
print("Ciphertext:", ciphertext_vigenere)
print("Decrypted:", decrypted_vigenere)

print("\nAutokey Cipher:")
print("Ciphertext:", ciphertext_autokey)
print("Decrypted:", decrypted_autokey)