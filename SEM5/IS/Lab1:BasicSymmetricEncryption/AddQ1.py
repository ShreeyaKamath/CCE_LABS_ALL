
# Use a brute-force attack to decipher the following message enciphered by Alice using an additive cipher. Suppose that Alice always uses a key that is close to her
#birthday, which is on the 13th of the month:
#NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY


def decrypt_additive_cipher(ciphertext, key):
    """ Decrypt the ciphertext using an additive cipher with a given key. """
    decrypted = ""
    for char in ciphertext:
        if char.isalpha():  # Check if the character is an alphabet
            # Convert char to number, A=0, ..., Z=25
            y = ord(char) - ord('A')
            # Apply decryption formula: D(y) = (y - k) % 26
            x = (y - key) % 26
            decrypted += chr(x + ord('A'))  # Convert back to character
        else:
            decrypted += char  # Non-alphabet characters remain unchanged
    return decrypted

# Given ciphertext
ciphertext = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"

# Brute-force attack for keys close to 13 (11, 12, 13, 14, 15)
for key in range(11, 16):
    decrypted_text = decrypt_additive_cipher(ciphertext, key)
    print(f"Key: {key} -> Decrypted: {decrypted_text}")