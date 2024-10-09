# Use a brute-force attack to decipher the following message. Assume that you
#know it is an affine cipher and that the plaintext "ab" is enciphered to "GL":



def mod_inverse(a, m):
    """ Return the modular inverse of a under modulo m using Extended Euclidean Algorithm """
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def affine_decrypt(ciphertext, a, b):
    """ Decrypt the ciphertext using the affine cipher decryption formula """
    decrypted = ""
    for char in ciphertext:
        if char.isalpha():  # Check if character is an alphabet
            y = ord(char) - ord('A')  # Convert to number
            a_inv = mod_inverse(a, 26)  # Get modular inverse of a
            if a_inv is not None:
                x = (a_inv * (y - b)) % 26  # Apply decryption formula
                decrypted += chr(x + ord('A'))  # Convert back to character
            else:
                decrypted += char  # In case of invalid a
        else:
            decrypted += char  # Non-alphabet characters remain unchanged
    return decrypted

# Given ciphertext
ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"

# Brute-force attack
for a in range(1, 26):  # a can be from 1 to 25
    for b in range(26):  # b can be from 0 to 25
        decrypted_text = affine_decrypt(ciphertext, a, b)
        print(f"a: {a}, b: {b} -> Decrypted: {decrypted_text}")