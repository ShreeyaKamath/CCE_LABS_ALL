#4) Use a Hill cipher to encipher the message "We live in an insecure world". Use
#the following key:
#�
#�   # =  [03 03
#02 07]



import Numpy as np



# Helper function to convert characters to numbers (A=0, B=1, ..., Z=25)
def char_to_num(c):
    return ord(c.upper()) - ord('A')


# Helper function to convert numbers to characters
def num_to_char(n):
    return chr((n % 26) + ord('A'))


# Encrypt a 2x1 matrix (pair of letters) using the 2x2 Hill cipher key matrix
def encrypt_hill_block(block, key_matrix):
    # Convert the block into a column vector of numbers
    vector = np.array([[char_to_num(block[0])], [char_to_num(block[1])]])

    # Perform matrix multiplication (mod 26)
    result_vector = np.dot(key_matrix, vector) % 26

    # Convert the result back to characters
    return num_to_char(result_vector[0][0]) + num_to_char(result_vector[1][0])


# Prepare the plaintext by removing spaces and padding if necessary
def prepare_plaintext(plaintext):
    plaintext = plaintext.replace(" ", "").upper()  # Remove spaces and convert to uppercase
    if len(plaintext) % 2 != 0:  # If length is odd, add a filler letter (e.g., 'X')
        plaintext += 'X'
    return plaintext


# Encrypt the entire message using Hill cipher
def encrypt_hill_cipher(plaintext, key_matrix):
    plaintext = prepare_plaintext(plaintext)
    ciphertext = ""

    # Process each pair of letters (2 characters at a time)
    for i in range(0, len(plaintext), 2):
        ciphertext += encrypt_hill_block(plaintext[i:i + 2], key_matrix)

    return ciphertext


# Define the 2x2 Hill cipher key matrix
key_matrix = np.array([[3, 3], [2, 7]])

# Main data
plaintext = "We live in an insecure world"

# Encrypt using Hill cipher
ciphertext = encrypt_hill_cipher(plaintext, key_matrix)
print("Ciphertext:", ciphertext)