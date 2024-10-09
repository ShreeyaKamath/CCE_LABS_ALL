#3) Use the Playfair cipher to encipher the message "The key is hidden under the
#door pad". The secret key can be made by filling the first and part of the second
#row with the word "GUIDANCE" and filling the rest of the matrix with the
#rest of the alphabet.




import string


# Helper functions for Playfair cipher
def create_playfair_matrix(key):
    matrix = []
    key = "".join(dict.fromkeys(key.upper().replace("J", "I")))  # Remove duplicates and treat 'I' and 'J' as the same
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    used_letters = set(key)

    # Fill the matrix with the key letters first
    for letter in key:
        if letter not in matrix:
            matrix.append(letter)

    # Fill the remaining spaces with the rest of the alphabet
    for letter in alphabet:
        if letter not in used_letters:
            matrix.append(letter)

    # Convert the flat list to a 5x5 matrix
    return [matrix[i:i + 5] for i in range(0, len(matrix), 5)]


def find_position(matrix, letter):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == letter:
                return row, col
    return None


def encrypt_pair(matrix, a, b):
    row_a, col_a = find_position(matrix, a)
    row_b, col_b = find_position(matrix, b)

    if row_a == row_b:  # Same row, move to the right
        return matrix[row_a][(col_a + 1) % 5] + matrix[row_b][(col_b + 1) % 5]
    elif col_a == col_b:  # Same column, move down
        return matrix[(row_a + 1) % 5][col_a] + matrix[(row_b + 1) % 5][col_b]
    else:  # Rectangle swap
        return matrix[row_a][col_b] + matrix[row_b][col_a]


def prepare_input(plaintext):
    plaintext = plaintext.upper().replace("J", "I").replace(" ", "")
    prepared = ""
    i = 0
    while i < len(plaintext):
        a = plaintext[i]
        if i + 1 < len(plaintext):
            b = plaintext[i + 1]
        else:
            b = 'X'

        if a == b:
            prepared += a + 'X'
            i += 1
        else:
            prepared += a + b
            i += 2

    if len(prepared) % 2 == 1:
        prepared += 'X'

    return prepared


def encrypt_playfair(plaintext, key):
    matrix = create_playfair_matrix(key)
    print("Playfair Matrix:")
    for row in matrix:
        print(row)

    plaintext = prepare_input(plaintext)
    ciphertext = ""

    for i in range(0, len(plaintext), 2):
        ciphertext += encrypt_pair(matrix, plaintext[i], plaintext[i + 1])

    return ciphertext


# Main data
plaintext = "The key is hidden under the door pad"
key = "GUIDANCE"

# Encrypt using Playfair cipher
ciphertext = encrypt_playfair(plaintext, key)
print("\nCiphertext:", ciphertext)