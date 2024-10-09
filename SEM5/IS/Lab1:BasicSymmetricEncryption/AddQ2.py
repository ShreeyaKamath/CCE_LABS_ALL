#2. Eve secretly gets access to Alice's computer and using her cipher types
#"abcdefghi". The screen shows "CABDEHFGL". If Eve knows that Alice is using
#a keyed transposition cipher, answer the following questions:
#a) What type of attack is Eve launching?
#b) What is the size of the permutation key?
#c) Use the Vigenere cipher with keyword "HEALTH" to encipher the
#message "Life is full of surprises".




# Vigenère Cipher - Encryption Function
def vigenere_encrypt(plaintext, keyword):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    keyword = keyword.upper()
    plaintext = plaintext.upper().replace(" ", "")  # Remove spaces and capitalize

    encrypted_text = []
    keyword_repeated = (keyword * (len(plaintext) // len(keyword))) + keyword[:len(plaintext) % len(keyword)]

    for i in range(len(plaintext)):
        if plaintext[i].isalpha():
            letter_index = (alphabet.index(plaintext[i]) + alphabet.index(keyword_repeated[i])) % 26
            encrypted_text.append(alphabet[letter_index])
        else:
            encrypted_text.append(plaintext[i])  # Non-alphabetic characters are left unchanged

    return ''.join(encrypted_text)


# Encrypting the message
plaintext = "Life is full of surprises"
keyword = "HEALTH"

encrypted_message = vigenere_encrypt(plaintext, keyword)
print("Encrypted Message:", encrypted_message)
