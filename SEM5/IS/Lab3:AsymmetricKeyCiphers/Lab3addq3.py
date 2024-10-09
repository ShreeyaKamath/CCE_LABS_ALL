# Function to convert a string message into its numeric representation
def string_to_int(message):
    return int.from_bytes(message.encode(), 'big')


# Function to convert a numeric value back into a string message
def int_to_string(number):
    # Convert the integer to bytes
    byte_length = (number.bit_length() + 7) // 8
    byte_array = number.to_bytes(byte_length, 'big')

    # Attempt to decode the bytes to a string
    try:
        return byte_array.decode('utf-8')
    except UnicodeDecodeError:
        # Handle cases where the byte array cannot be decoded
        print("Decryption resulted in invalid byte sequence.")
        return ""


# RSA encryption function
def rsa_encrypt(message, n, e):
    message_int = string_to_int(message)  # Convert message to integer
    ciphertext = pow(message_int, e, n)  # Compute ciphertext = (message^e) % n
    return ciphertext


# RSA decryption function
def rsa_decrypt(ciphertext, n, d):
    decrypted_int = pow(ciphertext, d, n)  # Compute decrypted message = (ciphertext^d) % n
    decrypted_message = int_to_string(decrypted_int)  # Convert integer back to string
    return decrypted_message


# RSA parameters (n, e) for encryption and (n, d) for decryption
n = 323
e = 5
d = 173

# Shortened message to fit the small n value
message = "Crypto"

# Step 1: Encrypt the message using the public key (n, e)
ciphertext = rsa_encrypt(message, n, e)
print("Encrypted Ciphertext:", ciphertext)

# Step 2: Decrypt the ciphertext using the private key (n, d)
decrypted_message = rsa_decrypt(ciphertext, n, d)
print("Decrypted Message:", decrypted_message)
