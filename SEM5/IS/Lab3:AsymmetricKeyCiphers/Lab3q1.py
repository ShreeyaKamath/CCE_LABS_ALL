from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import bytes_to_long, long_to_bytes

# Generate RSA keys (for demonstration purposes, you can replace with actual values)
def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    private_key = key
    public_key = key.publickey()
    return public_key, private_key

# RSA encryption using public key (n, e)
def rsa_encrypt(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message)
    return ciphertext

# RSA decryption using private key (n, d)
def rsa_decrypt(private_key, ciphertext):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(ciphertext)
    return decrypted_message

# Generate RSA key pair
public_key, private_key = generate_rsa_keypair()

# Message to encrypt
message = b'Asymmetric Encryption'

# Encrypt the message
ciphertext = rsa_encrypt(public_key, message)

# Decrypt the ciphertext
decrypted_message = rsa_decrypt(private_key, ciphertext)

# Display results
print("Ciphertext (Hex):", ciphertext.hex())
print("Decrypted Plaintext:", decrypted_message.decode('utf-8'))
