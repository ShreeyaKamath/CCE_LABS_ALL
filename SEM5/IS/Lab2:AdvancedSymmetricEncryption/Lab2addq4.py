from Crypto.Cipher import AES
from Crypto.Util import Counter
import binascii

def aes_ctr_encrypt(key, plaintext, nonce):
    """Encrypt the plaintext using AES in CTR mode."""
    # Create a counter with the nonce
    ctr = Counter.new(64, prefix=nonce[:8], initial_value=0)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    ciphertext = cipher.encrypt(plaintext)  # Encrypt the plaintext
    return ciphertext

def aes_ctr_decrypt(key, ciphertext, nonce):
    """Decrypt the ciphertext using AES in CTR mode."""
    ctr = Counter.new(64, prefix=nonce[:8], initial_value=0)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    decrypted = cipher.decrypt(ciphertext)  # Decrypt the ciphertext
    return decrypted

# Key and message preparation
aes_key = b'0123456789ABCDEF0123456789ABCDEF'[:32]  # 32-byte key for AES-256
plaintext = b'Cryptography Lab Exercise'  # Message to encrypt
nonce = b'0000000000000000'[:16]  # 16-byte nonce (first 8 bytes used for the prefix)

# Encrypt the message
ciphertext = aes_ctr_encrypt(aes_key, plaintext, nonce)
ciphertext_hex = binascii.hexlify(ciphertext).decode('utf-8')

# Decrypt the ciphertext
decrypted_message = aes_ctr_decrypt(aes_key, ciphertext, nonce)

# Display results
print("Ciphertext (Hex):", ciphertext_hex)
print("Decrypted Plaintext:", decrypted_message.decode('utf-8'))
