from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
import binascii

# AES-256 Encryption and Decryption
def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)  # Use ECB mode
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))  # Pad the plaintext
    return ciphertext

def aes_decrypt(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)  # Unpad after decryption
    return decrypted

# DES Encryption and Decryption in CBC Mode
def des_encrypt(key, plaintext, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))  # Pad the plaintext
    return ciphertext

def des_decrypt(key, ciphertext, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ciphertext), DES.block_size)  # Unpad after decryption
    return decrypted

# AES-256 example
aes_key = b'0123456789ABCDEF0123456789ABCDEF'  # 32 bytes key for AES-256
aes_plaintext = b'Encryption Strength'  # Message to encrypt

# AES Encryption
aes_ciphertext = aes_encrypt(aes_key, aes_plaintext)
aes_ciphertext_hex = binascii.hexlify(aes_ciphertext).decode('utf-8')

# AES Decryption
aes_decrypted = aes_decrypt(aes_key, aes_ciphertext)

# Display AES results
print("AES-256 Ciphertext (Hex):", aes_ciphertext_hex)
print("AES-256 Decrypted Plaintext:", aes_decrypted.decode('utf-8'))

# DES example
des_key = b'A1B2C3D4'  # 8 bytes key for DES
des_iv = b'12345678'  # 8 bytes IV
des_plaintext = b'Secure Communication'  # Message to encrypt

# DES Encryption
des_ciphertext = des_encrypt(des_key, des_plaintext, des_iv)
des_ciphertext_hex = binascii.hexlify(des_ciphertext).decode('utf-8')

# DES Decryption
des_decrypted = des_decrypt(des_key, des_ciphertext, des_iv)

# Display DES results
print("DES Ciphertext (Hex):", des_ciphertext_hex)
print("DES Decrypted Plaintext:", des_decrypted.decode('utf-8'))