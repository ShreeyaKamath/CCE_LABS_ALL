from Crypto.Cipher import DES
import binascii

def pad_data(data):
    """Pad the data to ensure it is a multiple of 8 bytes for DES."""
    while len(data) % 8 != 0:
        data += b'\x00'  # Padding with null bytes
    return data

def encrypt_des(key, data):
    """Encrypt the given data using DES with the provided key."""
    des = DES.new(key, DES.MODE_ECB)
    encrypted_data = des.encrypt(data)
    return encrypted_data

def decrypt_des(key, encrypted_data):
    """Decrypt the given encrypted data using DES with the provided key."""
    des = DES.new(key, DES.MODE_ECB)
    decrypted_data = des.decrypt(encrypted_data)
    return decrypted_data

# Key and data preparation
key_hex = "A1B2C3D4E5F60708"
key = binascii.unhexlify(key_hex)  # Convert the key from hex to bytes

# Block 1
block1_hex = "54686973206973206120636f6e666964656e7469616c206d657373616765"
block1_data = binascii.unhexlify(block1_hex)  # Convert from hex to bytes
block1_data = pad_data(block1_data)  # Pad the data if necessary

# Block 2
block2_hex = "416e64207468697320697320746865207365636f6e6420626c6f636b"
block2_data = binascii.unhexlify(block2_hex)  # Convert from hex to bytes
block2_data = pad_data(block2_data)  # Pad the data if necessary

# Encrypt both blocks
ciphertext_block1 = encrypt_des(key, block1_data)
ciphertext_block2 = encrypt_des(key, block2_data)

# Decrypt the ciphertext
decrypted_block1 = decrypt_des(key, ciphertext_block1)
decrypted_block2 = decrypt_des(key, ciphertext_block2)

# Convert ciphertext and decrypted data to hex for readability
ciphertext_block1_hex = binascii.hexlify(ciphertext_block1).decode('utf-8')
ciphertext_block2_hex = binascii.hexlify(ciphertext_block2).decode('utf-8')

# Convert decrypted data back to string (remove padding)
decrypted_block1_str = decrypted_block1.rstrip(b'\x00').decode('utf-8')
decrypted_block2_str = decrypted_block2.rstrip(b'\x00').decode('utf-8')

# Display results
print("Block 1 Ciphertext (Hex):", ciphertext_block1_hex)
print("Block 1 Decrypted Plaintext:", decrypted_block1_str)
print("Block 2 Ciphertext (Hex):", ciphertext_block2_hex)
print("Block 2 Decrypted Plaintext:", decrypted_block2_str)