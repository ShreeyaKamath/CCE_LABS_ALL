from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import time
import matplotlib.pyplot as plt

# Set up the messages
messages = [
    b"This is the first message.",
    b"Second message for encryption.",
    b"Third message goes here.",
    b"Fourth message, almost done.",
    b"Final message to finish."
]

# Keys for AES (must be 16, 24, or 32 bytes)
aes_keys = {
    128: get_random_bytes(16),   # 128 bits
    192: get_random_bytes(24),   # 192 bits
    256: get_random_bytes(32)    # 256 bits
}

# DES Key (must be 8 bytes)
des_key = get_random_bytes(8)

# Different modes of operation for AES
modes = {
    "ECB": AES.MODE_ECB,
    "CBC": AES.MODE_CBC,
    "CFB": AES.MODE_CFB,
    "OFB": AES.MODE_OFB
}

# Initialize lists to store execution times
aes_times = {key: [] for key in aes_keys.keys()}
des_times = []

# Encrypt messages with DES
for message in messages:
    start_time = time.time()
    cipher = DES.new(des_key, DES.MODE_ECB)
    encrypted_message = cipher.encrypt(pad(message, DES.block_size))
    des_times.append(time.time() - start_time)

# Encrypt messages with AES
for key_size, key in aes_keys.items():
    for mode_name, mode in modes.items():
        times = []
        for message in messages:
            start_time = time.time()
            if mode == AES.MODE_CBC:
                cipher = AES.new(key, mode, iv=get_random_bytes(AES.block_size))
            else:
                cipher = AES.new(key, mode)
            encrypted_message = cipher.encrypt(pad(message, AES.block_size))
            times.append(time.time() - start_time)
        aes_times[key_size].append(sum(times) / len(times))  # Average time

# Plotting the results
x_labels = ['DES', 'AES-128', 'AES-192', 'AES-256']
execution_times = [sum(des_times) / len(des_times)] + [aes_times[key][0] for key in aes_keys.keys()]

plt.figure(figsize=(10, 5))
plt.bar(x_labels, execution_times, color=['blue', 'green', 'orange', 'red'])
plt.title('Execution Time for Encryption (DES vs AES)')
plt.ylabel('Execution Time (seconds)')
plt.xlabel('Encryption Technique')
plt.grid(axis='y')

# Show the plot
plt.show()
