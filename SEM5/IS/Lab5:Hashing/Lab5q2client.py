import socket
import hashlib

def compute_hash(data):
    """Compute the SHA-256 hash of the given data."""
    return hashlib.sha256(data).hexdigest()

def start_client(message):
    # Create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the socket to the server's address and port
    server_address = ('localhost', 65432)
    client_socket.connect(server_address)

    try:
        # Send data to the server
        client_socket.sendall(message.encode())
        print(f"Sent data: {message}")

        # Receive the hash from the server
        received_hash = client_socket.recv(64).decode()
        print(f"Received hash: {received_hash}")

        # Compute the local hash of the message
        local_hash = compute_hash(message.encode())
        print(f"Local computed hash: {local_hash}")

        # Verify the integrity of the data
        if local_hash == received_hash:
            print("Data integrity verified: No tampering detected.")
        else:
            print("Data integrity verification failed: Data may be corrupted or tampered with.")
    finally:
        client_socket.close()

if __name__ == "__main__":
    # Example message to be sent
    message = "Hello, this is a secure message!"
    start_client(message)