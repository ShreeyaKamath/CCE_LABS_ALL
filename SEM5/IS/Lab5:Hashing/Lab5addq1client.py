import socket
import hashlib

def compute_hash(data):
    """Compute the SHA-256 hash of the given data."""
    return hashlib.sha256(data.encode()).hexdigest()

def main():
    # Create a socket for the client
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 65432))  # Connect to the server

    # The message to be sent to the server
    message = "This is a test message that will be sent in multiple parts."
    parts = [message[i:i+10] for i in range(0, len(message), 10)]  # Split message into parts of 10 characters

    # Send message parts to the server
    for part in parts:
        print(f"Sending part: {part}")
        client_socket.send(part.encode())

    # Close the connection after sending all parts
    client_socket.shutdown(socket.SHUT_WR)

    # Receive the hash from the server
    received_hash = client_socket.recv(1024).decode()
    print(f"Received hash from server: {received_hash}")

    # Compute the hash of the original message locally
    original_hash = compute_hash(message)
    print(f"Computed local hash: {original_hash}")

    # Verify the integrity of the message
    if received_hash == original_hash:
        print("Message integrity verified!")
    else:
        print("Message integrity check failed!")

    client_socket.close()  # Close the socket

if __name__ == "__main__":
    main()