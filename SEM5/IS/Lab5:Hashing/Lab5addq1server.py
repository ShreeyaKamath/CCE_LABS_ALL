import socket
import hashlib

def compute_hash(data):
    """Compute the SHA-256 hash of the given data."""
    return hashlib.sha256(data.encode()).hexdigest()

def main():
    # Create a socket for the server
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65432))  # Bind to the localhost and port 65432
    server_socket.listen()

    print("Server is listening for incoming connections...")
    conn, addr = server_socket.accept()  # Accept a connection
    print(f"Connection established with {addr}")

    # Reassemble message parts
    message_parts = []
    while True:
        part = conn.recv(1024).decode()  # Receive data in parts
        if "<END>" in part:  # Look for end of message signal
            message_parts.append(part.replace("<END>", ""))  # Remove the end signal
            break
        message_parts.append(part)

    # Join all parts to reconstruct the original message
    complete_message = ''.join(message_parts)
    print(f"Reassembled message: {complete_message}")

    # Compute the hash of the complete message
    message_hash = compute_hash(complete_message)
    print(f"Computed hash: {message_hash}")

    # Send the computed hash back to the client
    conn.send(message_hash.encode())
    conn.close()  # Close the connection

if __name__ == "__main__":
    main()
