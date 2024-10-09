import socket
import hashlib

def compute_hash(data):
    """Compute the SHA-256 hash of the given data."""
    return hashlib.sha256(data).hexdigest()

def start_server():
    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the address and port
    server_address = ('localhost', 65432)
    server_socket.bind(server_address)

    # Listen for incoming connections
    server_socket.listen(1)
    print("Server is listening on port 65432...")

    while True:
        # Wait for a connection
        connection, client_address = server_socket.accept()
        try:
            print(f"Connection from {client_address} established.")
            # Receive the data from the client
            data = connection.recv(1024)
            print(f"Received data: {data.decode()}")

            # Compute the hash of the received data
            data_hash = compute_hash(data)
            print(f"Computed hash: {data_hash}")

            # Send the hash back to the client
            connection.sendall(data_hash.encode())
        finally:
            connection.close()

if __name__ == "__main__":
    start_server()

'''Explanation of the Code

    Server (server.py):
        Listens on a specified port (65432).
        Accepts connections from clients.
        Receives data and computes the SHA-256 hash of the received data.
        Sends the computed hash back to the client.

    Client (client.py):
        Connects to the server.
        Sends a message to the server.
        Receives the hash from the server.
        Computes the hash of the sent message locally.
        Compares the received hash with the locally computed hash to verify data integrity.

Running the Example

    Start the Server:
        Run the server script in a terminal:

    bash

python server.py

Run the Client:

    In another terminal, run the client script:

bash

    python client.py

Testing Data Integrity

    The client will send the message "Hello, this is a secure message!" to the server.
    The server computes the hash of this message and sends it back.
    The client computes the hash locally and compares it with the hash received from the server.
    If the hashes match, it indicates that the data was transmitted without corruption. If you modify the message in the client script and run it again, you will see that the data integrity verification will fail.

Example Output

When both scripts are run without tampering, you would see output like:

Server Output:

kotlin

Server is listening on port 65432...
Connection from ('127.0.0.1', 55848) established.
Received data: Hello, this is a secure message!
Computed hash: <computed_hash_value>

Client Output:

yaml

Sent data: Hello, this is a secure message!
Received hash: <computed_hash_value>
Local computed hash: <computed_hash_value>
Data integrity verified: No tampering detected.

This demonstrates how hash functions can ensure data integrity during transmission over a network'''