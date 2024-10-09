import time
from Crypto.Random import random
from Crypto.Util.number import getPrime, GCD

# Diffie-Hellman parameters: a large prime p and base g
def generate_dh_parameters(bits=2048):
    p = getPrime(bits)  # Generate a large prime p
    g = 2               # Use a small base g (2 is common)
    return p, g

# Each peer generates a private key and corresponding public key
def generate_dh_keypair(p, g):
    # Generate private key (a random number less than p)
    private_key = random.randint(2, p - 2)

    # Compute public key (g^private_key mod p)
    public_key = pow(g, private_key, p)

    return private_key, public_key

# Each peer computes the shared secret using their private key and the other peer's public key
def compute_shared_secret(private_key, peer_public_key, p):
    # Shared secret: (peer_public_key^private_key mod p)
    shared_secret = pow(peer_public_key, private_key, p)
    return shared_secret

# Main function to perform the Diffie-Hellman key exchange and measure performance
def diffie_hellman_key_exchange(bits=2048):
    # Step 1: Generate Diffie-Hellman parameters (prime p and base g)
    p, g = generate_dh_parameters(bits)

    # Step 2: Key generation for peer 1
    start_time = time.time()
    private_key1, public_key1 = generate_dh_keypair(p, g)
    keygen_time_peer1 = time.time() - start_time

    # Step 3: Key generation for peer 2
    start_time = time.time()
    private_key2, public_key2 = generate_dh_keypair(p, g)
    keygen_time_peer2 = time.time() - start_time

    # Step 4: Peer 1 computes the shared secret using its private key and Peer 2's public key
    start_time = time.time()
    shared_secret1 = compute_shared_secret(private_key1, public_key2, p)
    key_exchange_time_peer1 = time.time() - start_time

    # Step 5: Peer 2 computes the shared secret using its private key and Peer 1's public key
    start_time = time.time()
    shared_secret2 = compute_shared_secret(private_key2, public_key1, p)
    key_exchange_time_peer2 = time.time() - start_time

    # Check if both peers computed the same shared secret
    assert shared_secret1 == shared_secret2, "Shared secrets do not match!"

    # Step 6: Print results and performance metrics
    print("\nDiffie-Hellman Key Exchange ({}-bit)".format(bits))
    print("Peer 1 - Private Key: ", private_key1)
    print("Peer 1 - Public Key:  ", public_key1)
    print("Peer 2 - Private Key: ", private_key2)
    print("Peer 2 - Public Key:  ", public_key2)
    print("\nShared Secret:       ", shared_secret1)

    print("\nPerformance Metrics:")
    print("Key Generation Time (Peer 1): {:.6f} seconds".format(keygen_time_peer1))
    print("Key Generation Time (Peer 2): {:.6f} seconds".format(keygen_time_peer2))
    print("Key Exchange Time (Peer 1):   {:.6f} seconds".format(key_exchange_time_peer1))
    print("Key Exchange Time (Peer 2):   {:.6f} seconds".format(key_exchange_time_peer2))

# Run the Diffie-Hellman Key Exchange and measure performance
diffie_hellman_key_exchange(2048)