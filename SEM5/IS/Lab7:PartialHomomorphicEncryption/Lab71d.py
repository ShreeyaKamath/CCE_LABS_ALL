import random
import time
import math


class ElGamal:
    def __init__(self, p=None, g=None):
        self.p = p if p else self.generate_prime()
        self.g = g if g else random.randint(2, self.p - 2)
        self.x = random.randint(1, self.p - 2)  # Private key
        self.y = pow(self.g, self.x, self.p)  # Public key

    def generate_prime(self, bits=8):
        """Generate a small prime number for testing."""
        while True:
            num = random.getrandbits(bits)
            if self.is_prime(num):
                return num

    def is_prime(self, n):
        """Check if n is a prime number."""
        if n <= 1:
            return False
        for i in range(2, int(math.sqrt(n)) + 1):
            if n % i == 0:
                return False
        return True

    def encrypt(self, m):
        """Encrypt the message m using ElGamal encryption."""
        k = random.randint(1, self.p - 2)
        c1 = pow(self.g, k, self.p)
        c2 = (m * pow(self.y, k, self.p)) % self.p
        return (c1, c2)


class Paillier:
    def __init__(self, bits=8):
        self.p = self.generate_prime(bits)
        self.q = self.generate_prime(bits)
        self.n = self.p * self.q
        self.n2 = self.n * self.n
        self.g = self.n + 1
        self.lambda_n = (self.p - 1) * (self.q - 1) // math.gcd(self.p - 1, self.q - 1)

    def generate_prime(self, bits):
        """Generate a small prime number for testing."""
        while True:
            num = random.getrandbits(bits)
            if self.is_prime(num):
                return num

    def is_prime(self, n):
        """Check if n is a prime number."""
        if n <= 1:
            return False
        for i in range(2, int(math.sqrt(n)) + 1):
            if n % i == 0:
                return False
        return True

    def encrypt(self, m):
        """Encrypt a message m."""
        r = random.randint(1, self.n - 1)
        ciphertext = (pow(self.g, m, self.n2) * pow(r, self.n, self.n2)) % self.n2
        return ciphertext


def performance_analysis():
    elgamal = ElGamal()
    paillier = Paillier()

    # Performance with ElGamal
    start_time = time.time()
    for i in range(100):
        elgamal.encrypt(i)
    elgamal_time = time.time() - start_time

    print(f"ElGamal Encryption Time for 100 messages: {elgamal_time:.6f} seconds")

    # Performance with Paillier
    start_time = time.time()
    for i in range(100):
        paillier.encrypt(i)
    paillier_time = time.time() - start_time

    print(f"Paillier Encryption Time for 100 messages: {paillier_time:.6f} seconds")


if __name__ == "__main__":
    performance_analysis()