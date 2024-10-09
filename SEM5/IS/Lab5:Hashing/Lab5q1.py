def custom_hash(input_string):
    # Initial hash value
    hash_value = 5381

    for char in input_string:
        # Get ASCII value of the character
        ascii_value = ord(char)

        # Update the hash value
        hash_value = (hash_value * 33) + ascii_value

        # Ensure the hash value is kept within 32-bit range
        hash_value &= 0xFFFFFFFF  # Apply the mask for 32-bit range

    return hash_value


# Example usage
if __name__ == "__main__":
    test_string = "Hello, World!"
    hash_result = custom_hash(test_string)
    print(f"The hash of '{test_string}' is: {hash_result}")

"""Explanation of the Code

    Initialization:
        The initial hash value is set to 5381.

    Iteration Over Characters:
        The function iterates over each character in the input string using a for loop.
        For each character, it retrieves the ASCII value using the ord() function.

    Hash Calculation:
        The hash value is updated by multiplying the current hash value by 33 and adding the ASCII value of the character.

    Bitwise Operations:
        The bitwise AND operation (&) with 0xFFFFFFFF is used to ensure that the hash value remains within a 32-bit range, effectively discarding any overflow.

    Return Value:
        The final computed hash value is returned."""
