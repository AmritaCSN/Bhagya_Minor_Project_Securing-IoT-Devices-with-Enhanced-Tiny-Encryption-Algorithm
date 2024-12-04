import time
import psutil
import hashlib
import os

# Function to compute SHA-256 hash and split into two 128-bit halves
def compute_sha256_hash(data):
    hash_object = hashlib.sha256(data.encode('utf-8'))
    hash_bytes = hash_object.digest()
    return hash_bytes[:16], hash_bytes[16:]  # First and second 128-bit halves

# # Function to XOR 32-bit hash segments with the original key
def xor_with_key(hash_segments, original_keys):
    return [
        (int.from_bytes(hash_segments[i], 'big') if isinstance(hash_segments[i], (bytes, bytearray)) else hash_segments[i])
        ^
        (int.from_bytes(original_keys[i], 'big') if isinstance(original_keys[i], (bytes, bytearray)) else original_keys[i])
        for i in range(len(hash_segments))
    ]

# Enhanced TEA encryption 
def enhanced_tea_encrypt(plaintext_block, key, round_keys_store):
    L0 = int.from_bytes(plaintext_block[:4], 'big')
    R0 = int.from_bytes(plaintext_block[4:], 'big')

    k0 = int.from_bytes(key[:4], 'big')
    k1 = int.from_bytes(key[4:8], 'big')
    k2 = int.from_bytes(key[8:12], 'big')
    k3 = int.from_bytes(key[12:], 'big')

    delta = 0x9e3779b9
    sum = 0

    hash_value1, hash_value2 = compute_sha256_hash(plaintext_block.decode(errors='ignore'))
    first_half_segments = [hash_value1[i:i+4] for i in range(0, 16, 4)]
    second_half_segments = [hash_value2[i:i+4] for i in range(0, 16, 4)]

    for i in range(32):
        if i % 2 == 0:
            # Use first 128-bit hash for even rounds
            key_segments = xor_with_key(first_half_segments, [k0, k1, k2, k3])
        else:
            # Use second 128-bit hash for odd rounds
            key_segments = xor_with_key(second_half_segments, [k0, k1, k2, k3])

        round_keys_store.append(key_segments)  # Store key segments for decryption

        sum = (sum + delta) & 0xffffffff
        L0 = (L0 + (((R0 << 4) + key_segments[0]) ^ (R0 + sum) ^ ((R0 >> 5) + key_segments[1]))) & 0xffffffff
        R0 = (R0 + (((L0 << 4) + key_segments[2]) ^ (L0 + sum) ^ ((L0 >> 5) + key_segments[3]))) & 0xffffffff

    ciphertext_block = L0.to_bytes(4, 'big') + R0.to_bytes(4, 'big')
    return ciphertext_block

# Function to calculate the Hamming distance between two binary strings
def hamming_distance(bin1, bin2):
    """Calculate the Hamming Distance between two binary strings."""
    return sum(b1 != b2 for b1, b2 in zip(bin1, bin2))

# Avalanche Effect Test
def avalanche_effect_test(key, plaintext, bit_position):
    # Ensure plaintext is 8 bytes (block size)
    if len(plaintext) < 8:
        plaintext = plaintext.ljust(8, b'\x00')
    
    # Encrypt original plaintext
    round_keys_store = []
    original_ciphertext = enhanced_tea_encrypt(plaintext, key, round_keys_store)
    
    # Flip a single bit in the plaintext
    modified_plaintext = bytearray(plaintext)
    modified_plaintext[bit_position // 8] ^= (1 << (bit_position % 8))  # Flip bit
    
    # Encrypt modified plaintext
    modified_round_keys_store = []
    modified_ciphertext = enhanced_tea_encrypt(bytes(modified_plaintext), key, modified_round_keys_store)
    
    # Convert ciphertexts to binary
    original_binary = ''.join(f"{byte:08b}" for byte in original_ciphertext)
    modified_binary = ''.join(f"{byte:08b}" for byte in modified_ciphertext)
    
    # Compute Hamming distance
    flipped_bits = hamming_distance(original_binary, modified_binary)
    total_bits = len(original_binary)
    avalanche_percentage = (flipped_bits / total_bits) * 100
    
    return flipped_bits, avalanche_percentage

# Example usage
key = b"0123456789abcdef"  # 16-byte key
plaintext = b"For a high avalanche effect (like 56%), it's critical that the encryption or hashing algorithm behaves randomly and diffusely. A small change in the input should cause a significant change in the output. To determine the avalanche effect, flip each bit in the input data one at a time and check how many bits in the output change. Since the goal is to get 56 of the bits flipped in the output, find which input bit flip causes the output to have around 36 flipped bit"  # Example plaintext block
bit_position = 3  # Position of the bit to flip (0-indexed)

# Performing the avalanche effect test
flipped_bits, avalanche_percentage = avalanche_effect_test(key, plaintext, bit_position)
print(f"Flipped Bits: {flipped_bits}")
print(f"Avalanche Effect: {avalanche_percentage:.2f}%")

# Test with different bit positions
for bit_position in range(64):  # Testing all 64 bits of an 8-byte block
    flipped_bits, avalanche_percentage = avalanche_effect_test(key, plaintext, bit_position)
    print(f"Bit Position: {bit_position}, Flipped Bits: {flipped_bits}, Avalanche Effect: {avalanche_percentage:.2f}%")
