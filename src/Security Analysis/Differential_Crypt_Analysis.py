import hashlib
import random
from collections import defaultdict

# Function to compute SHA-256 hash 
def compute_sha256_hash(plaintext):
    hash_obj = hashlib.sha256(plaintext.encode())
    full_hash = hash_obj.digest()
    return full_hash[:16], full_hash[16:]

# XOR function for key segments
def xor_with_key(hash_segments, key_segments):
    return [int.from_bytes(hash_seg, 'big') ^ key_seg for hash_seg, key_seg in zip(hash_segments, key_segments)]

# Enhanced TEA encryption 
def enhanced_tea_encrypt(plaintext_block, key):
    v0 = int.from_bytes(plaintext_block[:4], 'big')
    v1 = int.from_bytes(plaintext_block[4:], 'big')

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

        sum = (sum + delta) & 0xffffffff
        v0 = (v0 + (((v1 << 4) + key_segments[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key_segments[1]))) & 0xffffffff
        v1 = (v1 + (((v0 << 4) + key_segments[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key_segments[3]))) & 0xffffffff

    ciphertext_block = v0.to_bytes(4, 'big') + v1.to_bytes(4, 'big')
    return ciphertext_block

# Function to generate plaintext pairs with a fixed difference
def generate_plaintext_pairs(base_plaintext, difference, count):
    plaintext_pairs = []
    for _ in range(count):
        new_plaintext = base_plaintext ^ difference  # Fixed difference
        plaintext_pairs.append((base_plaintext, new_plaintext))
        base_plaintext = random.randint(0, (1 << 64) - 1)  # Randomize base plaintext
    return plaintext_pairs

# Differential Analysis (Fixed Difference)
def differential_analysis(key, input_difference, pair_count):
    differential_table = defaultdict(int)
    plaintext_pairs = generate_plaintext_pairs(random.randint(0, (1 << 64) - 1), input_difference, pair_count)

    for p1, p2 in plaintext_pairs:
        c1 = enhanced_tea_encrypt(p1.to_bytes(8, 'big'), key)
        c2 = enhanced_tea_encrypt(p2.to_bytes(8, 'big'), key)
        output_difference = int.from_bytes(c1, 'big') ^ int.from_bytes(c2, 'big')
        differential_table[output_difference] += 1

    return differential_table

# Main Function
def main():
    key = b'0123456789abcdef'  # 16-byte key for TEA
    input_difference = 0x00000001  # Fixed input difference
    pair_count = 1000 
    print(f"Performing differential cryptanalysis with input difference: {input_difference:#0{10}x}")
    results = differential_analysis(key, input_difference, pair_count)

    # Output the results
    print("Output Differences and Their Frequencies:")
    for output_diff, count in sorted(results.items(), key=lambda x: -x[1]):
        print(f"Output Difference: {output_diff:#0{10}x}, Count: {count}")

if __name__ == "__main__":
    main()
