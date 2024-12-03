import time
import psutil
import hashlib
import os

# Function to compute SHA-256 hash
def compute_sha256_hash(plaintext):
    hash_obj = hashlib.sha256(plaintext.encode())
    full_hash = hash_obj.digest()
    return full_hash[:16], full_hash[16:]

# XOR function for key segments
def xor_with_key(hash_segments, key_segments):
    return [int.from_bytes(hash_seg, 'big') ^ key_seg for hash_seg, key_seg in zip(hash_segments, key_segments)]

# Enhanced TEA encryption with dynamic key scheduling and key storage for decryption
def enhanced_tea_encrypt(plaintext_block, key, round_keys_store):
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

        round_keys_store.append(key_segments)  # Store key segments for decryption

        sum = (sum + delta) & 0xffffffff
        v0 = (v0 + (((v1 << 4) + key_segments[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key_segments[1]))) & 0xffffffff
        v1 = (v1 + (((v0 << 4) + key_segments[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key_segments[3]))) & 0xffffffff

    ciphertext_block = v0.to_bytes(4, 'big') + v1.to_bytes(4, 'big')
    return ciphertext_block

# Enhanced TEA decryption using stored round keys
def enhanced_tea_decrypt(ciphertext_block, key, round_keys_store):
    v0 = int.from_bytes(ciphertext_block[:4], 'big')
    v1 = int.from_bytes(ciphertext_block[4:], 'big')

    delta = 0x9e3779b9
    sum = (delta * 32) & 0xffffffff  # Initial sum for decryption

    for i in range(31, -1, -1):  # Loop in reverse order for decryption
        key_segments = round_keys_store[i]  # Retrieve stored key segments

        v1 = (v1 - (((v0 << 4) + key_segments[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key_segments[3]))) & 0xffffffff
        v0 = (v0 - (((v1 << 4) + key_segments[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key_segments[1]))) & 0xffffffff
        sum = (sum - delta) & 0xffffffff

    plaintext_block = v0.to_bytes(4, 'big') + v1.to_bytes(4, 'big')
    return plaintext_block

# Function to handle larger plaintext sizes
def encrypt_large_plaintext(plaintext, key):
    blocks = [plaintext[i:i+8] for i in range(0, len(plaintext), 8)]
    ciphertext = b""
    round_keys_store = []  # Store round keys for each block

    for block in blocks:
        if len(block) < 8:
            block = block.ljust(8, b'\x00')
        ciphertext += enhanced_tea_encrypt(block, key, round_keys_store)

    return ciphertext, round_keys_store

# Function to decrypt larger ciphertext sizes
def decrypt_large_ciphertext(ciphertext, key, round_keys_store):
    blocks = [ciphertext[i:i+8] for i in range(0, len(ciphertext), 8)]
    plaintext = b""

    for id, block in enumerate(blocks):
        # Use appropriate round keys for each block during decryption
        plaintext += enhanced_tea_decrypt(block, key, round_keys_store[id*32:(id+1)*32])

    return plaintext

# Function to measure decryption performance
def measure_decryption_performance(plaintext_size):
    plaintext = b"Hello, this is a test message for TEA encryption!" * plaintext_size  # Generate plaintext of given size
    key = b"0123456789abcdef"  # 16-byte key for TEA

    # Encrypt plaintext to get ciphertext and round keys
    ciphertext, round_keys_store = encrypt_large_plaintext(plaintext, key)

    decryption_times = []
    cpu_utilizations = []
    memory_usages = []

    # Run decryption 50 times for averaging
    for _ in range(50):
        start_cpu = psutil.cpu_percent(interval=None)
        start_time = time.perf_counter()

        # Decrypt the ciphertext
        decrypted_plaintext = decrypt_large_ciphertext(ciphertext, key, round_keys_store)

        end_time = time.perf_counter()
        end_cpu = psutil.cpu_percent(interval=0.1)

        # Verify decryption
        if plaintext != decrypted_plaintext:
            print("Decryption failed! Original plaintext does not match decrypted plaintext.")
            return

        # Calculate decryption time and CPU utilization for this run
        decryption_times.append(end_time - start_time)
        cpu_utilizations.append(end_cpu - start_cpu)

        # Memory usage
        process = psutil.Process(os.getpid())
        memory_usages.append(process.memory_info().rss / 1024 / 1024)  # Convert to MB

    # Calculate averages
    avg_decryption_time = sum(decryption_times) / len(decryption_times)
    avg_cpu_utilization = sum(cpu_utilizations) / len(cpu_utilizations)
    avg_memory_usage = sum(memory_usages) / len(memory_usages)

    print(f"Plaintext size: {plaintext_size * 8} bits")
    print(f"Average Decryption Time: {avg_decryption_time:.6f} seconds")
    print(f"Average CPU Utilization: {avg_cpu_utilization:.2f}%")
    print(f"Average Memory Used: {avg_memory_usage:.4f} MB\n")

# Test with different plaintext sizes
plaintext_sizes = [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536]

# Running the tests for each plaintext size
for size in plaintext_sizes:
    measure_decryption_performance(size)
