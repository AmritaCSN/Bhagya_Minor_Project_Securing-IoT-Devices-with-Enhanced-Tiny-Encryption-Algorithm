import time
import psutil
import hashlib
import os

# Function to compute SHA-256 hash (used in enhanced TEA)
def compute_sha256_hash(plaintext):
    hash_obj = hashlib.sha256(plaintext.encode())
    full_hash = hash_obj.digest()
    return full_hash[:16], full_hash[16:]

# XOR function for key segments
def xor_with_key(hash_segments, key_segments):
    return [int.from_bytes(hash_seg, 'big') ^ key_seg for hash_seg, key_seg in zip(hash_segments, key_segments)]

# Enhanced TEA encryption
def enhanced_tea_encrypt(plaintext_block, key):
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
        
        sum = (sum + delta) & 0xffffffff
        L0 = (L0 + (((R0 << 4) + key_segments[0]) ^ (R0 + sum) ^ ((R0 >> 5) + key_segments[1]))) & 0xffffffff
        R0 = (R0 + (((L0 << 4) + key_segments[2]) ^ (L0 + sum) ^ ((L0 >> 5) + key_segments[3]))) & 0xffffffff

    ciphertext_block = L0.to_bytes(4, 'big') + R0.to_bytes(4, 'big')
    return ciphertext_block

# Function to handle larger plaintext sizes
def encrypt_large_plaintext(plaintext, key):
    blocks = [plaintext[i:i+8] for i in range(0, len(plaintext), 8)]
    ciphertext = b""
    for block in blocks:
        if len(block) < 8:
            block = block.ljust(8, b'\x00')
        ciphertext += enhanced_tea_encrypt(block, key)
    return ciphertext

# Function to measure encryption time and CPU usage
def measure_encryption_performance(plaintext_size):
    plaintext = b"Hello, this is a test message for TEA encryption!" * plaintext_size  # Generate plaintext of given size
    key = b"0123456789abcdef"  # 16-byte key for TEA
    
    start_cpu = psutil.cpu_percent(interval=None)
    start_time = time.perf_counter()

    # Encrypt plaintext
    encrypt_large_plaintext(plaintext, key)

    end_time = time.perf_counter()
    end_cpu = psutil.cpu_percent(interval=0.1)

    encryption_time = end_time - start_time
    cpu_utilization = end_cpu - start_cpu

    # Memory usage
    process = psutil.Process(os.getpid())
    memory_used = process.memory_info().rss / 1024 / 1024  # Convert to MB

    return encryption_time, cpu_utilization, memory_used

# Testing with different plaintext sizes (bytes to bits)
plaintext_sizes = [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384]

# Running the tests for each plaintext size
for size in plaintext_sizes:
    total_time, total_cpu, total_memory = 0, 0, 0

    for _ in range(50):  # Running 50 times
        enc_time, cpu_usage, mem_used = measure_encryption_performance(size)
        total_time += enc_time
        total_cpu += cpu_usage
        total_memory += mem_used

    # Calculate averages
    avg_time = total_time / 50
    avg_cpu = total_cpu / 50
    avg_memory = total_memory / 50

    print(f"Plaintext size: {size * 8} bits, Average Encryption time: {avg_time:.6f} seconds")
    print(f"Average CPU Utilization: {avg_cpu:.2f}%, Average Memory Used: {avg_memory:.4f} MB\n")
