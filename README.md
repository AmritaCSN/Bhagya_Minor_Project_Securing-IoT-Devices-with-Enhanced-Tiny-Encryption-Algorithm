# Bhagya_Minor_Project_Securing-IoT-Devices-with-Enhanced-Tiny-Encryption-Algorithm
This repository contains the implementation codes for the project "Securing IoT Devices with Enhanced Tiny Encryption Algorithm", focusing on lightweight cryptography for resource-constrained IoT environments.
## Overview of the Project
The exponential growth of Internet of Things (IoT) devices has brought about significant security challenges, particularly due to their limited computational resources and deployment in critical applications such as smart cities, healthcare and industrial automation.  The Tiny Encryption Algorithm (TEA) has gained wide adoption for its simplicity and minimal resource requirements, making it a suitable choice for constrained IoT environments. However, TEA’s fixed key scheduling mechanism leaves it vulnerable to cryptanalytic attacks, especially known-plaintext attacks. To address these vulnerabilities, this project introduces an enhanced version of TEA that incorporates a dynamic round key scheduling mechanism, improving its resilience against evolving security threats while preserving its lightweight characteristics. In terms of overall security and performance, the enhanced TEA algorithm outperformed the original TEA. By offering a secure and efficient encryption solution tailored to the specific limitations and security demands of IoT ecosystems, this project contributes significantly to the field of IoT cryptography.
## Overview of the Repository
### Folder Structure
#### src Folder:
Contains the core implementation of the project, divided into three subfolders:
1. Encryption & Decryption
2. Performance Analysis
3. Security Analysis
#### Block Diagram:
Visual representation illustrating the encryption process.
![Block Diagram](https://github.com/user-attachments/assets/3b7d812d-a988-44b8-b195-93e839a05d60)

### Subfolders and Their Contents
#### `1. Encryption&Decryption_Algorithm`
This folder contains the implementation of the encryption and decryption processes using the enhanced TEA algorithm:

| Files | Description |
| --- | --- |
| Encryption.py | Implements the encryption process for plaintext. Helps visualize the encrypted output for different data inputs, demonstrating the effectiveness of the enhanced TEA algorithm. |
| Encryption & Decryption.py | Combines both encryption and decryption processes in a single file. Verifies the decryption accuracy across varying data sizes, ensuring data integrity and reliability. |

#### `2. Performance_Analysis`
This folder evaluates the resource efficiency of the enhanced TEA algorithm:

| Files | Description |
| --- | --- |
| time&memory_analysis_for 50 loops_encryption.py | Measures the time taken and memory consumed during the encryption process. Essential for validating the lightweight nature of the algorithm, ensuring its suitability for resource-constrained IoT devices. |
| decryption_time&memory_analysis_for 50 loops.py | Assesses the time and memory usage during the decryption process. Confirms that the algorithm maintains efficiency in real-world applications without compromising performance. |

#### `3. Security Analysis`
This folder tests the robustness and security of the enhanced TEA algorithm:

| Command | Description |
| --- | --- |
| Avalanche_effect_test.py | Analyzes how small changes in the plaintext or key affect the ciphertext. Demonstrates the algorithm's sensitivity to input changes, a critical property for cryptographic strength. |
| Differential_Crypt_analysis.py | Evaluates the algorithm's resistance to differential cryptanalysis attacks. |
| Entropy_analysis.py | Calculates the randomness in the ciphertext output. Validates the unpredictability of the encrypted data. |

## Tools and Technologies
#### Programming Language
Python 3.11.5: The project is implemented using Python for its simplicity and extensive library support.
#### IDE
Visual Studio Code: Used for writing, debugging, and testing the code.
#### Libraries Used
Hashlib: Provides a common interface for secure cryptographic hash and message digest algorithms.

Time: Used to compute the encryption and decryption time for performance evaluation.

psutil: Used to monitor resource usage during the encryption and decryption process.
## Usage
Follow the steps below to use the functionalities provided in this repository:

1. Clone the Repository
2. Navigate into the cloned directory.
3. Ensure you have Python 3.11.5 installed.
4. Navigate to the src/encryption & decryption folder.
5. Use the encryption.py file to encrypt a plaintext message using the Enhanced TEA algorithm.
6. Use the encryption & decryption.py file to perform both encryption and decryption, verifying the process for data integrity.
7. Navigate to the src/performance analysis folder and run the code to analyse the time and memory during encryption and decryption.
8. Navigate to the src/security analysis folder.
9. Test the Avalanche Effect to measure the sensitivity of the algorithm to small input changes.
10. Perform Differential Cryptanalysis to evaluate the resistance of the Enhanced TEA algorithm against cryptanalytic attacks.
11. Conduct Entropy Analysis to assess the randomness and uniformity of the ciphertext.
12. Modify the encryption key, plaintext size, etc in the source files to explore how they affect the encryption process and its performance. Test with different inputs to evaluate the robustness and scalability of the algorithm.
13. To install the psutil library, use the following command: `pip install psutil` 
