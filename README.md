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

### Subfolders and Their Contents
##### 1. Encryption & Decryption
This folder contains the implementation of the encryption and decryption processes using the enhanced TEA algorithm:
###### encryption:
Implements the encryption process for plaintext.

Helps visualize the encrypted output for different data inputs, demonstrating the effectiveness of the enhanced TEA algorithm.
###### encryption & decryption:
Combines both encryption and decryption processes in a single file.

Verifies the decryption accuracy across varying data sizes, ensuring data integrity and reliability.
##### 2. Performance Analysis
This folder evaluates the resource efficiency of the enhanced TEA algorithm:
###### Time & Memory analysis for encryption:
Measures the time taken and memory consumed during the encryption process.

Essential for validating the lightweight nature of the algorithm, ensuring its suitability for resource-constrained IoT devices.
###### Time & Memory analysis for decryption:
Assesses the time and memory usage during the decryption process.

Confirms that the algorithm maintains efficiency in real-world applications without compromising performance.
##### 3. Security Analysis
This folder tests the robustness and security of the enhanced TEA algorithm:
###### Avalanche effect test:
Analyzes how small changes in the plaintext or key affect the ciphertext.

Demonstrates the algorithm's sensitivity to input changes, a critical property for cryptographic strength.
###### Differential cryptanalysis:
Evaluates the algorithm's resistance to differential cryptanalysis attacks.
###### Entropy analysis:
Calculates the randomness in the ciphertext output.

Validates the unpredictability of the encrypted data.
## Tools and Technologies
#### Programming Language
Python 3.11.5: The project is implemented using Python for its simplicity and extensive library support.
#### IDE
Visual Studio Code: Used for writing, debugging, and testing the code.
#### Libraries Used
Hashlib: Provides a common interface for secure cryptographic hash and message digest algorithms.

Time: Used to compute the encryption and decryption time for performance evaluation.

psutil: Used to monitor resource usage during the encryption and decryption process.
