RiftForged Encryption Library: Design
1. Introduction
This document outlines the design for a modular and robust encryption library for the RiftForged ecosystem. The primary goal is to provide a standardized, secure, and easy-to-use cryptographic module that can be seamlessly integrated into various components like RiftNet, RiftServer, and RiftShard. The library will support two modern and secure authenticated encryption with associated data (AEAD) schemes: ChaCha20-Poly1305 and AES-256-GCM.

2. Core Requirements
Modularity: The library will be designed in a modular fashion, allowing for easy expansion with new cryptographic algorithms in the future.

Algorithm Support: It will initially support ChaCha20-Poly1305 and AES-256-GCM.

Ease of Use: The library will provide a simple and intuitive API for encryption and decryption operations, abstracting away the complexities of the underlying cryptographic primitives.

Security: The implementation will adhere to cryptographic best practices to prevent common vulnerabilities. This includes proper handling of keys, nonces (IVs), and authentication tags.

Flexibility: The library will allow for the specification of the desired encryption algorithm, giving developers control over the trade-offs between performance and security where applicable.

3. Architecture
The library will be built around a central Encryptor class, which will serve as the main interface for all cryptographic operations. This class will be initialized with a specific encryption algorithm and a secret key.

3.1. CryptoAlgorithm Interface
To ensure modularity, we will define a CryptoAlgorithm interface (or an abstract base class in Python) that all supported algorithms must implement. This interface will define the core encryption and decryption methods.

interface CryptoAlgorithm {
  encrypt(plaintext: bytes, associated_data: bytes): bytes;
  decrypt(ciphertext: bytes, associated_data: bytes): bytes;
}

3.2. Algorithm Implementations
We will provide concrete implementations of the CryptoAlgorithm interface for ChaCha20-Poly1305 and AES-256-GCM.

ChaCha20Poly1305Algorithm: This class will implement the CryptoAlgorithm interface using the ChaCha20-Poly1305 cipher.

AESGCMAlgorithm: This class will implement the CryptoAlgorithm interface using the AES-256-GCM cipher.

3.3. Encryptor Class
The Encryptor class will be the primary entry point for developers. It will be initialized with an instance of a CryptoAlgorithm.

class Encryptor {
  private algorithm: CryptoAlgorithm;

  constructor(algorithm: CryptoAlgorithm);

  encrypt(plaintext: bytes, associated_data: bytes = b""): bytes;
  decrypt(ciphertext: bytes, associated_data: bytes = b""): bytes;
}

This design decouples the Encryptor from the specific cryptographic algorithms, making it easy to switch between them or add new ones without changing the core application logic.

4. Key Management
The security of any cryptographic system relies heavily on the secure management of keys. This library will assume that keys are managed securely by the calling application.

Key Generation: The library will provide a helper function to generate cryptographically secure random keys of the appropriate length for each algorithm (32 bytes for both AES-256 and ChaCha20).

Key Storage: Key storage and retrieval are the responsibility of the application using the library. Keys should be stored in a secure manner, such as in a hardware security module (HSM) or a secure key vault.

5. Data Format
The output of the encrypt method will be a single byte string containing the nonce (IV), the ciphertext, and the authentication tag, concatenated in a defined order. This simplifies data handling for the application, as it only needs to store and transmit a single blob of data.

For AES-256-GCM: nonce (12 bytes) || ciphertext || tag (16 bytes)

For ChaCha20-Poly1305: nonce (12 bytes) || ciphertext || tag (16 bytes)

The decrypt method will parse this format to extract the necessary components for decryption and authentication.

6. Usage Example (Conceptual)
Here is a conceptual example of how the library might be used in Python:

from riftforged_crypto import Encryptor, ChaCha20Poly1305Algorithm, AESGCMAlgorithm, generate_key

# 1. Generate a key
key = generate_key()

# 2. Choose an algorithm and create an encryptor
# For ChaCha20-Poly1305
chacha_algo = ChaCha20Poly1305Algorithm(key)
encryptor = Encryptor(chacha_algo)

# For AES-256-GCM
aes_algo = AESGCMAlgorithm(key)
encryptor = Encryptor(aes_algo)

# 3. Encrypt data
plaintext = b"This is a secret message for RiftNet."
associated_data = b"metadata" # Optional
ciphertext = encryptor.encrypt(plaintext, associated_data)

# 4. Decrypt data
decrypted_plaintext = encryptor.decrypt(ciphertext, associated_data)

assert plaintext == decrypted_plaintext

7. Integration with RiftForged Components
This library can be integrated into various parts of the RiftForged ecosystem:

RiftNet: For securing peer-to-peer communications. Each message can be encrypted with a shared session key.

RiftServer: For encrypting data at rest, such as user data or sensitive configuration files.

RiftShard: For securing communications between different shards or nodes in a distributed system.

By providing a single, standardized encryption library, we ensure that all components of RiftForged use consistent and secure cryptographic practices.