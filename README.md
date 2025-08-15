RiftEncrypt 

RiftEncrypt is a high-performance, modern C++ encryption library designed for real-time applications like networking and games. It provides a clean, type-safe C++ wrapper around the robust and audited libsodium cryptographic library, focusing on ease of use and speed.

Features
Modern C++ Interface: A simple, object-oriented API using std::vector for byte streams and smart pointers for resource management (std::unique_ptr).

AEAD Ciphers: Implements authenticated encryption with associated data (AEAD) to protect against tampering.

AES-256-GCM: Extremely fast on modern CPUs with AES-NI hardware acceleration.

ChaCha20-Poly1305: A secure and fast software-based cipher, providing excellent performance on platforms without AES hardware support.

Type-Safe & Modular: The design uses a virtual interface (CryptoAlgorithm) to decouple the core logic from the specific algorithm, making it easy to extend.

Minimal Dependencies: Only requires a C++17 compiler and the libsodium library.

High Performance: Benchmarked to handle millions of encryption/decryption operations per second.

Requirements
C++17 (or newer) compiler

Libsodium library installed and linked

For Windows users, using a package manager like vcpkg is the recommended way to install libsodium:

vcpkg install libsodium

Quick Start: API Usage
Using RiftEncrypt is straightforward. Create an Encryptor instance by choosing an algorithm and providing a key.

#include "RiftEncrypt.hpp"
#include <iostream>

int main() {
    try {
        // 1. Generate a secure key for AES-256-GCM
        auto key = generate_key(crypto_aead_aes256gcm_KEYBYTES);

        // 2. Create an Encryptor with the desired algorithm
        Encryptor encryptor(std::make_unique<AESGCMAlgorithm>(key));

        // 3. Prepare data
        byte_vec plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'R', 'i', 'f', 't', 'N', 'e', 't'};
        byte_vec nonce(crypto_aead_aes256gcm_NPUBBYTES, 0); // Use a real, unique nonce per message!
        byte_vec associated_data = {'M', 'E', 'T', 'A', 'D', 'A', 'T', 'A'};

        // 4. Encrypt the data
        byte_vec ciphertext = encryptor.encrypt_with_nonce(plaintext, nonce, associated_data);
        if (ciphertext.empty()) {
            std::cerr << "Encryption failed!" << std::endl;
            return 1;
        }
        std::cout << "Encryption successful." << std::endl;

        // 5. Decrypt the data
        byte_vec decrypted_text = encryptor.decrypt_with_nonce(ciphertext, nonce, associated_data);
        if (decrypted_text.empty()) {
            std::cerr << "Decryption failed! (Ciphertext may have been tampered with)" << std::endl;
            return 1;
        }

        // 6. Verify correctness
        if (plaintext == decrypted_text) {
            std::cout << "Success! Decrypted text matches original plaintext." << std::endl;
        } else {
            std::cout << "Verification failed!" << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

Important: The example above uses a zero-filled nonce for simplicity. In a real application, you must ensure that a unique nonce is used for every single message sent with a given key.

Performance Benchmarks
The library has been benchmarked for end-to-end encrypt/decrypt operations. The results below were captured on an x64 Release build with 100,000 iterations per test.

AES-256-GCM

64 B Payload: 1,929,324 ops/second

512 B Payload: 2,083,832 ops/second

1400 B Payload: 1,275,380 ops/second

4096 B Payload: 609,067 ops/second

ChaCha20-Poly1305

64 B Payload: 1,276,071 ops/second

512 B Payload: 804,208 ops/second

1400 B Payload: 335,853 ops/second

4096 B Payload: 142,221 ops/second

License
This project is licensed under the MIT License. See the LICENSE file for details.
