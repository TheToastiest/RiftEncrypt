// =====================================================================================
// main.cpp - Example Usage
// =====================================================================================
#include "../include/RiftEncrypt.hpp"
#include <iostream>
#include <string>
#include <cassert>

// Helper to convert string to byte_vec
byte_vec to_vec(const std::string& str) {
    return byte_vec(str.begin(), str.end());
}

// Helper to convert byte_vec to string
std::string to_str(const byte_vec& vec) {
    return std::string(vec.begin(), vec.end());
}

//int main() {
//    // Generate a key for ChaCha20
//    auto key = generate_key(crypto_aead_chacha20poly1305_ietf_KEYBYTES);
//
//    // Prepare example data
//    byte_vec plaintext = { 'R', 'i', 'f', 't', 'F', 'o', 'r', 'g', 'e', 'd' };
//    byte_vec aad = { 'm', 'e', 't', 'a' };
//    byte_vec nonce(crypto_aead_chacha20poly1305_ietf_NPUBBYTES, 0x42); // Static nonce for test
//
//    // Build Encryptor with manual nonce support
//    auto algo = std::make_unique<ChaCha20Poly1305Algorithm>(key);
//    Encryptor enc(std::move(algo));
//
//    // Encrypt with nonce
//    byte_vec ciphertext = enc.encrypt(plaintext, aad);  // For general interface
//
//    // OR: direct nonce control
//    ChaCha20Poly1305Algorithm raw(key);
//    byte_vec manual_ct = raw.encrypt_with_nonce(plaintext, nonce, aad);
//    byte_vec manual_pt = raw.decrypt_with_nonce(manual_ct, nonce, aad);
//
//    // Verify
//    std::string result_str(manual_pt.begin(), manual_pt.end());
//    std::cout << "Manual decrypted text: " << result_str << std::endl;
//
//    return 0;
//}