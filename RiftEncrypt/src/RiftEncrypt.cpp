// =====================================================================================
// riftencrypt.cpp - Source File
// =====================================================================================
#include "../include/RiftEncrypt.hpp"
#include <sodium.h>
#include <stdexcept>
#include <iostream>

// --- Helper function to initialize libsodium ---
// This ensures that libsodium is initialized before any crypto operations are performed.
// It's safe to call sodium_init() multiple times.
static bool initialize_sodium() {
    if (sodium_init() < 0) {
        // We use cerr here as a last resort. In a real application,
        // this should be logged properly.
        std::cerr << "FATAL: Could not initialize libsodium!" << std::endl;
        return false;
    }
    return true;
}
static const bool sodium_initialized = initialize_sodium();


// --- Key Generation ---
byte_vec generate_key(size_t length) {
    if (!sodium_initialized) {
        throw std::runtime_error("Libsodium not initialized.");
    }
    byte_vec key(length);
    randombytes_buf(key.data(), key.size());
    return key;
}

// --- AESGCMAlgorithm Implementation ---
AESGCMAlgorithm::AESGCMAlgorithm(const byte_vec& key) : key(key) {
    if (!sodium_initialized) {
        throw std::runtime_error("Libsodium not initialized.");
    }
    if (key.size() != crypto_aead_aes256gcm_KEYBYTES) {
        throw std::invalid_argument("Invalid key size for AES-256-GCM.");
    }
}

byte_vec AESGCMAlgorithm::encrypt(const byte_vec& plaintext, const byte_vec& associated_data) {
    // AES-256-GCM requires a 12-byte (96-bit) nonce.
    const size_t NONCE_SIZE = crypto_aead_aes256gcm_NPUBBYTES;
    byte_vec nonce(NONCE_SIZE);
    randombytes_buf(nonce.data(), nonce.size());

    // The ciphertext will be the plaintext size + an authentication tag.
    byte_vec ciphertext(plaintext.size() + crypto_aead_aes256gcm_ABYTES);
    unsigned long long ciphertext_len;

    int result = crypto_aead_aes256gcm_encrypt(
        ciphertext.data(), &ciphertext_len,
        plaintext.data(), plaintext.size(),
        associated_data.data(), associated_data.size(),
        nullptr, // nsec is not used, must be NULL
        nonce.data(),
        this->key.data()
    );

    if (result != 0) {
        return {}; // Return empty vector on failure
    }

    // The final format is [nonce][ciphertext_with_tag]
    byte_vec final_message;
    final_message.reserve(nonce.size() + ciphertext.size());
    final_message.insert(final_message.end(), nonce.begin(), nonce.end());
    final_message.insert(final_message.end(), ciphertext.begin(), ciphertext.end());

    return final_message;
}

byte_vec AESGCMAlgorithm::decrypt(const byte_vec& ciphertext, const byte_vec& associated_data) {
    const size_t NONCE_SIZE = crypto_aead_aes256gcm_NPUBBYTES;
    if (ciphertext.size() < NONCE_SIZE + crypto_aead_aes256gcm_ABYTES) {
        return {}; // Not enough data to possibly be valid
    }

    // Extract the nonce and the actual ciphertext part
    byte_vec nonce(ciphertext.begin(), ciphertext.begin() + NONCE_SIZE);
    byte_vec encrypted_part(ciphertext.begin() + NONCE_SIZE, ciphertext.end());

    byte_vec decrypted_message(encrypted_part.size() - crypto_aead_aes256gcm_ABYTES);
    unsigned long long decrypted_len;

    int result = crypto_aead_aes256gcm_decrypt(
        decrypted_message.data(), &decrypted_len,
        nullptr, // nsec is not used, must be NULL
        encrypted_part.data(), encrypted_part.size(),
        associated_data.data(), associated_data.size(),
        nonce.data(),
        this->key.data()
    );

    if (result != 0) {
        return {}; // Decryption failed (invalid tag or corrupted data)
    }

    // On success, libsodium might have written fewer bytes. Resize to actual length.
    decrypted_message.resize(decrypted_len);
    return decrypted_message;
}


// --- ChaCha20Poly1305Algorithm Implementation ---
ChaCha20Poly1305Algorithm::ChaCha20Poly1305Algorithm(const byte_vec& key) : key(key) {
    if (!sodium_initialized) {
        throw std::runtime_error("Libsodium not initialized.");
    }
    if (key.size() != crypto_aead_chacha20poly1305_ietf_KEYBYTES) {
        throw std::invalid_argument("Invalid key size for ChaCha20-Poly1305.");
    }
}

byte_vec ChaCha20Poly1305Algorithm::encrypt(const byte_vec& plaintext, const byte_vec& associated_data) {
    // IETF ChaCha20-Poly1305 uses a 12-byte (96-bit) nonce.
    const size_t NONCE_SIZE = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    byte_vec nonce(NONCE_SIZE);
    randombytes_buf(nonce.data(), nonce.size());

    byte_vec ciphertext(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len;

    int result = crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext.data(), &ciphertext_len,
        plaintext.data(), plaintext.size(),
        associated_data.data(), associated_data.size(),
        nullptr, // nsec is not used
        nonce.data(),
        this->key.data()
    );

    if (result != 0) {
        return {};
    }

    byte_vec final_message;
    final_message.reserve(nonce.size() + ciphertext.size());
    final_message.insert(final_message.end(), nonce.begin(), nonce.end());
    final_message.insert(final_message.end(), ciphertext.begin(), ciphertext.end());

    return final_message;
}

byte_vec ChaCha20Poly1305Algorithm::encrypt_with_nonce(const byte_vec& plaintext, const byte_vec& nonce, const byte_vec& associated_data) {
    if (nonce.size() != crypto_aead_chacha20poly1305_ietf_NPUBBYTES) {
        throw std::invalid_argument("Invalid nonce size");
    }

    byte_vec ciphertext(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len;

    int result = crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext.data(), &ciphertext_len,
        plaintext.data(), plaintext.size(),
        associated_data.data(), associated_data.size(),
        nullptr, nonce.data(), this->key.data());

    if (result != 0) return {};

    return ciphertext; // No prepended nonce
}

byte_vec ChaCha20Poly1305Algorithm::decrypt(const byte_vec& ciphertext, const byte_vec& associated_data) {
    const size_t NONCE_SIZE = crypto_aead_chacha20poly1305_ietf_NPUBBYTES;
    if (ciphertext.size() < NONCE_SIZE + crypto_aead_chacha20poly1305_ietf_ABYTES) {
        return {};
    }

    byte_vec nonce(ciphertext.begin(), ciphertext.begin() + NONCE_SIZE);
    byte_vec encrypted_part(ciphertext.begin() + NONCE_SIZE, ciphertext.end());

    byte_vec decrypted_message(encrypted_part.size() - crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long decrypted_len;

    int result = crypto_aead_chacha20poly1305_ietf_decrypt(
        decrypted_message.data(), &decrypted_len,
        nullptr, // nsec is not used
        encrypted_part.data(), encrypted_part.size(),
        associated_data.data(), associated_data.size(),
        nonce.data(),
        this->key.data()
    );

    if (result != 0) {
        return {};
    }

    decrypted_message.resize(decrypted_len);
    return decrypted_message;
}

byte_vec ChaCha20Poly1305Algorithm::decrypt_with_nonce(const byte_vec& ciphertext, const byte_vec& nonce, const byte_vec& associated_data) {
    if (nonce.size() != crypto_aead_chacha20poly1305_ietf_NPUBBYTES) {
        throw std::invalid_argument("Invalid nonce size");
    }

    byte_vec decrypted(ciphertext.size() - crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long decrypted_len;

    int result = crypto_aead_chacha20poly1305_ietf_decrypt(
        decrypted.data(), &decrypted_len,
        nullptr, ciphertext.data(), ciphertext.size(),
        associated_data.data(), associated_data.size(),
        nonce.data(), this->key.data());

    if (result != 0) return {};
    decrypted.resize(decrypted_len);
    return decrypted;
}

// --- Encryptor Implementation ---
Encryptor::Encryptor(std::unique_ptr<CryptoAlgorithm> algo) : algorithm(std::move(algo)) {}

byte_vec Encryptor::encrypt(const byte_vec& plaintext, const byte_vec& associated_data) {
    if (!algorithm) {
        throw std::runtime_error("No encryption algorithm has been configured.");
    }
    return algorithm->encrypt(plaintext, associated_data);
}

byte_vec Encryptor::decrypt(const byte_vec& ciphertext, const byte_vec& associated_data) {
    if (!algorithm) {
        throw std::runtime_error("No encryption algorithm has been configured.");
    }
    return algorithm->decrypt(ciphertext, associated_data);
}