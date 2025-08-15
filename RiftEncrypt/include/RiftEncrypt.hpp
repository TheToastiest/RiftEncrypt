// =====================================================================================
// riftencrypt.hpp - Header File
// =====================================================================================
#ifndef RIFTFORGED_CRYPTO_HPP
#define RIFTFORGED_CRYPTO_HPP

#include <vector>
#include <memory>
    #include <sodium.h>

// Forward declaration to avoid including sodium.h in the public header if not necessary,
// though for a library like this, it's often practical to include it.
// #include <sodium.h>

// A type alias for byte vectors for clarity.
using byte_vec = std::vector<unsigned char>;

/**
 * @class CryptoAlgorithm
 * @brief An abstract base class (interface) for cryptographic algorithms.
 *
 * This interface defines the contract for all AEAD (Authenticated Encryption
 * with Associated Data) algorithms within the library, ensuring modularity.
 */
class CryptoAlgorithm {
public:
    virtual ~CryptoAlgorithm() = default;

    /**
     * @brief Encrypts a plaintext message.
     * @param plaintext The data to encrypt.
     * @param associated_data Additional data to authenticate but not encrypt.
     * @return A byte vector containing the nonce and ciphertext (including tag).
     * Returns an empty vector on failure.
     */
    virtual byte_vec encrypt(const byte_vec& plaintext, const byte_vec& associated_data) = 0;


    /**
     * @brief Decrypts a ciphertext message.
     * @param ciphertext The data to decrypt (must include nonce and tag).
     * @param associated_data Additional data that was authenticated.
     * @return The original plaintext if decryption and authentication are successful.
     * Returns an empty vector on failure.
     */
    virtual byte_vec decrypt(const byte_vec& ciphertext, const byte_vec& associated_data) = 0;

    /**
     * @brief Encrypts a plaintext message with a specific nonce.
	 */
    virtual byte_vec encrypt_with_nonce(const byte_vec& plaintext, const byte_vec& nonce, const byte_vec& associated_data) = 0;

    /**
	* @brief Decrypts a ciphertext message with a specific nonce.
    */
    virtual byte_vec decrypt_with_nonce(const byte_vec& ciphertext, const byte_vec& nonce, const byte_vec& associated_data) = 0;

};

/**
 * @class AESGCMAlgorithm
 * @brief Implements the CryptoAlgorithm interface using AES-256-GCM from libsodium.
 */
class AESGCMAlgorithm : public CryptoAlgorithm {
private:
    byte_vec key;

public:
    explicit AESGCMAlgorithm(const byte_vec& key);
    byte_vec encrypt(const byte_vec& plaintext, const byte_vec& associated_data) override;
    byte_vec decrypt(const byte_vec& ciphertext, const byte_vec& associated_data) override;

	byte_vec encrypt_with_nonce(const byte_vec& plaintext, const byte_vec& nonce, const byte_vec& associated_data) override;
	byte_vec decrypt_with_nonce(const byte_vec& ciphertext, const byte_vec& nonce, const byte_vec& associated_data) override;

};

/**
 * @class ChaCha20Poly1305Algorithm
 * @brief Implements the CryptoAlgorithm interface using ChaCha20-Poly1305 from libsodium.
 */
class ChaCha20Poly1305Algorithm : public CryptoAlgorithm {
private:
    byte_vec key;

public:
    explicit ChaCha20Poly1305Algorithm(const byte_vec& key);
    byte_vec encrypt(const byte_vec& plaintext, const byte_vec& associated_data) override;
    byte_vec decrypt(const byte_vec& ciphertext, const byte_vec& associated_data) override;

    byte_vec encrypt_with_nonce(const byte_vec& plaintext, const byte_vec& nonce, const byte_vec& associated_data) override;
    byte_vec decrypt_with_nonce(const byte_vec& ciphertext, const byte_vec& nonce, const byte_vec& associated_data) override;

};

/**
 * @class Encryptor
 * @brief The main interface for performing encryption and decryption.
 *
 * This class provides a simple API that abstracts away the underlying
 * cryptographic algorithm being used.
 */
class Encryptor {
private:
    std::unique_ptr<CryptoAlgorithm> algorithm;

public:
    explicit Encryptor(std::unique_ptr<CryptoAlgorithm> algo);

    /**
     * @brief Encrypts data using the configured algorithm.
     * @param plaintext The data to encrypt.
     * @param associated_data Optional data to authenticate.
     * @return The encrypted data.
     */
    byte_vec encrypt(const byte_vec& plaintext, const byte_vec& associated_data = {});

    /**
     * @brief Decrypts data using the configured algorithm.
     * @param ciphertext The data to decrypt.
     * @param associated_data Optional authenticated data.
     * @return The decrypted plaintext.
     */
    byte_vec decrypt(const byte_vec& ciphertext, const byte_vec& associated_data = {});

	byte_vec encrypt_with_nonce(const byte_vec& plaintext, const byte_vec& nonce, const byte_vec& associated_data = {});

	byte_vec decrypt_with_nonce(const byte_vec& ciphertext, const byte_vec& nonce, const byte_vec& associated_data = {});
};

/**
 * @brief Generates a cryptographically secure key.
 * @param length The desired length of the key in bytes.
 * @return A byte vector containing the generated key.
 */
byte_vec generate_key(size_t length);

#endif // RIFTFORGED_CRYPTO_HPP