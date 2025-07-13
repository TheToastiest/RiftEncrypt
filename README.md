# RiftEncrypt — Encrypted Communication for Real-Time Systems

> “If you want truth across the wire, start with encryption.”

---

**RiftEncrypt** is a standalone C++ library for secure communication in real-time systems. It powers the encryption layer in [RiftNet](https://github.com/TheToastiest/RiftNet) and is designed to be fast, stateless, and fully compatible with **libsodium**.

---

## 🔑 Features

- X25519 key exchange (ephemeral)
- ChaCha20-Poly1305 or AES256-GCM encryption
- Nonce management with safeguards
- Simple API, modular design
- No runtime memory allocations inside hotpaths

---

## ⚙️ Integration

To use RiftEncrypt:

1. Include `RiftEncrypt/include/` in your project.
2. Link against libsodium (static or dynamic).
3. Use `SecureChannel` to encrypt/decrypt buffers.

Example:
```cpp
SecureChannel channel;
channel.initiateHandshake();

channel.encrypt(message, outputBuffer);
channel.decrypt(encryptedMessage, outputBuffer);
