# RiftEncrypt — Encrypted Communication for Real-Time Systems

> “If you want truth across the wire, start with encryption.”

---

**RiftEncrypt** is a standalone C++ library for secure communication in real-time systems. It powers the encryption layer in [RiftNet](https://github.com/TheToastiest/RiftNet) and is designed to be fast, stateless, and fully compatible with **libsodium**.

---
## BENCHMARKS

Starting RiftEncrypt End-to-End Benchmark...
--------------------------------------------------------------------------------
Algorithm                Payload Size   Iterations     Ops/Second
--------------------------------------------------------------------------------
AES-256-GCM              64 B           100000         1929324.97
AES-256-GCM              512 B          100000         2083832.58
AES-256-GCM              1400 B         100000         1275380.06
AES-256-GCM              4096 B         100000         609067.18
--------------------------------------------------------------------------------
ChaCha20-Poly1305        64 B           100000         1276071.74
ChaCha20-Poly1305        512 B          100000         804208.91
ChaCha20-Poly1305        1400 B         100000         335853.80
ChaCha20-Poly1305        4096 B         100000         142221.82
--------------------------------------------------------------------------------

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
