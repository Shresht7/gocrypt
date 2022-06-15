# gocrypt

A collection of go packages for cryptography.

- [Encryption](./encryption/)
- [Hash](./hash/)
- [HMAC](./hmac/)
- [Key Derivation Function](./key/)
- [Stream Encryption](./stream/)
- [Utilities](./utils/)

## Installation

```sh
go get github.com/Shresht7/gocrypt
```

## Packages

### `encryption`

Encrypt and decrypt data using cryptographic `AEAD` algorithms like `AES-256-GCM` and `XChaCha20-Poly1305`.

### `hash`

Hash data using cryptographic hashing functions like `SHA-256`, `SHA-512` and `HMAC-SHA-512-256`.

### `hmac`

_Hash-based Message Authentication Code_ using `HMAC-SHA-512-256`.

### `key`

Password-based Key Derivation Functions using `bcrypt`, `scrypt` and `argon2id`.

### `stream`

Encrypt and decrypt data streams using `stream-ciphers`.

### `utils`

The [`utils`](./utils./) package contains miscellaneous helper functions to generate a byte-slice of random bytes, generate random string, and encode/decode byte slices.

## 📑 License

> [MIT License](./LICENSE)
