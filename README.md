U++ Cloud utilities
===
A collection of U++ packages that might be useful for interaction with cloud services.

*In early development.*

[U++](https://github.com/ultimatepp/ultimatepp)

RSA
---
- Supports traditional format RSA keys with RS256 signature signing and verification.
  - Uses RSAPrivateKey and RSAPublicKey functions:
    - https://www.openssl.org/docs/man1.1.1/man3/PEM_read_bio_RSAPrivateKey.html
- Loading and saving PEM files is supported.

JWT
---
- Simple class for creating (signing) and parsing and verifying the signature of JWT's.
- Only supports alg=RS256 right now

EVP
---
- EVP - High-level cryptographic functions
  - https://www.openssl.org/docs/man1.0.2/man3/evp.html
- Provides the following features of OpenSSL:
  - Signature/Verification
  - Encryption/decryption
  - Digest
