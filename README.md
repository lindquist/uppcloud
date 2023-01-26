U++ Cloud utilities
===
A collection of U++ packages that might be useful for interaction with cloud services.

*In early development.*

[U++](https://github.com/ultimatepp/ultimatepp)

RSA
---
The RSA package provides a simple U++ class for handling traditional RSA keys.

Dependencies:
- Core/SSL

Features:
- Supports traditional format RSA keys with RS256 signature signing and verification.
- Loading and saving PEM files.
- Uses RSAPrivateKey and RSAPublicKey functions:
  - https://www.openssl.org/docs/man1.1.1/man3/PEM_read_bio_RSAPrivateKey.html


JWT
---
The JWT package provides a simple U++ class for handling JWT tokens.

Dependencies:
- RSA

Features:
- Simple class for creating (signing) and parsing and verifying JWT tokens.
- Only supports `alg:"RS256"` right now.


EVP
---
The EVP package provides a simple U++ interface to OpenSSL EVP (Envelope - High-level cryptographic functions).

Dependencies:
- Core/SSL

Features:
- EVP - High-level cryptographic functions
  - https://www.openssl.org/docs/man1.0.2/man3/evp.html
- Provides the following features of OpenSSL:
  - Signature/Verification
  - Encryption/decryption
  - Digest
