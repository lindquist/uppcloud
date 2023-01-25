U++ Cloud utilities
===
A collection of packages useful for interaction with cloud services.

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
