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
evp - OpenSSL High-level cryptographic functions

Uses the following OpenSSL API's:

- Private/public keys, signing, verifying:
  - PEM_read_bio_PrivateKey
  - PEM_read_bio_PUBKEY
  - PEM_write_bio_PKCS8PrivateKey
  - PEM_write_bio_PrivateKey
  - PEM_write_bio_PUBKEY
  - EVP_PKEY_CTX_new_id
  - EVP_PKEY_keygen_init
  - EVP_PKEY_keygen
  - EVP_PKEY_sign_init
  - EVP_PKEY_sign
  - EVP_PKEY_verify_init
  - EVP_PKEY_verify

- Encryption/decryption:
  - EVP_EncryptInit_ex
  - EVP_EncryptUpdate
  - EVP_EncryptFinal_ex
  - EVP_DecryptInit_ex
  - EVP_DecryptUpdate
  - EVP_DecryptFinal_ex
  
