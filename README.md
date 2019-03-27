# Cryptor

## Description
Command-line tool for encrypting/decrypting files with the AES-256 block cipher operating in CBC mode. The secret key is derived from a user-provided password using the PBKDF2 key derivation function. The SHA-512 cryptographic hash function is used to generate an HMAC for password and data integrity verification.

## Usage
With command-line arguments:

`java cryptor.Main -encrypt plaintext ciphertext password`

`java cryptor.Main -decrypt ciphertext plaintext password`

With command prompts:

`java cryptor.Main`
