# Crypto-Utilities-Java

A mini-project in Java for implementing and demonstrating fundamental cryptographic concepts. The goal is to develop a practical understanding of symmetric and asymmetric encryption, hashing, and digital signatures.

## Table of Contents

- [About the Project](#about-the-project)
- [Implemented Features](#implemented-features)
- [Technologies](#technologies)
- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [License](#license)

## About the Project

This project serves as a hands-on exercise to deepen the understanding of cryptography. It implements a set of Java classes that perform basic cryptographic operations using the Java Cryptography Architecture (JCA) and Java Cryptography Extension (JCE). The focus is on the correct application of common algorithms and modes to ensure data security and integrity.

## Implemented Features

### 1. Symmetric Encryption (AES)
- **Algorithm:** AES (Advanced Encryption Standard)
- **Mode/Padding:** GCM (Galois/Counter Mode) with NoPadding
- **Key Length:** 256 bits
- **Functions:**
    - `generateSymmetricKey()`: Generates a new, random AES key.
    - `encryptSymmetric(String message)`: Encrypts a message. A unique, random Initialization Vector (IV) is generated for each operation and returned along with the Base64-encoded ciphertext.
    - `decryptSymmetric(EncryptedData encryptedData)`: Decrypts a message and verifies its integrity using the GCM authentication tag.

### 2. Asymmetric Encryption (RSA)
- **Algorithm:** RSA (Rivest–Shamir–Adleman)
- **Mode/Padding:** ECB (Electronic Codebook) with OAEPWithSHA-256AndMGF1Padding
- **Key Length:** 4096 bits
- **Functions:**
    - `generateKeyPair()`: Generates a new RSA key pair (public and private key).
    - `encryptAsymmetric(String message)`: Encrypts a message using the public key.
    - `decryptAsymmetric(byte[] encryptedMessage)`: Decrypts a message using the private key.
- **Note:** Asymmetric encryption is primarily designed for secure exchange of symmetric keys or for encrypting small amounts of data (e.g., session keys), not for large data volumes.

### 3. Hashing
- **Algorithm:** SHA-256 (Secure Hash Algorithm 256)
- **Functions:**
    - `generateHash(String data)`: Computes the SHA-256 hash of a string. The hash is output as a hexadecimal string.
- **Purpose:** Used for data integrity verification. Even a minimal change to the input will result in a completely different hash (avalanche effect).

### 4. Digital Signatures
- **Algorithm:** SHA256withRSA
- **Functions:**
    - `signData(String data)`: Signs data using the private key of the generated key pair. The signature is returned Base64-encoded.
    - `verifySignature(String data, byte[] signatureBytes)`: Verifies a signature using the corresponding public key. Checks if the data is unaltered and originated from the holder of the private key.

## Technologies

- **Java Development Kit (JDK):** Version 17+ (or any version supporting Java Records)
- **Standard Java Cryptography Architecture (JCA) / Java Cryptography Extension (JCE)**

## Usage

The project can be executed directly via the `App.java` class. The `main` method contains demonstrations of all implemented cryptographic operations.

### Compiling and Running (without a build tool):

1.  Navigate to the `src/main/java` directory of your project in the terminal.
2.  Compile the Java files:
    ```bash
    javac com/boeani/crypto/*.java
    ```
3.  Run the `App` class:
    ```bash
    java com.boeani.crypto.App
    ```

If you are using a build tool like Maven or Gradle, follow your tool's specific instructions.

## Security Considerations

The implementation addresses the following security aspects:

- **AES GCM:** Using Galois/Counter Mode for symmetric encryption provides both confidentiality and authenticity/integrity of data.
- **Unique IV:** A new, random Initialization Vector (IV) is generated for each AES-GCM encryption operation.
- **RSA OAEP Padding:** For asymmetric RSA encryption, OAEP (Optimal Asymmetric Encryption Padding) is used to enhance security against various attack types.
- **RSA Key Size:** RSA keys with a length of 4096 bits are generated, which aligns with current best practices.
- **SHA-256:** A secure hash algorithm used for integrity checks.
- **Digital Signatures:** SHA256withRSA is used for digital signatures to ensure authenticity, integrity, and non-repudiation.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE.md) file for more details.
