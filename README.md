# 🔐 Secure File Vault

### Hybrid RSA-OAEP + AES-256-GCM File Encryption System

A Python-based **Cryptography & Network Security (CNS) Mini Project** that provides secure file encryption, decryption, integrity verification, and RSA key management using modern cryptographic techniques.

The project uses **AES-256-GCM** for efficient file encryption and **RSA-3072 with OAEP-SHA256** for secure AES key protection.

> ⚠️ **Academic Project:** This application is developed for educational and demonstration purposes. It has not been professionally security-audited and should not be considered a replacement for production-grade encryption software.

---

## 👨‍🎓 Student Information

| Field | Details |
|---|---|
| **Student Name** | Jitendra Gaherwar |
| **Roll Number** | 149 |
| **Batch** | A3 |
| **Department** | Information Technology |
| **College** | Priyadarshini College of Engineering, Nagpur |
| **Academic Year** | 2026–2027 |
| **Course** | Cryptography & Network Security |

---

# 📌 Project Overview

Secure File Vault is a hybrid cryptographic file protection system developed using Python and Streamlit.

Instead of encrypting the complete file using RSA, the project combines two cryptographic algorithms:

- **AES-256-GCM** → Encrypts the actual file data.
- **RSA-3072 + OAEP-SHA256** → Encrypts/wraps the randomly generated AES key.
- **SHA-256** → Provides additional file integrity verification.

This approach combines the efficiency of symmetric encryption with the secure key-management capabilities of asymmetric encryption.



# 🎯 Problem Statement

Sensitive files can be exposed to unauthorized access or modification when stored or transferred without proper encryption.

RSA alone is not suitable for encrypting large files because it is comparatively slower and has input-size limitations.

Therefore, this project implements a **Hybrid Encryption System** in which:

1. AES encrypts the actual file.
2. RSA securely protects the AES key.
3. AES-GCM authentication detects unauthorized modifications.
4. SHA-256 can be used to compare file integrity.



# 🎯 Objectives

The main objectives of this project are:

- 🔐 Encrypt files using AES-256-GCM.
- 🔑 Generate and manage RSA-3072 key pairs.
- 🛡️ Protect AES keys using RSA-OAEP-SHA256.
- 🔓 Decrypt encrypted files securely.
- 🔍 Detect modification of encrypted data.
- 🧾 Verify file integrity using SHA-256.
- 🛡️ Implement input validation and basic security protections.
- 📁 Create a custom `.sfv` encrypted-file container.
- 🖥️ Provide a user-friendly Streamlit interface.
- 📝 Maintain security activity logs.
- 🧪 Provide automated tests for important cryptographic workflows.



# ⭐ Key Features

## 🔐 1. AES-256-GCM File Encryption

Files are encrypted using AES-256-GCM.

AES-GCM provides:

- Confidentiality
- Integrity
- Authentication
- Tamper detection

A random AES-256 key and random 96-bit nonce are generated for encryption.



## 🔑 2. RSA-3072 Key Management

The application supports RSA-3072 public/private key pairs.

The RSA public key is used during encryption, while the corresponding private key is required for decryption.


## 🛡️ 3. RSA-OAEP-SHA256 Key Protection

The randomly generated AES key is encrypted using:

```text
RSA-3072
+
OAEP
+
SHA-256

```
📦 4. Custom .sfv Encrypted Container

Encrypted files are stored using a custom .sfv format.

The container layout is:
```
"SFV1"
    |
Header Length
    |
JSON Header
    |
AES-GCM Authentication Tag
    |
Ciphertext
```
The header contains information such as:

Nonce
Wrapped AES key
Filename
File size
Timestamp
Cryptographic metadata

🛡️ 5. Metadata Tamper Detection

The .sfv header is passed to AES-GCM as Associated Authenticated Data (AAD).

Therefore, unauthorized modification of authenticated metadata can cause authentication verification to fail.

#️⃣ 6. SHA-256 Integrity Verification

The project supports SHA-256 hashing to compare file contents.

Example:

```
 Original File
     |
     v
SHA-256 Hash
     |
     v
Decrypted File
     |
     v
SHA-256 Hash
     |
     v
Compare
```
If the hashes match, the file contents are identical for the compared data.
