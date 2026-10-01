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
---
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
---
The .sfv header is passed to AES-GCM as Associated Authenticated Data (AAD).

Therefore, unauthorized modification of authenticated metadata can cause authentication verification to fail.


#️⃣ 6. SHA-256 Integrity Verification
---
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


🔓 7. Secure Decryption
---
During decryption:

RSA private key unwraps the AES key.
AES-GCM verifies the authentication tag.
The encrypted file is decrypted.
The original file is released only after successful authentication.


🧪 8. Tamper Detection
---

The project can demonstrate what happens when encrypted data is modified.

For example:

 Original .sfv
     ↓
Modify Ciphertext / Metadata
     ↓
AES-GCM Verification
     ↓
Authentication Failure
     ↓
Decryption Rejected


🔒 9. Private Key Protection
---

The project supports password-protected RSA private keys.

A strong password is recommended when protecting the private key.


🛡️ 10. Input Validation
---

The project includes validation for:

File size
File extensions
RSA keys
.sfv containers
Filenames
Invalid input
Path traversal attempts


📋 11. Activity Logging
---

Security-related events can be recorded through the activity logging system.

Sensitive cryptographic secrets should not be stored in activity logs.



🔄 How the System Works
---
Encryption Process
```
                USER FILE
                    |
                    v
        Generate Random AES-256 Key
                    |
                    v
        Generate Random 96-bit Nonce
                    |
                    v
             AES-256-GCM
                    |
             +------+------+
             |             |
             v             v
        Ciphertext       Tag
                    |
                    |
        AES Key + RSA Public Key
                    |
                    v
             RSA-OAEP-SHA256
                    |
                    v
          Encrypted AES Key
                    |
                    v
        +-----------------------+
        |      .SFV Container   |
        |-----------------------|
        | Header                |
        | Nonce                 |
        | Encrypted AES Key     |
        | Tag                   |
        | Ciphertext            |
        +-----------------------+
```
---
🔓 Decryption Process
---
    

```
                  .SFV FILE
                  |
                  v
          Read Container
                  |
                  v
           RSA Private Key
                  |
                  v
       Recover AES-256 Key
                  |
                  v
        AES-GCM Verification
                  |
           +------+------+
           |             |
        SUCCESS        FAILURE
           |             |
           v             v
      Decrypt File    Reject File
           |
           v
      Original File
```
🔐 Cryptography Concepts Used
---
| Concept                | Implementation                         |
| ---------------------- | -------------------------------------- |
| Symmetric Encryption   | AES-256-GCM                            |
| Asymmetric Encryption  | RSA-3072                               |
| Key Wrapping           | RSA-OAEP                               |
| Hash Algorithm         | SHA-256                                |
| Authentication         | AES-GCM Authentication Tag             |
| Nonce                  | Random 96-bit GCM nonce                |
| Associated Data        | `.sfv` header                          |
| Integrity Verification | SHA-256 + AES-GCM authentication       |
| Key Management         | RSA public/private key pair            |
| Secure Comparison      | HMAC `compare_digest` where applicable |

🛠️ Technologies Used
---
Python
Streamlit
Cryptography
Pytest
Git
GitHub

📚 Python Libraries Used
cryptography
---
Used for:

AES-GCM
RSA
OAEP
SHA-256
Key serialization
Public/private key handling
streamlit

Used to create the graphical web-based user interface.

pytest

Used for automated testing.

Python Standard Library
---
The project also uses modules such as:
```
os
json
base64
struct
datetime
re
hashlib
hmac
```
These support file handling, metadata, encoding, hashing, validation, logging and container processing.

📁 Project Structure
---
```
 secure-file-vault/
│
├── app.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
│
├── data/
│
├── docs/
│
├── screenshots/
│
├── src/
│   │
│   ├── core/
│   │   ├── container.py
│   │   └── validators.py
│   │
│   ├── crypto/
│   │   ├── aes.py
│   │   ├── rsa.py
│   │   └── key_manager.py
│   │
│   ├── security/
│   │   ├── hashing.py
│   │   └── activity_log.py
│   │
│   └── ui/
│       └── components.py
│
└── tests/
```

💻 System Requirements
---
 Hardware
Minimum 4 GB RAM recommended
At least 500 MB free storage
Modern computer capable of running Python
 Software
Windows / Linux / macOS
Python 3.10+
VS Code or another Python IDE
Modern web browser

⚙️ Installation
---
1. Clone the Repository
   ```
   git clone <YOUR-GITHUB-REPOSITORY-LINK>
   
   ```
Move into the project directory:
```
   cd secure-file-vault
```

🐍 2. Create Virtual Environment
---
Windows
```
python -m venv .venv
```
Activate it:
```
.venv\Scripts\activate
```
Linux / macOS
---
```
python3 -m venv .venv
source .venv/bin/activate
```
📦 3. Install Dependencies
---
```
pip install -r requirements.txt
```
▶️ 4. Run the Application
---
```
streamlit run app.py
```
The application will normally open at:

```
http://localhost:8501
```
🧪 Run Tests
---

To run the automated test suite:
```
pytest -v
```
The tests cover important cryptographic and validation workflows such as:

AES encryption/decryption
RSA key operations
Wrong-key rejection
Password-protected private keys
Tamper detection
Invalid containers
SHA-256 verification
Filename sanitization
Extension validation

🖥️ Application Modules
---

The Streamlit application provides the following sections:

🏠 Dashboard

Provides an overview of the Secure File Vault system and cryptographic architecture.

🔑 RSA Key Management

Used to generate and manage RSA-3072 public/private key pairs.

🔐 Encrypt File

Allows the user to:

Select a file.
Upload the RSA public key.
Generate a random AES key.
Encrypt the file using AES-256-GCM.
Wrap the AES key using RSA-OAEP.
Generate the .sfv encrypted container.
🔓 Decrypt File

Allows the user to:

Select an .sfv file.
Upload the RSA private key.
Recover the AES key.
Verify the GCM authentication tag.
Decrypt the original file.
🛡️ Integrity Verification

Allows SHA-256 based file integrity verification and tamper demonstrations.

📊 Security Information

Displays information about the cryptographic algorithms and security architecture.

📋 Activity Log

Displays relevant security activity events.

ℹ️ About Project

Provides project information and educational context.

🎬 Project Demonstration
---
```
Recommended demonstration flow:
1. Open Dashboard
        ↓
2. Generate RSA Key Pair
        ↓
3. Select sample file
        ↓
4. Upload RSA Public Key
        ↓
5. Encrypt File
        ↓
6. Download .sfv file
        ↓
7. Calculate / note SHA-256
        ↓
8. Open Decrypt File
        ↓
9. Upload .sfv + Private Key
        ↓
10. Decrypt
        ↓
11. Compare SHA-256
        ↓
12. Open Integrity Verification
        ↓
13. Run Tamper Demonstration
 ```
📸 Screenshots
---

Dashboard

![Secure File Vault Dashboard](screenshots/dashboard.png)
RSA Key Management
![RSA Key Management](screenshots/rsa-key-management.png)
Encrypt File
![Encrypt File](screenshots/encrypt-file.png)
Decrypt File
![Decrypt File](screenshots/decrypt-file.png)
Integrity Verification
![Integrity Verification](screenshots/integrity-verification.png)

Place the screenshots inside the screenshots/ folder using the filenames shown above.

☁️ Deployment
---

The project can be deployed using Streamlit Community Cloud.

General deployment process:
