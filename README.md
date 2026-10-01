# 🔐 Secure File Vault
Hybrid RSA-OAEP + AES-256-GCM file encryption, a CNS mini project (Python, Streamlit, `cryptography`).

## How it works
**Encrypt:** random AES-256 key + random 96-bit nonce → AES-GCM encrypts the file (ciphertext + 16-byte tag) → the AES key is wrapped with the RSA public key (OAEP-SHA256) → everything is stored in a `.sfv` container.
**Decrypt:** RSA private key unwraps the AES key → AES-GCM decrypts and verifies the tag → the file is released only if authentication succeeds.

`.sfv` layout: `"SFV1" | header length | JSON header | tag | ciphertext`. The header (nonce, wrapped key, names, sizes, timestamp) is passed to GCM as associated data, so editing metadata is detected too. Base64 is used only to fit binary values into JSON.

## Project structure
`app.py` UI · `src/crypto/` (aes, rsa, key_manager) · `src/core/` (container, validators) · `src/security/` (hashing, activity log) · `tests/`

## Install & run
```
python -m venv .venv
.venv\Scripts\activate        # Windows   (Linux/macOS: source .venv/bin/activate)
pip install -r requirements.txt
streamlit run app.py
pytest -v
```

## Deploy (Streamlit Community Cloud)
Push to GitHub (keys are git-ignored) → share.streamlit.io → New app → pick repo, branch, `app.py`. The app uses in-memory uploads/downloads only, so no local paths are needed. On a hosted app, files pass through the server, so use it for demos only.

## GitHub upload
```
git init && git add . && git commit -m "Secure File Vault"
git branch -M main && git remote add origin <your-repo-url> && git push -u origin main
```
Check `git status` first: no `*.pem`, `*.sfv`, or `.env` should be listed.

## Security notes and limitations
Academic prototype. Private-key protection is critical (password protection helps only if the password is strong). A compromised computer defeats file encryption. Whole files are processed in memory (50 MB limit). The container reveals filename, size and time. Not audited; not a replacement for professional software.

## Threat model (short)
Stolen `.sfv` → no plaintext without the private key · modified ciphertext/metadata → GCM tag fails · wrong key → AES-key unwrap fails · stolen private key → attacker can decrypt files for that key · weak key password → weaker protection.

## Demo
Dashboard → generate keys → encrypt `data/sample.txt` → note SHA-256 → decrypt with the private key → compare hashes → Integrity Verification page → run the tamper demo.

## Authors
Student Name · Roll Number · Batch · College · Department · Academic Year (fill in)
