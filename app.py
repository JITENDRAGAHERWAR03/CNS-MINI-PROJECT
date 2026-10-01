"""Secure File Vault: Hybrid RSA + AES file encryption (Streamlit UI)."""
import streamlit as st

from src.core import container
from src.core.validators import validate_sfv_name
from src.crypto import key_manager
from src.errors import AuthenticationError, VaultError
from src.security.hashing import hashes_match, sha256_hex
from src.security.security_utils import log_event, read_log
from src.ui.components import info_cards, status_badge

st.set_page_config(page_title="Secure File Vault", page_icon="🔐", layout="wide")

PAGES = ["🏠 Dashboard", "🔑 RSA Key Management", "🔒 Encrypt File", "🔓 Decrypt File",
         "🛡️ Integrity Verification", "📊 Security Information", "📜 Activity Log", "ℹ️ About Project"]
page = st.sidebar.radio("Navigation", PAGES)
st.sidebar.caption("Academic prototype. Not a replacement for audited encryption software.")
st.title("🔐 Secure File Vault")
st.caption("Hybrid RSA-OAEP + AES-256-GCM file encryption")


def read_upload(f) -> bytes:
    return f.getvalue()


if page == PAGES[0]:
    info_cards({"Encryption": "AES-256-GCM", "Key Encryption": "RSA-OAEP", "RSA Key Size": "3072-bit", "Hash": "SHA-256"})
    st.subheader("Architecture")
    st.code("""ENCRYPT                                   DECRYPT
USER FILE -> AES-256-GCM -> ciphert+tag   .SFV -> RSA private key -> AES key
random AES key -> RSA-OAEP(public key)         .SFV ciphertext + AES key -> AES-GCM
   -> encrypted AES key                        -> verify tag -> original file
ciphertext + tag + encrypted key + metadata -> .sfv""", language="text")
    st.markdown("""**Why hybrid?** AES is fast for large files; RSA is slow and size-limited, so RSA only
protects the small AES key. **AES-GCM** gives confidentiality *and* integrity/authenticity.
The container header is authenticated too, so metadata edits are detected.""")

elif page == PAGES[1]:
    st.subheader("Generate RSA-3072 key pair")
    pw = st.text_input("Optional password to protect the private key", type="password",
                       help="Password strength still matters: a weak password weakens the protection.")
    if st.button("Generate RSA Keys"):
        with st.spinner("Generating keys..."):
            priv, pub = key_manager.generate_key_pair(pw or None)
        st.session_state["keys"] = (priv, pub, bool(pw))
        log_event("KEY_GENERATED")
    if "keys" in st.session_state:
        priv, pub, protected = st.session_state["keys"]
        status_badge("ok", "Key pair generated." + (" Private key is password-protected." if protected else ""))
        if not protected:
            status_badge("warn", "Private key is NOT password-protected. Store it safely.")
        c1, c2 = st.columns(2)
        c1.download_button("⬇ private_key.pem", priv, "private_key.pem", "application/x-pem-file")
        c2.download_button("⬇ public_key.pem", pub, "public_key.pem", "application/x-pem-file")
        st.caption("Keep the private key secret and never commit it to Git. Keys live only in this session's memory.")

elif page == PAGES[2]:
    st.subheader("Encrypt a file")
    f = st.file_uploader("File to encrypt")
    pub = st.file_uploader("RSA public key (.pem)", type=["pem"])
    if st.button("Encrypt") and f and pub:
        try:
            data = read_upload(f)
            blob, info = container.encrypt_file(data, f.name, read_upload(pub))
            log_event("FILE_ENCRYPTED", info["original_filename"])
            status_badge("ok", "File encrypted with AES-256-GCM; AES key wrapped with RSA-OAEP.")
            st.json({k: v for k, v in info.items() if k not in ("encrypted_key", "nonce")})
            st.text(f"Original SHA-256: {info['original_sha256']}")
            st.download_button("⬇ Download .sfv", blob, info["original_filename"] + ".sfv")
        except VaultError as e:
            log_event("ENCRYPTION_FAILED", type(e).__name__)
            status_badge("error", str(e))
    elif f is None or pub is None:
        st.info("Select a file and a public key.")

elif page == PAGES[3]:
    st.subheader("Decrypt a .sfv file")
    f = st.file_uploader("Encrypted file (.sfv)")
    priv = st.file_uploader("RSA private key (.pem)", type=["pem"])
    pw = st.text_input("Private key password (if any)", type="password")
    orig = st.text_input("Original SHA-256 (optional, for comparison)")
    if st.button("Decrypt") and f and priv:
        try:
            validate_sfv_name(f.name)
            res = container.decrypt_file(read_upload(f), read_upload(priv), pw or None)
            log_event("FILE_DECRYPTED", res.filename)
            status_badge("ok", "AES-GCM authentication succeeded.")
            st.text(f"Decrypted SHA-256: {res.sha256}")
            if orig.strip():
                ok = hashes_match(orig.strip().lower(), res.sha256)
                status_badge("ok" if ok else "error", "✓ File integrity verified" if ok else "Hash mismatch")
            st.download_button("⬇ Download decrypted file", res.data, res.filename)
        except AuthenticationError as e:
            log_event("DECRYPTION_FAILED", "Authentication failed")
            status_badge("error", "⚠ " + str(e) + " No output file was created.")
        except VaultError as e:
            log_event("DECRYPTION_FAILED", type(e).__name__)
            status_badge("error", str(e))

elif page == PAGES[4]:
    st.subheader("Tamper-detection demonstration")
    st.markdown("Encrypts a small sample in memory, flips **one byte**, and tries to decrypt.")
    if st.button("Run demo"):
        with st.spinner("Running..."):
            priv, pub = key_manager.generate_key_pair()
            sample = b"Hello from Secure File Vault!"
            blob, info = container.encrypt_file(sample, "sample.txt", pub)
            st.write("1. Original SHA-256:", info["original_sha256"])
            ok = container.decrypt_file(blob, priv)
            match = hashes_match(sha256_hex(sample), ok.sha256)
            st.write("2. Untouched file decrypts. Hash match:", "✓" if match else "✗")
            bad = bytearray(blob)
            bad[-1] ^= 1
            try:
                container.decrypt_file(bytes(bad), priv)
                status_badge("error", "Unexpected: tampering NOT detected")
            except AuthenticationError:
                status_badge("ok", "3. One byte modified -> AES-GCM authentication FAILED -> file rejected.")
    st.info("AES-GCM already protects integrity. SHA-256 comparison here is an educational extra, not a replacement.")

elif page == PAGES[5]:
    for q, a in {
        "Symmetric vs asymmetric": "Symmetric (AES) uses one shared key and is fast. Asymmetric (RSA) uses a public/private pair and is slow.",
        "AES-GCM": "A mode of AES giving encryption plus an authentication tag that detects any modification.",
        "Nonce": "A number used once per encryption. Reusing a nonce with the same key breaks GCM security.",
        "Authentication tag": "A 16-byte value verified during decryption; mismatch means data changed or the key is wrong.",
        "RSA-OAEP": "Randomized RSA padding that makes key encryption secure; used here to wrap the AES key.",
        "SHA-256": "A one-way hash. It is not encryption and cannot be reversed.",
        "Why hybrid?": "RSA is slow and can only encrypt data smaller than its key, so RSA protects the AES key and AES protects the file.",
        "Modified ciphertext?": "Tag check fails and decryption is rejected; no output is written.",
        "Wrong private key?": "RSA-OAEP unwrap fails, so the AES key can't be recovered.",
    }.items():
        with st.expander(q):
            st.write(a)

elif page == PAGES[6]:
    st.subheader("Activity log (events only; no secrets are logged)")
    st.code("\n".join(read_log()) or "No activity yet.", language="text")

else:
    st.markdown("""**Secure File Vault**: CNS mini project demonstrating hybrid encryption.

**Limitations:** academic prototype; private-key protection is critical; a compromised device
defeats file encryption; whole files are processed in memory (50 MB limit); the .sfv header reveals
the original filename, size and creation time; on shared hosting, uploaded files pass through the server.

Student Name: ______  Roll No: ______  Batch: ______  College: ______  Department: ______  Year: ______""")
