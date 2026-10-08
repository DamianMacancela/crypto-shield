crypto-shield
=============

*a CLI tool to encrypt and decrypt files using AES-256-GCM*

**crypto-shield** is a Python utility built to apply robust cryptographic primitives in practice. It uses `cryptography.hazmat` to handle AES-256 in Galois/Counter Mode (GCM) for authenticated encryption, and PBKDF2 for secure key derivation.

### Features
* **AES-256-GCM:** Ensures both confidentiality and data integrity.
* **PBKDF2-HMAC-SHA256:** Key derivation with 480,000 iterations and a unique 16-byte salt per file.
* **File Agnostic:** Encrypts any file format (PDF, DOCX, ZIP, etc.).

### Build / Install

```bash
git clone https://github.com/DamianMacancela/crypto-shield.git
cd crypto-shield
pip install -r requirements.txt
```

### Usage

**Encrypt:**
```bash
python crypto_shield.py encrypt document.pdf
```
*(Outputs `document.pdf.enc` and preserves the original file).*

**Decrypt:**
```bash
python crypto_shield.py decrypt document.pdf.enc
```
*(Outputs the restored `document.pdf`).*

### Warning
This is a learning and personal-use tool built to understand low-level cryptographic implementation. For life-or-death operational security, use established tools like GPG or Age.

### License
MIT
