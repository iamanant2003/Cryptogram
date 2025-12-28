# Cryptogram
Cryptogram is a comprehensive, full-stack web application designed to provide enterprise-grade security for file operations, including encryption, decryption, hashing, and secure cloud storage. Built with a focus on usability, security, and performance, Cryptogram bridges the gap between advanced cryptographic techniques &amp; friendly UI interaction.

## Features
**🔒 Core Security**
* AES-256 & DES Encryption – Industry-standard symmetric encryption
* SHA-256/512 Hashing – Cryptographic integrity verification
* PBKDF2 Key Derivation – 100,000 iterations with unique salt
* Auto-Expiring Files – Encrypted files expire after 5 minutes
* Zero Key Storage – Passwords never stored on server<br><br>

**☁️ Cloud Integration**
* Dropbox Storage – Secure cloud backup for files and hashes
* File Management – Upload, retrieve, delete from unified dashboard
* Optional Sync – Choose to store encrypted files in cloud
* Compressed Storage – Files automatically zipped before upload<br><br>

**🎯 User Experience**
* Modern Dashboard – Clean, responsive interface with dark/light modes
* Drag & Drop – Intuitive file upload interface
* Real-Time Feedback – Live password strength meter and activity feed
* Comprehensive Guide – Built-in tutorials and best practices
* Customizable Settings – Tailor the app to your preferences<br><br>

**🔍 Verification System**
* Hash Generation – Create unique fingerprints for any file
* Integrity Checking – Verify files haven't been tampered with
* Dual Storage – Hashes saved locally and in Dropbox
* Tamper Detection – Instant alerts for modified files

## User Guide
**1. Dashboard**
* Monitor encrypted, stored, and verified file counts
* Quick-access buttons for common operations
* Recent activity timeline<br><br>

**2. Encrypt a File**
* Select "Encrypt" action
* Choose AES (recommended) or DES algorithm
* Drag & drop your file
* Set a strong password (12+ characters recommended)
* Optional: Enable Dropbox storage
* Click "Process File"<br><br>

**3. Decrypt a File**
* Upload .enc file
* Enter the exact password used during encryption
* File must be decrypted within 5 minutes of encryption
* Download the restored original file<br><br>

**4. Generate & Verify Hashes**
* Generate: Create SHA-256/512 hash for any file
* Verify: Compare file against stored hash to detect tampering
* Store: Save hashes locally or in Dropbox for future verification<br><br>

**5. Cloud Storage**
* Upload: Store files directly to Dropbox (automatically zipped)
* Manage: View, download, or delete stored files
*Bulk Operations: Download or delete multiple files at once<br><br>

## 🔧 Technical Details
**Encryption Process**
* Salt Generation: 16 random bytes for each operation
* Key Derivation: PBKDF2-HMAC-SHA256 (100k iterations)
* Encryption: AES-256-CBC with random IV
* Packaging: [Salt][Timestamp][IV][Encrypted Data]
* Expiry: Embedded timestamp enforces 5-minute validity

**Security Features**
* End-to-End Encryption: Files encrypted before transmission
* Secure Memory Handling: Keys wiped from memory after use
* Input Validation: Protection against injection attacks
* HTTPS Ready: Built for secure deployment
* No Metadata Leakage: Minimal information stored

## 🔮 Future Roadmap
**Planned Features**
* Multi-Cloud Support – AWS S3, Google Drive, Azure
* File Sharing – Password-protected, expiring links
* Mobile Apps – iOS and Android clients
* Quantum-Resistant Algorithms – Post-quantum cryptography
* API Access – RESTful API for integration
* Batch Processing – Encrypt/decrypt multiple files
* Advanced Analytics – Usage reports and security audits

**Security Enhancements**
* Hardware Security Module (HSM) integration
* WebAssembly Crypto – Browser-based processing
* FIDO2/WebAuthn – Passwordless authentication
* Blockchain Verification – Immutable hash storage

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
* Hardware Security Module (HSM) integration
* WebAssembly Crypto – Browser-based processing
* FIDO2/WebAuthn – Passwordless authentication
* Blockchain Verification – Immutable hash storage
