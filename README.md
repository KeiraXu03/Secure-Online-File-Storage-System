# Secure Online File Storage System

## Overview
This project implements a secure web-based file storage system that allows users to upload, download, and share files with strong security guarantees. The design emphasizes confidentiality, authentication, and access control, ensuring that sensitive data remains protected even against a curious server or unauthorized adversaries.

**Key features:**
- Client-side encryption (RSA) – the server never sees plaintext files.
- Secure authentication with password hashing and multi-factor authentication (OTP).
- Fine-grained access control for file ownership and sharing.
- Audit logging of user actions for traceability.

---

## Features

### User Management
- **Registration**
  - Strong password policy (≥8 chars, digit, letter, special char).
  - Validates duplicate usernames/emails.
- **Login**
  - bcrypt for password hashing.
  - pyotp for OTP verification.
- **Password Reset**
  - Requires OTP + email verification.
  - New password stored only as bcrypt hash.
- **Multi-Factor Authentication (MFA)**
  - Time-based OTP (TOTP) using `pyotp`.
  - QR-code provisioning for authenticator apps.

### File Management
- **Upload**
  - Files are encrypted client-side before upload.
  - Metadata (hashed filename & owner) stored in DB.
- **Download**
  - OTP verification required.
  - Ownership and sharing checked before access.
- **Update/Edit**
  - Only owners can edit content.
  - Encrypted updates via Base64-encoded data.
- **Sharing**
  - Owners can share files with specific users.
  - Sharing list maintained in DB.

### Security Protections
- Client-side encryption prevents server access to plaintext.
- SQLAlchemy ORM prevents SQL injection.
- Session-based authentication ensures identity validity.
- Audit logging records all sensitive operations.
- Admin-only log access (logs are immutable).

---

## Threat Model

- **Adversary 1: Cloud Server**  
  Passive attacker observing stored data and traffic.  
  → Mitigation: All files encrypted on client-side.

- **Adversary 2: Unauthorized User**  
  Attacker attempting credential theft or SQL injection.  
  → Mitigation: OTP, bcrypt hashing, SQLAlchemy parameterized queries.

---

## Algorithms & Implementation

- **Authentication**
  - bcrypt for password hashing.
  - pyotp for OTP validation.
  - Flask session cookies.
- **Encryption**
  - Client-side RSA for file encryption.
  - Server stores only ciphertext.
- **Access Control**
  - Owner-only modification rights.
  - Sharing list for delegated access.
- **Logging**
  - All actions logged.
  - Admin-only dashboard for review.

---

## Example Test Cases

- **Unauthorized File Access**  
  User B cannot access User A’s file without explicit sharing, even if User B obtains the file key.

- **SQL Injection Attempt**  
  Input like `"' OR '1'='1"` is neutralized by SQLAlchemy’s parameterized queries.

---

## Tech Stack
- **Frontend**: HTML/CSS/JavaScript (with client-side crypto).  
- **Backend**: Flask + SQLAlchemy (Python).  
- **Database**: SQLite/MySQL.  
- **Security Libraries**: bcrypt, pyotp, qrcode, RSA.


