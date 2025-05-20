
# Secure Banking System

This project simulates a secure client-server ATM banking application developed as part of the COE817 Network Security course at Toronto Metropolitan University. It includes features such as user registration, login, secure transaction processing, and cryptographically protected audit logging.

## Key Features

- Encrypted login and registration using **AES (Fernet)**.
- Mutual authentication and secure key exchange between client and server.
- Encrypted and authenticated deposit, withdrawal, and balance inquiry transactions.
- Tamper-proof audit logging using **HMAC-SHA256**.
- Real-time socket communication over TCP.
- GUI interface for ATM client built using **Tkinter**.
- Multi-threaded server to handle multiple clients simultaneously.

## Project Structure

```
Secure-Banking-System/
├── ATM_client.py             # Client-side GUI and transaction logic
├── bank_server.py            # Multi-threaded server with encryption and logging
├── db.py                     # Lightweight TinyDB-based account database
├── audit_log.txt             # Audit log of all transactions
├── README.md                 # Project instructions and setup guide
└── requirements.txt          # List of required Python libraries
```

## Prerequisites

- Python 3.8+
- Libraries:
  - `cryptography`
  - `tinydb`
  - `tkinter` (comes with most Python installs)
  - `socket`
  - `threading`
  - `datetime`
  - `json`
  - `base64`

Install dependencies:

```bash
pip install -r requirements.txt
```

## How to Run the Project

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/secure-banking-system.git
cd secure-banking-system
```

### 2. Run the Bank Server

In one terminal, start the server:

```bash
python bank_server.py
```

### 3. Run the ATM Client

In a separate terminal, start the ATM GUI:

```bash
python ATM_client.py
```

You can now register a new user, log in, deposit/withdraw funds, and check your balance via the GUI.

## Security Overview

- **Encryption:** AES symmetric encryption via Python's `Fernet`.
- **Integrity:** Verified using `HMAC-SHA256`.
- **Replay Protection:** Timestamps are checked on every request (2-minute validity window).
- **Audit Logging:** Transactions are logged with timestamps, usernames, and actions, and validated via HMAC.

## Authors

- Vaishali Jadon 
- Atiya Azeez 
- Astha Patel 
- Waneeha Samoon 

This project was developed for academic purposes only under TMU’s course COE817.
