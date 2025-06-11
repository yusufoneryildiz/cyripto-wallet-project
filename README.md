# Raspberry Pi Crypto Hardware Wallet

A standalone, Python-based hardware wallet for Raspberry Pi that lets you securely generate, store, and use Bitcoin keys without exposing your private keys to the internet. Featuring ECC key management, AES-256 encrypted storage, PIN protection, OLED prompts and physical button confirmation for every transaction.

## 🚀 Features

- **ECC Key Generation & Management**  
  - P-256 & secp256k1 ECDSA private keys  
  - Exportable in DER & WIF formats  
- **Secure Storage**  
  - AES-256-CBC encryption with PBKDF2-derived keys  
  - Salted SHA-256 PIN for local access control  
- **Bitcoin Transaction Support**  
  - Build, serialize & sign P2PKH transactions  
  - DER-encoded ECDSA signatures with SIGHASH_ALL  
  - Self-verification before broadcast  
- **User Interface**  
  - 128×64 OLED display for prompts, status & countdowns  
  - GPIO-driven button for approving sensitive operations  
  - Console fallback for headless operation  
- **Utility Modules**  
  - Custom SHA-256 & HMAC-SHA256 implementations  
  - AES encryption helpers, key/address derivation, misc. utils  

## 📁 Repository Structure

├── main.py # Launch wallet UI, PIN & button flow
├── key_manager.py # ECC key generation & AES-encrypted storage
├── signer.py # SHA-256 hashing & ECDSA signature routines
├── bitcoin_keys.py # Bitcoin key/address (WIF, Base58) logic
├── bitcoin_transactions.py # P2PKH transaction builder & serializer
├── pin_manager.py # PIN setup, verify & lockout logic
├── encryptor.py # AES-256-CBC encryption/decryption helper
├── sha_256.py # Pure-Python SHA-256 & HMAC-SHA256 implementation
├── utils.py # Miscellaneous helper functions
├── demo_bitcoin.py # Interactive demo: key gen & tx signing
└── requirements.txt # Python dependencies

markdown
Kodu kopyala

## ⚙️ Prerequisites

- **Hardware:** Raspberry Pi (any model with GPIO), OLED display (128×64 SSD1306), 1–2 buttons  
- **Software:**  
  - Python 3.7+  
  - Libraries: `pycryptodome`, `ecdsa`, `base58`, `adafruit-ssd1306`, `RPi.GPIO`

## 💾 Installation

1. Clone the repo:  
   ```bash
   git clone https://github.com/yourusername/raspberrypi-crypto-wallet.git
   cd raspberrypi-crypto-wallet
Install dependencies:

bash
Kodu kopyala
pip install -r requirements.txt
🚦 Usage
Wiring

Connect your OLED to I²C (SDA, SCL)

Wire a push-button to a GPIO pin and GND

Run the Wallet Interface

bash
Kodu kopyala
python main.py
On-Screen Flow

Set PIN

Generate or Import Key

Create & Sign Transaction

Confirm via Button

View Signature & Broadcast

Demo Script

bash
Kodu kopyala
python demo_bitcoin.py
Quickly walk through key generation, address display, transaction signing, and verification in your terminal.

🛠️ Module Overview
key_manager.py – Handles ECC key pairs, AES encryption/decryption, key import/export.

signer.py – Implements hashing (SHA-256, HMAC) and ECDSA signing/verification.

bitcoin_keys.py – Converts ECC keys into Bitcoin WIF, Base58 addresses.

bitcoin_transactions.py – Builds raw P2PKH transactions; serializes & signs them.

pin_manager.py – Manages PIN creation, salted hashing, retry limits & lockouts.

encryptor.py – AES-CBC cipher wrapper with random IV & PKCS7 padding.

sha_256.py – Pure-Python implementation of SHA-256 & HMAC-SHA256 (no external libs).

utils.py – Helper routines: byte conversions, checksums, timing, etc.

🤝 Contributing
Fork the repository

Create a feature branch (git checkout -b feature/YourFeature)

Commit your changes (git commit -m "Add YourFeature")

Push to your fork (git push origin feature/YourFeature)

Open a Pull Request

Please follow the existing code style and include tests for new functionality.
