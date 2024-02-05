# Cryptonova - Cryptocurrency Project

## Overview

Cryptonova is a secure, innovative cryptocurrency designed for seamless transactions and enhanced security. Leveraging public/private key encryption for wallet generation and SHA-256 for hashing, Cryptonova ensures a robust security framework for managing digital assets through blockchain technology.

### Key Features

- **Secure Wallet Generation**: Utilizes RSA encryption to securely manage digital assets.
- **SHA-256 Hashing**: Ensures transaction integrity and security.
- **Blockchain Technology**: Employs blockchain for immutable transaction recording.
- **Simplified Transactions**: Facilitates easy fund transfers and balance checks.

## Getting Started

### Prerequisites

- Python 3.x
- `rsa` Python package for RSA encryption/decryption.

### Installation

1. Clone the repository or download the project files.
2. Install Python 3 if not already installed.
3. Install the `rsa` package:
   ```bash
   pip install rsa
   
## Running Cryptonova

```bash

### Get Wallet Address

./cryptomoney.sh address <wallet_file_name>.wallet.txt

### Fund Wallet

./cryptomoney.sh fund <wallet_tag> <amount> <transaction_file_name>.txt

### Transfer Funds

./cryptomoney.sh transfer <source_wallet_file>.wallet.txt <destination_wallet_tag> <amount> <transaction_statement_file>.txt

### Verify Transaction

./cryptomoney.sh verify <wallet_file>.wallet.txt <transaction_statement_file>.txt

### Check Balance

./cryptomoney.sh balance <wallet_tag>

### Mine Transactions

./cryptomoney.sh mine <difficulty_level>

### Validate Blockchain

./cryptomoney.sh validate





