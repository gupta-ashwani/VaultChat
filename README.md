# VaultChat: Secure XML Messaging System

VaultChat is a decentralized, End-to-End Encrypted (E2EE) messaging application built upon the SOAP protocol. Designed with a zero-knowledge server architecture, it ensures that the central messaging broker remains entirely "blind" to all conversations. By strictly enforcing W3C XML Security standards—including AES-256 payload encryption, RSA Digital Signatures, and Exclusive Canonicalization—VaultChat guarantees message confidentiality, integrity, and non-repudiation.

## Core Features

* **End-to-End Encryption (E2EE):** All messages are encrypted locally on the client using AES-256-CBC before transmission. The central server never processes or stores plaintext messages.
* **RSA Digital Signatures:** Every message is cryptographically signed using the sender's RSA-2048 private key. The receiving client validates this signature against the canonicalized XML payload to ensure the message was not tampered with and originated from a trusted source.
* **Zero-Knowledge Architecture:** The central SOAP broker is responsible exclusively for routing and temporary storage of encrypted XML blobs. It holds no private keys and cannot decrypt network traffic.
* **Strict Public Key Infrastructure (PKI):** Contact exchange is facilitated through unique, server-generated "Friend Codes", preventing man-in-the-middle (MITM) attacks and impersonation.
* **Persistent Local Storage:** Client instances maintain their own independent SQLite databases to persist cryptographic keys, contact lists, and decrypted chat histories across sessions.

## System Architecture

The system follows a distributed Client-Server model tailored for secure communication:

1. **Central SOAP Server:** Acts as the messaging broker. It exposes WSDL endpoints to handle user registration, key distribution, and message routing. It uses an SQLite database to store user public keys and encrypted message queues.
2. **Local Client Bridge:** A local Flask server that acts as the user's proxy. It provides a modern web interface, manages the local SQLite database (storing private keys and chat history), and handles all heavy cryptographic operations (AES encryption, RSA signing, XML Canonicalization) before interacting with the central server via SOAP.

## Technologies Used

* **Language:** Python 3
* **Web Service Protocol:** SOAP 1.1, WSDL
* **Web Framework:** Flask (Server and Client Bridge)
* **XML Processing:** lxml (DOM manipulation and Exclusive Canonicalization)
* **Cryptography:** python-cryptography (AES-256, RSA-OAEP, SHA-256)
* **SOAP Client:** Zeep
* **Database:** SQLite3
* **Frontend:** HTML5, CSS3, JavaScript (ES6+)

## Installation and Setup

### Prerequisites

Ensure you have Python 3.8 or higher installed on your system.

### Environment Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/gupta-ashwani/VaultChat.git
   cd VaultChat
   ```
2. Create and activate a virtual environment (recommended):

   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Unix/MacOS:
   source venv/bin/activate
   ```
3. Install the required dependencies:

   ```bash
   pip install flask lxml zeep cryptography
   ```

## Usage Instructions

To run the application locally, you must start the central SOAP server and at least one local client instance.

### 1. Start the Central SOAP Server

Open a terminal and start the server:

```bash
python server.py
```

The server will bind to `http://127.0.0.1:8000` and generate an empty `secure_messaging.db` database.

### 2. Start the Local Clients

To simulate two different users (e.g., Alice and Bob), open two additional terminals and start two separate client bridges on different ports:

**Terminal 2 (Client A):**

```bash
python web_client.py 5000
```

**Terminal 3 (Client B):**

```bash
python web_client.py 5001
```

### 3. Accessing the Interface

1. Open your web browser and navigate to `http://127.0.0.1:5000` (Client A). Register a new user to generate a local RSA key pair and a unique Friend Code.
2. Open another browser tab and navigate to `http://127.0.0.1:5001` (Client B). Register a second user.
3. Use the generated Friend Codes displayed in the user interface to add each user as a contact securely. Once added, you can exchange encrypted XML messages.

## Security Disclaimer

This project was developed as an academic implementation of W3C XML Security standards. While it utilizes industry-standard cryptographic algorithms, it has not undergone formal security auditing and should not be used for highly sensitive or production-grade communications without further review.
