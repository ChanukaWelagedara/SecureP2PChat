# 🔐 Secure P2P Chat Application

A comprehensive secure peer-to-peer (P2P) chat application built with Java that implements enterprise-grade cryptographic security. This application features end-to-end encryption, perfect forward secrecy, digital signatures, and automatic peer discovery in a fully decentralized architecture.

## 🌟 Key Features

### 🔒 Advanced Security

- **RSA 2048-bit Encryption** - Initial handshake and key exchange
- **Perfect Forward Secrecy (PFS)** - Diffie-Hellman ephemeral key exchange
- **AES Encryption** - Message content encryption after DH exchange
- **Digital Signatures** - SHA256withRSA for message authenticity
- **Message Freshness Validation** - Timestamp-based replay attack protection
- **Salted Password Hashing** - Secure user authentication

### 🚀 User Experience

- **Automatic Peer Discovery** - No manual IP/port configuration needed
- **GUI Interface** - User-friendly graphical interface available
- **Terminal Interface** - Command-line interface for advanced users
- **Real-time Messaging** - Instant secure communication
- **Chat Request System** - Accept/reject incoming chat requests
- **Online User Listing** - View all available peers

### 🏗️ Architecture

- **True P2P** - No central server required
- **Decentralized Registry** - Peer discovery through local file system
- **Multi-threaded** - Concurrent handling of multiple connections
- **Cross-platform** - Java-based for universal compatibility

## 📋 Requirements

- **Java JDK 11** or higher
- **Terminal/Command Prompt** for command-line interface
- **Git** (optional, for cloning repository)

## 🚀 Quick Start

### 1. Compilation

Navigate to the project directory and compile all Java files:

```bash
javac *.java
```

### 2. User Registration

Register users before chatting:

```bash
java RegisterUser
```

**Example:**

```
Enter username: alice
Enter password: mySecurePassword123
User registered successfully!
```

This creates:

- `keys/alice.pub` (RSA public key)
- `keys/alice.pri` (RSA private key)
- Adds user credentials to `users.txt`

Repeat for additional users (e.g., bob, charlie).

### 3. Starting the Application

#### Option A: Terminal Interface

```bash
java PeerChat
```

**User Experience:**

```
Enter username: alice
Enter password: mySecurePassword123
Authentication successful!
Enter your listening port: 5000
Listening for incoming connections on port 5000...

Enter 'list' to view online users or username to chat (or 'exit'): list

=== Online Peers ===
 - bob
 - charlie

Enter 'list' to view online users or username to chat (or 'exit'): bob
Start chatting with bob. Type 'quit' to end chat.
[You] > Hello Bob!
[bob] > Hi Alice! How are you?
```

#### Option B: GUI Interface

```bash
java ChatAppLauncher
```

Features a complete graphical interface with:

- Login window with authentication
- Registration dialog for new users
- Main chat window with peer discovery
- "List Online Users" button for peer selection
- Automatic connection handling

## 🔧 How It Works

### Cryptographic Flow

1. **Authentication** - User credentials verified with salted hash
2. **RSA Handshake** - Initial secure channel establishment
3. **DH Key Exchange** - Ephemeral keys generated for PFS
4. **AES Communication** - All messages encrypted with shared secret
5. **Digital Signatures** - Every message signed and verified

### Peer Discovery

1. **Registration** - Peers register IP:PORT in `peers.txt`
2. **Discovery** - Users can list all online peers
3. **Connection** - Connect by username (automatic IP/port lookup)
4. **Request System** - Chat requests must be accepted

### Message Security

- **End-to-End Encryption** - Only sender/receiver can read messages
- **Perfect Forward Secrecy** - Each session uses unique keys
- **Non-repudiation** - All messages digitally signed
- **Integrity Protection** - Tampering detection via signatures

## 📁 Project Structure

```
Secure-P2P-ChatApp/
├── PeerChat.java           # Main P2P chat application
├── CryptoUtils.java        # Cryptographic utilities
├── UserManager.java        # User authentication system
├── RegisterUser.java       # User registration utility
├── MessageLogger.java      # Encrypted message logging
├── LogViewer.java         # Log file viewer
├── LoginFrame.java        # GUI login interface
├── RegistrationDialog.java # GUI registration dialog
├── MainChatFrame.java     # GUI main chat window
├── ChatAppLauncher.java   # GUI application launcher
├── keys/                  # RSA key storage directory
├── users.txt             # User credential database
├── peers.txt             # Peer registry file
├── auth_log.txt          # Authentication log
└── encrypted_messages.txt # Encrypted message log
```

## � Logging and Monitoring

### Authentication Logs

```bash
# View authentication attempts
cat auth_log.txt
```

### Message Logs

```bash
# View encrypted message history
java LogViewer
```

### Real-time Monitoring

All cryptographic operations and peer connections are logged with timestamps for security auditing.

## 🛡️ Security Implementation Details

### Encryption Standards

- **RSA-2048** - Asymmetric encryption for initial handshake
- **AES-256** - Symmetric encryption for message content
- **SHA-256** - Cryptographic hashing for signatures
- **PBKDF2** - Password-based key derivation

### Security Measures

- **Replay Protection** - 60-second message freshness window
- **Key Rotation** - New DH keys for each chat session
- **Signature Verification** - All messages cryptographically verified
- **Secure Random** - Cryptographically secure random number generation

### Attack Mitigation

- **Man-in-the-Middle** - RSA public key authentication
- **Replay Attacks** - Timestamp validation
- **Message Tampering** - Digital signature verification
- **Password Attacks** - Salted hash storage

## 🎯 Usage Examples

### Terminal Workflow

```bash
# Start first user
java PeerChat
# alice, password, port 5000

# Start second user
java PeerChat
# bob, password, port 6000

# Bob connects to Alice
Enter 'list' to view online users or username to chat: alice
Start chatting with alice. Type 'quit' to end chat.
[You] > Hello Alice!
```

### GUI Workflow

1. Launch `java ChatAppLauncher`
2. Login with credentials
3. Click "List Online Users"
4. Select peer and start chatting

