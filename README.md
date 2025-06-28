# Eden Core

Universal Source Code Protection System

## Overview

Eden Core is a universal source code protection system that uses enterprise-grade cryptography (secp256k1 elliptic curve) to protect source code files from various programming languages. It provides enterprise-grade security with advanced features like multi-signature authentication, time-based access control, ownership management, and programmable access policies.

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org/dl/)

**Universal Source Code Protection System**

*Advanced cryptographic protection using secp256k1 elliptic curve cryptography*

</div>

---

## Features

### Core Security
- **secp256k1 Elliptic Curve** - Enterprise-grade cryptography
- **XOR Encryption with ECDH** - Key derivation from elliptic curve operations
- **Multi-layer Protection** - Configurable security layers
- **Advanced Features**: MultiAuth, TimeLock, Ownership control, PolicyScript

### Language Support
- **Universal**: Python, PHP, JavaScript, Go, Java, Ruby, Perl
- **Cross-platform**: Windows, macOS, Linux
- **Runtime Protection**: Files remain encrypted at rest

---

## Quick Start

### Installation

```bash
git clone https://github.com/purwowd/eden-core.git
cd eden-core
make build
```

### Basic Usage

```bash
# Protect a file
./bin/eden -protect -input app.py -output ./protected

# Run protected file  
./bin/eden -run -input protected/files/[file_id].eden

# Show examples
./bin/eden -examples
```

### Complete Documentation

📖 **[User Guide](docs/user-guide.md)** - Complete documentation including:
- Installation & Quick Start
- Usage Guide & Examples  
- Performance Optimization
- Security Features
- Troubleshooting & Best Practices
- Advanced Features & API Reference

---

## Command Line Interface

### Basic Commands

```bash
# Protection
eden -protect -input <file> -output <dir>

# Execution
eden -run -input <protected-file>

# Advanced protection
eden -protect -input <file> -multiauth '2-of-3' -signers 'key1,key2,key3'
eden -protect -input <file> -timelock '+24h'
```

---

## Configuration

Environment variables:

```bash
export EDEN_LOG_LEVEL=info
export EDEN_SECURITY_MAX_FILE_SIZE=104857600
export EDEN_STORAGE_BASE_PATH=./data
```

---

## Architecture

### Project Structure

```
eden-core/
├── cmd/eden/              # CLI application
├── pkg/
│   ├── core/              # Protection engine
│   ├── crypto/            # Cryptographic operations
│   └── network/           # Network security
├── internal/
│   ├── config/            # Configuration management
│   └── storage/           # Storage management
├── examples/              # Usage examples
└── tests/                 # Test suite
```

### Security Stack

```
Input Validation → MultiAuth/TimeLock/Ownership → XOR+ECDH → secp256k1 → Encrypted Storage
```

---

## Security Specification

| Component | Implementation |
|-----------|----------------|
| **Symmetric Encryption** | XOR with ECDH-derived keys |
| **Asymmetric Crypto** | secp256k1 Elliptic Curve |
| **Key Derivation** | ECDH + SHA-256 |
| **Digital Signatures** | ECDSA |
| **Security Level** | 256-bit |

---

## Testing

```bash
# Run tests
make test

# Run benchmarks  
go test -bench=. ./pkg/core/

# Coverage report
go test -coverprofile=coverage.out ./...
```

---

## Docker Support

```bash
docker build -t eden-core .
docker run -v $(pwd):/workspace eden-core -protect -input /workspace/app.py
```

---

## Performance

| Operation | Performance |
|-----------|-------------|
| **File Protection** | ~1000 files/second |
| **Encryption** | ~50MB/second |
| **Key Generation** | ~500 keys/second |

---

## License

MIT License - see [LICENSE](LICENSE) file for details.

---

## Support

- Issues: [GitHub Issues](https://github.com/purwowd/eden-core/issues)
- Email: support@purwowd.com

---

<div align="center">

**Built with Go for Enterprise Security**

</div>
