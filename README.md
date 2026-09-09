<div align="center">

# 🚇 PsiTunnel ( Web Filter and Firewall Bypass)

### Python Psiphon-Inspired Circumvention Tunnel

**A lightweight, encrypted, multi-transport tunneling and proxy suite written in Python.**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python\&logoColor=white)
![License](https://img.shields.io/badge/License-See%20Repository-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![AsyncIO](https://img.shields.io/badge/AsyncIO-Powered-purple)
![Cryptography](https://img.shields.io/badge/Cipher-ChaCha20--Poly1305-orange)

<br>

> 🔐 Multi-transport fallback • SOCKS5 • HTTP CONNECT • AEAD encryption • Async architecture

<br>

⭐ **If you find PsiTunnel useful, please consider starring the repository.**

</div>

---

## 📖 Overview

**PsiTunnel** is a Python-based tunneling and proxy suite inspired by architectural concepts used by systems such as **Psiphon**.

It provides a local SOCKS5 and HTTP CONNECT proxy while forwarding traffic through an encrypted remote relay using multiple transport mechanisms.

PsiTunnel focuses on:

* Multi-transport connectivity
* Automatic transport fallback
* Authenticated encryption
* Traffic framing and padding
* Remote DNS resolution
* Local SOCKS5 and HTTP CONNECT ingress
* Lightweight asynchronous networking
* Cross-platform Python deployment

The project is intended for **research, experimentation, privacy engineering, networking education, and authorized environments**.

---

# ✨ Features

## 🔄 Multi-Transport Fallback Engine

PsiTunnel can attempt several transport mechanisms in a configurable priority order.

If one transport becomes unavailable, the client can automatically attempt another transport without requiring the local proxy configuration to change.

```text
WebSocket
    ↓
TLS
    ↓
Obfuscated TCP
```

Configure transport order with:

```bash
--transports "ws,tls,obfs"
```

---

## 🌐 Multiple Transport Modes

### 1. WebSocket — `ws`

Encapsulates tunnel traffic inside a WebSocket connection.

```text
HTTP/1.1
      ↓
WebSocket Upgrade
      ↓
Encrypted Tunnel Frames
```

Useful when infrastructure already supports:

* HTTP reverse proxies
* WebSocket gateways
* Cloud edge infrastructure
* Standard HTTP/TLS stacks

### 2. TLS Transport — `tls`

Carries tunnel frames over standard TLS connections.

Supported features include:

* TLS 1.2 / TLS 1.3
* Configurable SNI
* ALPN negotiation
* Custom TLS certificates
* Self-signed certificates for development environments

### 3. Obfuscated Stream — `obfs`

Direct TCP transport with encrypted tunnel framing.

Features include:

* Pre-shared-key authentication
* ChaCha20-Poly1305 authenticated encryption
* Random frame padding
* Variable packet sizes
* Lightweight transport overhead

---

# 🔐 Cryptography

PsiTunnel uses authenticated encryption for tunnel frames.

### AEAD Cipher

```text
ChaCha20-Poly1305
```

### Key Derivation

```text
HKDF-SHA256
```

Separate directional keys are generated:

```text
client_to_server
server_to_client
```

---

# 🖥️ Local Proxy Interfaces

## SOCKS5

Default:

```text
127.0.0.1:1080
```

Supports IPv4, IPv6, domain names, and remote target DNS resolution.

## HTTP CONNECT

Default:

```text
127.0.0.1:8080
```

Compatible with browsers, `curl`, CLI tools, and applications supporting HTTP CONNECT.

---

# ⚡ Multiplexed Architecture

A single encrypted tunnel can carry multiple logical streams.

```text
Browser Tab 1 ─┐
Browser Tab 2 ─┤
CLI Request   ─┼──► Multiplexer ───► Encrypted Tunnel
Application   ─┤
API Request   ─┘
```

---

# 📚 Usage Guide

For complete setup instructions, configuration examples, deployment notes, proxy configuration, and advanced usage, see the full usage documentation:

## 👉 [Read the complete USAGE.md guide](https://github.com/sweenyxq-gif/psitunnel/blob/main/USAGE.md "PsiTunnel Usage Guide")

> New users should start with `USAGE.md` before deploying PsiTunnel to a remote server.

---

# 🚀 Quick Start

## 1. Requirements

```text
Python 3.10+
```

Install the dependency:

```bash
pip install cryptography
```

## 2. Start the Relay Server

```bash
python cli.py server \
  --psk "your-super-secret-key" \
  --obfs-port 9001 \
  --tls-port 9002 \
  --ws-port 9003
```

## 3. Start the Client

```bash
python cli.py client \
  --server 127.0.0.1 \
  --psk "your-super-secret-key" \
  --transports "ws,tls,obfs"
```

PsiTunnel starts:

```text
SOCKS5 Proxy  → 127.0.0.1:1080
HTTP CONNECT  → 127.0.0.1:8080
```

> 📘 For detailed deployment and usage instructions, see [USAGE.md](https://github.com/sweenyxq-gif/psitunnel/blob/main/USAGE.md "PsiTunnel Usage Guide").

---

# 🧪 Usage Examples

## SOCKS5 with `curl`

```bash
curl --socks5-hostname 127.0.0.1:1080 https://httpbin.org/ip
```

## HTTP CONNECT

```bash
curl -x http://127.0.0.1:8080 https://httpbin.org/ip
```

---

# 🌍 Browser Configuration

### SOCKS5

```text
Host: 127.0.0.1
Port: 1080
Type: SOCKS5
```

### HTTP

```text
Host: 127.0.0.1
Port: 8080
Type: HTTP
```

For advanced browser, system proxy, VPS, and remote deployment instructions:

👉 [USAGE.md](https://github.com/sweenyxq-gif/psitunnel/blob/main/USAGE.md "PsiTunnel Usage Guide")

---

# ⚙️ Command-Line Options

## Server

| Option        | Default                          | Description                   |
| ------------- | -------------------------------- | ----------------------------- |
| `--host`      | `0.0.0.0`                        | Server bind address           |
| `--psk`       | `psitunnel-secret-key-change-me` | Pre-shared authentication key |
| `--obfs-port` | `9001`                           | Obfuscated TCP listener       |
| `--tls-port`  | `9002`                           | TLS listener                  |
| `--ws-port`   | `9003`                           | WebSocket listener            |
| `--cert`      | `None`                           | TLS certificate               |
| `--key`       | `None`                           | TLS private key               |

## Client

| Option         | Default                          | Description               |
| -------------- | -------------------------------- | ------------------------- |
| `--server`     | `127.0.0.1`                      | Relay hostname or IP      |
| `--psk`        | `psitunnel-secret-key-change-me` | Shared authentication key |
| `--transports` | `ws,tls,obfs`                    | Transport fallback order  |
| `--obfs-port`  | `9001`                           | Remote OBFS port          |
| `--tls-port`   | `9002`                           | Remote TLS port           |
| `--ws-port`    | `9003`                           | Remote WebSocket port     |
| `--sni`        | `None`                           | Optional TLS SNI hostname |
| `--local-host` | `127.0.0.1`                      | Local proxy bind address  |
| `--socks-port` | `1080`                           | SOCKS5 proxy port         |
| `--http-port`  | `8080`                           | HTTP CONNECT proxy port   |

---

# 🧪 Testing

```bash
python -m unittest discover tests
```

Verbose mode:

```bash
python -m unittest discover -v tests
```

---

# 🔒 Security Notes

Before exposing a relay publicly:

* Replace the default PSK.
* Generate a strong random secret.
* Never commit secrets to Git.
* Restrict relay access when possible.
* Keep Python and dependencies updated.
* Use trusted TLS certificates for production deployments.
* Monitor relay bandwidth and system resources.

Generate a strong secret:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

---

# ⚠️ Responsible Usage

PsiTunnel is intended for:

* Networking research
* Privacy engineering
* Educational experimentation
* Testing networks you own
* Authorized security research
* Secure remote access environments

Users are responsible for complying with applicable laws, organizational policies, service agreements, and authorization requirements.

---

# 🤝 Contributing

Contributions are welcome through bug reports, documentation improvements, tests, compatibility improvements, and pull requests.

---

# ⭐ Support the Project

If PsiTunnel helped you, taught you something, or became useful in one of your projects:

### ⭐ Please star the repository.

Stars help more developers discover the project and support continued development.

---

# ❤️ Credit & Attribution

If you use **PsiTunnel**, its source code, architecture, protocol design, or significant portions of its implementation in another public project, please provide appropriate credit to the original project.

Recommended attribution:

```text
Based on / inspired by PsiTunnel
Original project: https://github.com/sweenyxq-gif/psitunnel
```

For GitHub projects:

```markdown
### Credits

This project uses or is based on components from
[PsiTunnel](https://github.com/sweenyxq-gif/psitunnel).

If you find the original project useful, please consider giving it a ⭐.
```

> Please do not remove existing copyright, license, or attribution notices when redistributing substantial portions of the project.

---

# 📚 Documentation

| Document                                                                                         | Description                                                   |
| ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------- |
| `README.md`                                                                                      | Project overview, architecture, features, and quick start     |
| [USAGE.md](https://github.com/sweenyxq-gif/psitunnel/blob/main/USAGE.md "PsiTunnel Usage Guide") | Complete setup, configuration, deployment, and usage guidance |

---

<div align="center">

## 🚇 PsiTunnel

**Encrypted. Lightweight. Multi-Transport. Python-Powered.**

📚 **[Read the Usage Guide](https://github.com/sweenyxq-gif/psitunnel/blob/main/USAGE.md "PsiTunnel Usage Guide")**

⭐ **Star the repository if PsiTunnel is useful to you.**

❤️ **If you reuse the project, please provide credit.**

</div>
