# PsiTunnel

> A censorship-resistant tunneling and proxy suite written in pure Python.

PsiTunnel circumvents network firewalls, internet censorship, and deep packet inspection (DPI) through multi-protocol fallback, traffic obfuscation, and local application ingress via SOCKS5 and HTTP CONNECT proxies. Inspired by the core architecture of [Psiphon](https://psiphon.ca).

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [CLI Reference](#cli-reference)
- [Running Tests](#running-tests)

---

## Features

### Multi-Transport Fallback Engine
When a censor throttles, fingerprints, or blocks a specific transport, PsiTunnel automatically fails over to the next available transport in your configured priority sequence until a working path is established.

### Three Obfuscated Transports

| Transport | Key | Description |
|---|---|---|
| WebSocket | `ws` | Disguises traffic as standard HTTP/1.1 WebSocket upgrades (RFC 6455). Traverses corporate firewalls, reverse proxies, and CDN edge nodes. |
| TLS Masking | `tls` | Encapsulates tunnel traffic inside TLS 1.3/1.2 with customizable SNI and ALPN negotiation. |
| Obfuscated Raw Stream | `obfs` | Direct TCP with PSK-authenticated encryption and variable random packet padding (0–32 bytes/frame) to defeat packet-size statistical fingerprinting. |

### End-to-End Cryptography

- **AEAD cipher** — ChaCha20-Poly1305 authenticated encryption on every frame.
- **Key derivation** — HKDF-SHA256 with dynamic 32-byte salts per session, generating distinct directional keys (`client_to_server` / `server_to_client`).
- **Anti-probing** — Server silently drops unauthenticated probes without exposing service banners.

### Local Ingress Proxies

- **SOCKS5** (RFC 1928, default `:1080`) — Supports IPv4, IPv6, and domain-name addressing with remote DNS resolution to prevent DNS leaks and ISP poisoning.
- **HTTP CONNECT** (default `:8080`) — Compatible with browsers, OS proxy settings, and tools like `curl`.

### Multiplexed Architecture
A single encrypted tunnel carries hundreds of concurrent sessions without per-connection setup overhead.

### Zero Heavy Dependencies
Built entirely on Python 3 `asyncio` and the standard `cryptography` library. No kernel-level TUN/TAP drivers or root privileges required.

---

## How It Works

```
Your PC (Browser / Apps)
  │
  ▼
PsiTunnel Client
  SOCKS5 :1080  ·  HTTP :8080
  │
  ▼  Encrypted / Obfuscated Tunnel
     (WebSocket · TLS · ChaCha20 + Dynamic Padding)
  │
  ▼
Company Firewall / DPI
  [Looks like standard HTTPS — bypassed]
  │
  ▼
PsiTunnel Relay Server
  Remote DNS resolution · Demultiplexer
  │
  ▼
Open Internet
  Netflix · WhatsApp · YouTube · Web
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                          YOUR PC                            │
│                                                             │
│  [Apps / Browser]                                           │
│         │                                                   │
│         ▼                                                   │
│  [PsiTunnel Client Ingress]                                 │
│    SOCKS5 Proxy   127.0.0.1:1080                            │
│    HTTP Proxy     127.0.0.1:8080                            │
│         │                                                   │
│         ▼                                                   │
│  [Multiplexer & Fallback Engine]                            │
│    Dynamic AEAD Framing (ChaCha20-Poly1305)                 │
│    Anti-DPI Random Padding (0–32 bytes/frame)               │
└─────────────────────┬───────────────────────────────────────┘
                      │
            ══ ENCRYPTED / OBFUSCATED TUNNEL ══
             WebSocket  ·  TLS  ·  OBFS (TCP 443)
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                 FIREWALL / ENTERPRISE DPI                    │
│                                                             │
│  Appears as benign HTTPS web traffic                        │
│  Packet-size analysis blinded by random padding             │
│  Optional upstream corporate proxy (--upstream-proxy)       │
│                                                             │
│               ✓ TRAVERSED / BYPASSED                        │
└─────────────────────┬───────────────────────────────────────┘
                      │
               ══ SECURE WAN EGRESS ══
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                   PSITUNNEL SERVER                          │
│                                                             │
│  Multi-Transport Ingress (WS · TLS · OBFS)                  │
│         │                                                   │
│         ▼                                                   │
│  Demultiplexer · Remote DNS Resolver                        │
│         │                                                   │
│         ▼                                                   │
│  Outbound Connection to Target                              │
└─────────────────────┬───────────────────────────────────────┘
                      │
                      ▼
         Netflix · WhatsApp · YouTube · Web
```

---

## Quick Start

### Requirements

- Python 3.10+
- `cryptography` package

```bash
pip install cryptography
```

### 1. Start the Relay Server

Run on a remote VPS or locally for testing:

```bash
python cli.py server \
  --psk "your-super-secret-key" \
  --obfs-port 9001 \
  --tls-port 9002 \
  --ws-port 9003
```

### 2. Start the Client

Point the client to your relay server:

```bash
python cli.py client \
  --server 127.0.0.1 \
  --psk "your-super-secret-key" \
  --transports "ws,tls,obfs"
```

The client will automatically:

1. Probe and connect via the best available transport in your `--transports` priority list.
2. Spin up local proxies:
   - **SOCKS5** → `127.0.0.1:1080`
   - **HTTP CONNECT** → `127.0.0.1:8080`
3. Display live throughput metrics (`Tx` / `Rx` / active streams).

---

## Usage Examples

### curl

**Via SOCKS5** (with remote DNS resolution):
```bash
curl --socks5-hostname 127.0.0.1:1080 https://httpbin.org/ip
```

**Via HTTP CONNECT proxy:**
```bash
curl -x http://127.0.0.1:8080 https://httpbin.org/ip
```

### Web Browsers (Chrome / Firefox / Edge)

Configure your browser's proxy settings manually or via an extension like [SwitchyOmega](https://github.com/FelisCatus/SwitchyOmega):

| Setting | Value |
|---|---|
| SOCKS Host | `127.0.0.1` |
| SOCKS Port | `1080` |
| SOCKS Version | v5 |
| Proxy DNS | Enabled |

Or use the HTTP proxy at `127.0.0.1:8080`.

---

## CLI Reference

### Server — `python cli.py server`

| Option | Default | Description |
|---|---|---|
| `--host` | `0.0.0.0` | Listen host address |
| `--psk` | `psitunnel-secret-key-change-me` | Pre-shared key for authentication and AEAD derivation |
| `--obfs-port` | `9001` | Port for obfuscated raw stream |
| `--tls-port` | `9002` | Port for TLS tunnel |
| `--ws-port` | `9003` | Port for WebSocket tunnel |
| `--cert` | _(none)_ | Path to custom TLS certificate (self-signed generated if omitted) |
| `--key` | _(none)_ | Path to custom TLS private key |

### Client — `python cli.py client`

| Option | Default | Description |
|---|---|---|
| `--server` | `127.0.0.1` | Remote relay server hostname or IP |
| `--psk` | `psitunnel-secret-key-change-me` | Pre-shared key matching the server |
| `--transports` | `ws,tls,obfs` | Comma-separated transport fallback priority |
| `--obfs-port` | `9001` | Server OBFS port |
| `--tls-port` | `9002` | Server TLS port |
| `--ws-port` | `9003` | Server WS port |
| `--sni` | _(none)_ | Custom SNI hostname for TLS disguise |
| `--local-host` | `127.0.0.1` | Local proxy bind interface |
| `--socks-port` | `1080` | Local SOCKS5 proxy port |
| `--http-port` | `8080` | Local HTTP CONNECT proxy port |

---

## Running Tests

Run the full unit and end-to-end integration test suite:

```bash
python -m unittest discover tests
```

---

## Security Notice

> **Use responsibly.** PsiTunnel is intended for legitimate use cases such as accessing the open internet in censored regions, bypassing restrictive corporate firewalls for authorized work, and privacy-focused networking research. Always ensure your use complies with applicable laws and terms of service in your jurisdiction.

---

## License

See [LICENSE](LICENSE) for details.
