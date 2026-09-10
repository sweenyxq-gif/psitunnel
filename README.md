# PsiTunnel (Python Psiphon-Inspired Circumvention Tunnel)

## Stream flow control and resource limits (protocol V3)

Update both client and relay together: V3 uses byte-credit messages and rejects
older handshake versions. Each direction of each stream permits 256 KiB of
unacknowledged data, with chunks up to 32 KiB. A separate delivery task drains
each destination and returns credit after delivery, keeping slow destinations
out of the shared tunnel reader. There is also a 4096 queued-frame limit per
stream; exceeding a receive limit closes that stream. The underlying TCP tunnel
still shares link congestion and transport-level head-of-line blocking.

Client `--max-channels` defaults to 128. Relay `--max-channels` defaults to 128
per authenticated session and counts pending target connections too. Relay
`--max-sessions` defaults to 64 authenticated sessions; it does not limit inbound
TLS/transport handshakes. Streams beyond these limits are rejected.

`--bandwidth N` caps delivered payload bytes per second **per stream**: on the
client it limits downloads; on the relay it limits uploads. Zero (the default)
disables pacing. This is receive-side pacing with a bounded in-flight window,
not a total network-interface cap. Client profiles accept `max_channels` and
`bandwidth` as well. The server takes its key through `--psk` or `PSK`;
for example, after setting PSK:

```powershell
python cli.py server --max-sessions 16 --max-channels 32 --bandwidth 1048576
python cli.py client --config examples/client.json --psk-file key.txt --max-channels 32 --bandwidth 1048576
```

## Client profiles and diagnostics

Use `python cli.py client --config examples/client.json --profile local --psk-file /path/to/key`
to start with a JSON profile. Use the same arguments with `doctor` instead of
`client` to check every configured relay's connection, authentication, and PING/PONG
response without opening local proxy listeners. Add `--json` to doctor for structured
results. Exit code is 0 when every relay passes, 1 when any fails, and 2 for invalid
configuration. A failure is reported by exception category without credential text.

The sample `examples/client.json` contains local and remote profiles. Edit the remote
hosts before using them. `defaults` are merged with the selected profile; scalar CLI
options override these values. A `relays` list defines the complete ordered endpoint
list and takes precedence over the single-server `--server`/`--transports` options.
Each endpoint has `host`, `transport` (`ws`, `tls`, or `obfs`), and optional `port`,
`path`, `sni`, and `use_ssl`. Existing client-side WSS is selected using `use_ssl`;
this does not create a WSS server listener.

Keys are resolved from `--psk`, then `PSK`, then `--psk-file` (or the profile's
`psk_file`). A configured key-file path is relative to the JSON file; a command-line
key-file path is relative to the current directory. Docker-mounted secret files
can be supplied with `--psk-file`. Profiles never contain an inline shared key.

Endpoints are tried in configured order initially. During subsequent selection,
failures and measured connection time determine preference among endpoints outside
cooldown. Failures incur a 2–60 second exponential cooldown. Health is kept in memory
for this client process. Heartbeats run every 20 seconds with a 10-second reply
deadline. A dropped tunnel reconnects automatically; applications must reopen TCP
streams interrupted by that drop. This is not stream resumption.

PsiTunnel is a censorship-resistant tunneling and proxy suite written in pure Python. Inspired by the core architecture of **Psiphon**, PsiTunnel is designed to circumvent network firewalls, internet censorship, and deep packet inspection (DPI) through **multi-protocol fallback**, **traffic obfuscation**, and **local application ingress** (SOCKS5 & HTTP CONNECT).

---

## Key Features

- **Multi-Transport Fallback Engine**:
  When censors throttle, fingerprint, or sever connections on a specific transport (e.g., standard TLS or raw TCP), PsiTunnel seamlessly fails over to alternate transports in priority sequence until a working path is negotiated.
- **Three Obfuscated Transports**:
  1. **WebSocket (`ws`)**: Disguises proxy traffic as ordinary HTTP/1.1 `GET /ws` WebSocket upgrades (RFC 6455). Easily traverses corporate firewalls, reverse proxies, and CDN edge nodes.
  2. **TLS Masking (`tls`)**: Tunnel traffic encapsulated inside standard TLS 1.3 / 1.2 with customizable SNI and ALPN negotiation.
  3. **Obfuscated Raw Stream (`obfs`)**: Direct TCP with Pre-Shared Key (PSK) authenticated encryption and variable random packet padding (0–32 bytes per frame) to foil packet-size statistical fingerprinting.
- **End-to-End Cryptography**:
  - **AEAD Cipher**: ChaCha20-Poly1305 authenticated encryption on every frame.
  - **Key Derivation**: HKDF-SHA256 with dynamic 32-byte salts per session, generating distinct directional session keys (`client_to_server` and `server_to_client`).
  - **Strict Anti-Probing**: Servers silently drop or reject unauthenticated probes without revealing service banners.
- **Local Ingress Proxies**:
  - **SOCKS5 Proxy** (RFC 1928, default port `1080`): Supports IPv4, IPv6, and **Domain Name addressing** (remote target DNS resolution to prevent DNS leaks and ISP poisoning).
  - **HTTP CONNECT Proxy** (default port `8080`): Directly compatible with web browsers, operating system proxy settings, and tools like `curl`.
- **Multiplexed Architecture**:
  - A single encrypted tunnel carries hundreds of simultaneous concurrent browsing sessions and streams without connection setup overhead.
- **Zero Heavy Dependencies**:
  - Built entirely on Python 3 asynchronous I/O (`asyncio`) and the standard `cryptography` library. No kernel-level TUN/TAP driver installation or root privileges required.

---

## End-to-End Circumvention Flow

```
Your PC (Browser / Desktop Apps)
  ↓
Psiphon Client (Local SOCKS5 on :1080 / HTTP on :8080)
  ↓
Encrypted / Obfuscated Tunnel (WebSocket / TLS / ChaCha20 + Dynamic Padding)
  ↓
Company Firewall (DPI inspection bypassed! Disguised as standard HTTPS web traffic)
  ↓
Psiphon Server (Remote Relay on Port 443 / Cloud VPS)
  ↓
Netflix / WhatsApp / Uncensored Internet
```

---

## Architecture Diagram

```
+---------------------------------------------------------------------------------+
|                                    YOUR PC                                      |
|                                                                                 |
|  [Netflix / WhatsApp / Apps]                                                    |
|           |                                                                     |
|           v                                                                     |
|  [Psiphon Client Ingress]                                                       |
|    - SOCKS5 Proxy  (127.0.0.1:1080)                                             |
|    - HTTP Proxy    (127.0.0.1:8080)                                             |
|           |                                                                     |
|           v                                                                     |
|  [Multiplexer & Fallback Engine]                                                |
|    - Dynamic AEAD Framing (ChaCha20-Poly1305)                                   |
|    - Anti-DPI Random Padding Injection (0–32 bytes)                             |
+-----------+---------------------------------------------------------------------+
            |
            | === ENCRYPTED / OBFUSCATED TUNNEL (WS / TLS / OBFS) ===
            v
+---------------------------------------------------------------------------------+
|                       COMPANY FIREWALL / ENTERPRISE DPI                         |
|                                                                                 |
|  - Looks like benign HTTPS web browsing (TCP 443 / WebSocket Upgrade)          |
|  - Packet size statistical analysis blinded by random padding                   |
|  - Optional corporate forward proxy support (--upstream-proxy)                  |
|  - FIREWALL TRAVERSED / RESTRICTIONS BYPASSED                                   |
+-----------+---------------------------------------------------------------------+
            |
            | === SECURE WAN EGRESS ===
            v
+---------------------------------------------------------------------------------+
|                                PSIPHON SERVER                                   |
|                                                                                 |
|  [Multi-Transport Ingress Listeners: WS / TLS / OBFS]                           |
|           |                                                                     |
|           v                                                                     |
|  [Demultiplexer & Remote DNS Resolver]                                          |
|           |                                                                     |
|           v                                                                     |
|  [Outbound Internet Target Connection]                                          |
+-----------+---------------------------------------------------------------------+
            |
            v
+---------------------------------------------------------------------------------+
|                             RESTRICTED SERVICES                                 |
|                                                                                 |
|                     Netflix  /  WhatsApp  /  YouTube  /  Web                    |
+---------------------------------------------------------------------------------+
```

---

## Quick Start

### 1. Requirements
- Python 3.10+
- `cryptography` package:
  ```bash
  pip install cryptography
  ```

### 2. Start the Relay Server
Run the relay server on your remote server (or locally for testing):

```bash
python cli.py server --psk "your-super-secret-key" --obfs-port 9001 --tls-port 9002 --ws-port 9003
```

### 3. Start the Client
Start the client on your local computer, pointing to the relay server:

```bash
python cli.py client --server 127.0.0.1 --psk "your-super-secret-key" --transports "ws,tls,obfs"
```

The client will automatically:
1. Probe and connect to the best available transport in your `--transports` list.
2. Spin up local proxies on:
   - SOCKS5: `127.0.0.1:1080`
   - HTTP: `127.0.0.1:8080`
3. Provide live throughput metrics (`Tx` / `Rx` / active streams).

---

## Usage Examples

### Using with `curl`

**Via SOCKS5 (with remote DNS resolution):**
```bash
curl --socks5-hostname 127.0.0.1:1080 https://httpbin.org/ip
```

**Via HTTP CONNECT Proxy:**
```bash
curl -x http://127.0.0.1:8080 https://httpbin.org/ip
```

### Using with Web Browsers (Chrome / Firefox / Edge)
1. Configure your browser's proxy settings or use an extension like **SwitchyOmega**:
   - **SOCKS Host**: `127.0.0.1`, Port: `1080`, SOCKS v5, Enable *Proxy DNS when using SOCKS v5*.
   - Or **HTTP Proxy**: `127.0.0.1`, Port: `8080`.
2. All browser traffic is now routed through the PsiTunnel obfuscated tunnel to the relay server.

---

## Command Line Options

### Server Options (`python cli.py server --help`)
| Option | Default | Description |
|---|---|---|
| `--host` | `0.0.0.0` | Listen host address |
| `--psk` | Required (`PSK` environment variable is also supported) | Pre-shared key for authentication and AEAD derivation |
| `--obfs-port` | `9001` | Port for obfuscated raw stream |
| `--tls-port` | `9002` | Port for TLS tunnel |
| `--ws-port` | `9003` | Port for WebSocket tunnel |
| `--cert` | `None` | Optional path to custom TLS certificate (self-signed generated if omitted) |
| `--key` | `None` | Optional path to custom TLS private key |

### Client Options (`python cli.py client --help`)
| Option | Default | Description |
|---|---|---|
| `--server` | `127.0.0.1` | Remote relay server hostname or IP |
| `--psk` | Required (`PSK` environment variable is also supported) | Pre-shared key matching the server |
| `--transports` | `ws,tls,obfs` | Comma-separated transport fallback priority |
| `--obfs-port` | `9001` | Server OBFS port |
| `--tls-port` | `9002` | Server TLS port |
| `--ws-port` | `9003` | Server WS port |
| `--sni` | `None` | Custom SNI hostname header for TLS disguise |
| `--local-host` | `127.0.0.1` | Local proxy bind interface |
| `--socks-port` | `1080` | Local SOCKS5 proxy port |
| `--http-port` | `8080` | Local HTTP CONNECT proxy port |

---

## Running the Automated Test Suite

Run unit and end-to-end integration tests:
```bash
python -m unittest discover tests
```
