# PsiTunnel: Step-by-Step Usage & Deployment Guide

This guide covers everything you need to run **PsiTunnel**, including **100% free cloud hosting** (like GitHub Codespaces and Oracle Cloud), low-cost VPS hosting, client connection, and browser configuration for multiple PCs.

---

## Table of Contents
1. [How PsiTunnel Works](#how-psitunnel-works)
2. [Server Hosting Tiers (Free & Paid)](#server-hosting-tiers)
   - [Tier 1: GitHub Codespaces (100% Free - 60 hrs/mo)](#tier-1-github-codespaces-100-free)
   - [Tier 2: Oracle Cloud Always Free (100% Free Forever - 24/7)](#tier-2-oracle-cloud-always-free-247-permanent)
   - [Tier 3: Low-Cost Dedicated VPS ($3 - $5/month)](#tier-3-low-cost-dedicated-vps-3---5mo)
3. [Connecting Your PC (Client Setup)](#connecting-your-pc-client-setup)
4. [Routing Traffic (Browser & Apps)](#routing-traffic-browser--apps)
   - [Method A: Dedicated Chrome Shortcut (Recommended)](#method-a-dedicated-chrome-shortcut)
   - [Method B: Windows System-Wide Proxy](#method-b-windows-system-wide-proxy)
   - [Method C: Mozilla Firefox](#method-c-mozilla-firefox)
5. [Using on Another PC or Laptop](#using-on-another-pc-or-laptop)
6. [Troubleshooting & FAQs](#troubleshooting--faqs)

---

## How PsiTunnel Works

```
Your PC (Chrome / Apps)
       │
       ▼  (SOCKS5 on 127.0.0.1:1080 or HTTP on 127.0.0.1:8080)
PsiTunnel Local Client
       │
       ▼  (Encrypted WSS / TLS tunnel disguised as regular web browsing)
Cloud Relay Server (GitHub Codespace / VPS / Oracle Cloud)
       │
       ▼  (Uncensored, unthrottled outbound internet)
Any Blocked Website (Netflix, YouTube, Reddit, News, etc.)
```

---

## Server Hosting Tiers

### Tier 1: GitHub Codespaces (100% Free)
> **Best for:** Fast, zero-setup free hosting with no credit card required.  
> **Free allowance:** 60 core-hours every month (resets monthly).

#### Step-by-Step Setup:
1. **Push your code to GitHub**:
   Make sure your PsiTunnel repository is pushed to your personal GitHub account.
2. **Launch a Codespace**:
   - Go to your repository on GitHub.
   - Click the green **Code** button → select the **Codespaces** tab → click **Create codespace on main**.
3. **Run the Relay Server inside the Codespace Terminal**:
   ```bash
   pip install -r requirements.txt
   python cli.py server --ws-port 9003 --psk "my-super-secret-key-123"
   ```
4. **Make the Port Public (Crucial Step)**:
   - In Codespaces, look at the bottom panel and switch to the **Ports** tab.
   - Find port `9003`.
   - Right-click on port `9003` → select **Port Visibility** → change from **Private** to **Public**.
   - Copy the **Forwarded Address** URL (e.g. `automatic-invention-xxxx-9003.app.github.dev`).
5. **Done!** Your server is live on port `443` (WSS) using that domain name.

> [!NOTE]
> Codespaces will automatically suspend when idle after ~30 minutes. Whenever you want to browse again, just reopen your Codespace page in your browser.

---

### Tier 2: Oracle Cloud Always Free (24/7 Permanent)
> **Best for:** A permanent, 24/7 proxy server that **never sleeps** and is completely free forever.  
> **Free allowance:** 1-4 VMs (up to 4 ARM Ampere cores + 24GB RAM or 2 AMD VMs) + permanent static IPv4 address.

#### Step-by-Step Setup:
1. **Sign Up**: Register at [cloud.oracle.com](https://cloud.oracle.com) (requires a credit card for identity validation; you will not be billed if you stay within Always Free).
2. **Create Compute Instance**:
   - Go to **Compute** → **Instances** → **Create Instance**.
   - Image: **Ubuntu 22.04 / 24.04**.
   - Shape: Always Free Eligible (`VM.Standard.A1.Flex` or `VM.Standard.E2.1.Micro`).
   - Save your private SSH key.
3. **Open Firewall Ports**:
   - In the Virtual Cloud Network (VCN) subnet Security List, add an Ingress Rule:
     - **Source CIDR**: `0.0.0.0/0`
     - **IP Protocol**: TCP
     - **Destination Port Range**: `9003, 443`
4. **Deploy PsiTunnel on the VM**:
   SSH into your Oracle instance:
   ```bash
   sudo apt update && sudo apt install -y python3-pip git
   git clone <YOUR_REPO_URL> psitunnel
   cd psitunnel
   pip install -r requirements.txt
   ```
5. **Run in Background (systemd service)**:
   Create a persistent service file:
   ```bash
   sudo nano /etc/systemd/system/psitunnel.service
   ```
   Paste the following:
   ```ini
   [Unit]
   Description=PsiTunnel Relay Server
   After=network.target

   [Service]
   Type=simple
   User=ubuntu
   WorkingDirectory=/home/ubuntu/psitunnel
   ExecStart=/usr/bin/python3 /home/ubuntu/psitunnel/cli.py server --ws-port 9003 --psk "my-super-secret-key-123"
   Restart=always
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```
   Enable and start it:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable --now psitunnel
   ```
6. **Done!** Connect your client using your Oracle VM''s public IP address on port `9003`.

---

### Tier 3: Low-Cost Dedicated VPS ($3 - $5/mo)
> **Best for:** Maximum speeds, high bandwidth streaming (4K Netflix/YouTube), and servers in specific countries (US, Germany, Singapore).

Top Recommended Providers:
- **Hetzner Cloud**: ~€3.40/month (unbeatable speed and reliability in Europe & US).
- **OVHcloud**: ~$3.50/month.
- **AWS Lightsail**: $3.50/month.
- **DigitalOcean / Linode / Vultr**: $4 - $6/month.

#### 1-Line Docker Deployment on Any VPS:
```bash
docker run -d --name psitunnel --restart always -p 9003:9003 \
  $(docker build -q .) \
  server --ws-port 9003 --psk "my-super-secret-key-123"
```

---

## Connecting Your PC (Client Setup)

### 1. Install Dependencies
Make sure you have Python 3.10+ installed:
```powershell
pip install -r requirements.txt
```

### 2. Launch the Client
Replace `<SERVER_DOMAIN_OR_IP>`, `<PORT>`, and `<PSK>` with your server details:

```powershell
# For GitHub Codespaces (uses port 443 WSS):
python cli.py client --server automatic-invention-xxxx-9003.app.github.dev --ws-port 443 --transports ws --psk "my-super-secret-key-123"

# For Oracle Cloud / VPS (direct IP and port):
python cli.py client --server YOUR_SERVER_IP --ws-port 9003 --transports ws --psk "my-super-secret-key-123"
```

When successfully connected, you will see:
```
============================================================
 PsiTunnel is active and protecting your traffic!
 SOCKS5 Proxy : socks5://127.0.0.1:1080
 HTTP Proxy   : http://127.0.0.1:8080
============================================================
```

---

## Routing Traffic (Browser & Apps)

### Method A: Dedicated Chrome Shortcut (Recommended)
This opens a clean, isolated Chrome session routed completely through PsiTunnel without touching your regular browser or system settings.

#### Create a Desktop Shortcut (Run once in PowerShell):
```powershell
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$([Environment]::GetFolderPath('Desktop'))\PsiTunnel Chrome.lnk")
$Shortcut.TargetPath = "C:\Program Files\Google\Chrome\Application\chrome.exe"
$Shortcut.Arguments = '--proxy-server="socks5://127.0.0.1:1080" --user-data-dir="%TEMP%\chrome_proxy"'
$Shortcut.Save()
```
Now, simply double-click the **"PsiTunnel Chrome"** icon on your desktop whenever PsiTunnel is running. You can open any site directly in this browser!

---

### Method B: Windows System-Wide Proxy
Routes all apps, Edge, and standard Chrome through the tunnel.

#### Enable:
```powershell
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyServer -Value "http=127.0.0.1:8080;https=127.0.0.1:8080"
```
*(Or via Windows: **Settings** → **Network & Internet** → **Proxy** → Set Manual Proxy to `127.0.0.1:8080`)*

#### Disable (When finished):
```powershell
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -Name ProxyEnable -Value 0
```

---

### Method C: Mozilla Firefox
Firefox supports custom proxy settings that do not alter the rest of Windows:
1. Open Firefox → **Settings**.
2. Scroll to the bottom and click **Settings...** under **Network Settings**.
3. Select **Manual proxy configuration**:
   - **SOCKS Host**: `127.0.0.1` | **Port**: `1080`
   - Select **SOCKS v5**.
   - Check **"Proxy DNS when using SOCKS v5"** *(prevents DNS leaks)*.
4. Click **OK**.

---

## Using on Another PC or Laptop

You do **not** need to deploy another server! Multiple computers can connect to the same server simultaneously.

### On the 2nd PC:
1. Copy the project folder to the second PC (or `git clone`).
2. Run `pip install -r requirements.txt`.
3. Run the exact same client command:
   ```powershell
   python cli.py client --server <YOUR_SERVER_ADDRESS> --ws-port <PORT> --transports ws --psk "my-super-secret-key-123"
   ```
4. Open the proxy browser on that PC.

#### Optional: Portable Executable (No Python required on 2nd PC):
On your primary machine, build an `.exe`:
```powershell
pip install pyinstaller
pyinstaller --onefile --name psitunnel cli.py
```
Copy `dist\psitunnel.exe` to any Windows machine and run:
```powershell
.\psitunnel.exe client --server <YOUR_SERVER_ADDRESS> --ws-port <PORT> --transports ws --psk "my-super-secret-key-123"
```

---

## Troubleshooting & FAQs

### 1. Connection fails with "Connection refused" or HTTP 502 / 503
- **GitHub Codespaces**: Ensure port `9003` in the **Ports** tab is set to **Public** (not Private). If it is Private, external connections are rejected by GitHub.
- **Codespace Sleeping**: Visit your Codespaces dashboard to verify the container is running.
- **Firewall**: On VPS/Oracle, verify port `9003` or `443` is permitted in the cloud security list and `ufw` firewall (`sudo ufw allow 9003/tcp`).

### 2. Can I browse any website or only Netflix?
You can browse **every website**! The proxy handles all web traffic, streaming, torrents, and file downloads. Any URL typed into the address bar routes through the encrypted tunnel.

### 3. How to check if my IP is really hidden?
While connected through the proxy browser, visit:
- [https://ipleak.net](https://ipleak.net) or [https://whatismyipaddress.com](https://whatismyipaddress.com)
- You should see your cloud server''s IP address and location (e.g. Microsoft/Azure for Codespaces) rather than your local home ISP.
