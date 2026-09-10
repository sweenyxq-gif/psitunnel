"""
PsiTunnel Interactive Client App
Prompts user for hosted relay server URL, port, and secret key,
then establishes the encrypted tunnel and launches local proxies.
"""

import asyncio
import json
import os
import re
import shutil
import subprocess
import sys
from urllib.parse import urlparse

if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, APP_DIR)

from psitunnel.client.fallback_mgr import FallbackManager
from psitunnel.client.local_http import LocalHttpProxyServer
from psitunnel.client.local_socks5 import LocalSocks5Server

CONFIG_FILE = os.path.join(APP_DIR, "psitunnel_client.json")


def clean_host_input(raw: str):
    raw = raw.strip()
    if not raw:
        return "", None

    if not re.match(r"^[a-zA-Z]+://", raw):
        parsed = urlparse("//" + raw)
    else:
        parsed = urlparse(raw)

    host = parsed.hostname or raw
    port = parsed.port
    return host, port


def load_saved_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_config(host: str, port: int, psk: str):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump({"server": host, "port": port, "psk": psk}, f, indent=2)
    except Exception:
        pass


def kill_lingering_port(port: int = 1080):
    if sys.platform == "win32":
        try:
            cmd = f'powershell -Command "$p = Get-NetTCPConnection -LocalPort {port} -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess; if ($p) {{ Stop-Process -Id $p -Force }}"'
            subprocess.run(cmd, shell=True, capture_output=True, timeout=5)
        except Exception:
            pass


def launch_chrome_with_proxy(socks_port: int = 1080):
    chrome_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
    ]
    chrome_bin = None
    for p in chrome_paths:
        if os.path.exists(p):
            chrome_bin = p
            break

    if not chrome_bin:
        chrome_bin = shutil.which("chrome") or shutil.which("google-chrome")

    if chrome_bin:
        user_data = os.path.expandvars(r"%TEMP%\chrome_proxy")
        args = [
            chrome_bin,
            f"--proxy-server=socks5://127.0.0.1:{socks_port}",
            f"--user-data-dir={user_data}",
            "https://api.ipify.org",
        ]
        try:
            flags = 0
            if sys.platform == "win32":
                flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
            subprocess.Popen(
                args,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                creationflags=flags,
            )
            print("[INFO] Google Chrome launched with PsiTunnel proxy!")
            return True
        except Exception as e:
            print(f"[WARN] Failed to launch Chrome: {e}")
    else:
        print("[WARN] Google Chrome executable not found in default paths.")
    return False


def main():
    print("=" * 68)
    print("                 PsiTunnel High-Speed Proxy Client")
    print("         Encrypted Tunnel & Censorship Circumvention")
    print("=" * 68)

    saved = load_saved_config()
    default_host = saved.get("server", "psitunnel.onrender.com")
    default_port = saved.get("port", 443)
    default_psk = saved.get("psk", "my-super-secret-key-123")

    # 1. Prompt for Relay Host / URL
    print(f"\nEnter the hosted relay server URL or hostname:")
    raw_host = input(f"Relay Server [{default_host}]: ").strip()
    if raw_host:
        parsed_host, parsed_port = clean_host_input(raw_host)
        host = parsed_host
        if parsed_port:
            default_port = parsed_port
    else:
        host = default_host

    # 2. Prompt for Port
    print(f"\nEnter WebSocket port (443 for HTTPS/WSS like Render, Codespaces, Cloudflare):")
    raw_port = input(f"Port [{default_port}]: ").strip()
    try:
        port = int(raw_port) if raw_port else default_port
    except ValueError:
        port = default_port

    # 3. Prompt for Secret Key
    print(f"\nEnter Pre-Shared Secret Key (PSK):")
    raw_psk = input(f"Secret Key [{default_psk}]: ").strip()
    psk = raw_psk if raw_psk else default_psk

    # 4. Prompt for Chrome launch
    print(f"\nLaunch Google Chrome automatically with this proxy? [Y/n]:")
    raw_chrome = input("Launch Chrome [Y]: ").strip().lower()
    auto_chrome = raw_chrome not in ("n", "no")

    # Save preferences for next launch
    save_config(host, port, psk)

    print("\n" + "-" * 68)
    print(f" Connecting to : {host}:{port} [WSS]")
    print(f" Local SOCKS5  : socks5://127.0.0.1:1080")
    print(f" Local HTTP    : http://127.0.0.1:8080")
    print("-" * 68)

    # Free local port if locked
    kill_lingering_port(1080)
    kill_lingering_port(8080)

    candidate_endpoints = [
        {"transport": "ws", "host": host, "port": port}
    ]

    fallback_mgr = FallbackManager(
        psk=psk,
        candidate_endpoints=candidate_endpoints,
        max_channels=1024,
        bandwidth=0,
    )
    socks_server = LocalSocks5Server(fallback_mgr, host="127.0.0.1", port=1080)
    http_server = LocalHttpProxyServer(fallback_mgr, host="127.0.0.1", port=8080)

    async def stats_monitor():
        while True:
            try:
                await asyncio.sleep(5.0)
                active_t = fallback_mgr.active_transport.name.upper() if fallback_mgr.active_transport else "NONE"
                channels_count = len(fallback_mgr.channels)
                kb_sent = fallback_mgr.bytes_sent / 1024.0
                kb_recv = fallback_mgr.bytes_received / 1024.0
                sys.stdout.write(
                    f"\r[STATUS] Protocol: {active_t} | Streams: {channels_count} | "
                    f"Tx: {kb_sent:.1f} KB | Rx: {kb_recv:.1f} KB   "
                )
                sys.stdout.flush()
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    async def run():
        loop = asyncio.get_running_loop()

        def proactor_exception_handler(l, context):
            exc = context.get("exception")
            if isinstance(exc, ConnectionResetError) or (isinstance(exc, OSError) and getattr(exc, "winerror", None) == 10054):
                return
            l.default_exception_handler(context)

        loop.set_exception_handler(proactor_exception_handler)

        print("\n[INFO] Connecting to relay server...")
        connected = False
        for attempt in range(1, 4):
            if attempt > 1:
                print(f"[INFO] Server may be waking up. Retrying attempt {attempt}/3...")
                await asyncio.sleep(2.0)
            connected = await fallback_mgr.start()
            if connected:
                break

        if not connected:
            print("\n[ERROR] Failed to establish tunnel connection.")
            print("Please verify:")
            print(f"  1. The server URL is correct: {host}")
            print(f"  2. The server port is accessible: {port}")
            print("  3. The pre-shared secret key matches the server")
            input("\nPress Enter to exit...")
            return

        await socks_server.start()
        await http_server.start()

        print("\n" + "=" * 60)
        print(" [SUCCESS] PsiTunnel is active and protecting your traffic!")
        print(" SOCKS5 Proxy : socks5://127.0.0.1:1080")
        print(" HTTP Proxy   : http://127.0.0.1:8080")
        print("=" * 60 + "\n")

        if auto_chrome:
            launch_chrome_with_proxy(1080)

        print("[ACTIVE] Proxy is running. Press Ctrl+C at any time to disconnect.\n")

        monitor_task = asyncio.create_task(stats_monitor())
        stop_event = asyncio.Event()

        try:
            await stop_event.wait()
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass
            await socks_server.stop()
            await http_server.stop()
            await fallback_mgr.stop()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\n\n[INFO] Client disconnected by user.")
    except Exception as e:
        print(f"\n\n[ERROR] An unexpected error occurred: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("[DONE] PsiTunnel stopped.")
        try:
            input("\nPress Enter to exit...")
        except Exception:
            pass


if __name__ == "__main__":
    main()
