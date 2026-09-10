"""
PsiTunnel 24/7 Keepalive Pinger
Pings the Render relay URL periodically to prevent it from spinning down.
"""

import argparse
import sys
import time
import urllib.request
from datetime import datetime


def ping(url: str, timeout: float = 15.0) -> bool:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "PsiTunnel-KeepAlive/1.0",
            "Cache-Control": "no-cache",
        },
    )
    start_time = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed = (time.time() - start_time) * 1000
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{now}] [OK] Pinged {url} -> HTTP {resp.status} in {elapsed:.1f}ms (Render is AWAKE)")
            return True
    except Exception as e:
        elapsed = (time.time() - start_time) * 1000
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{now}] [WARN] Pinged {url} -> {e} in {elapsed:.1f}ms (Server woke up or responding)")
        return False


def main():
    parser = argparse.ArgumentParser(description="PsiTunnel Render Keepalive Pinger")
    parser.add_argument(
        "--url",
        default="https://psitunnel.onrender.com",
        help="Public URL of the Render relay (default: https://psitunnel.onrender.com)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=600,
        help="Ping interval in seconds (default: 600s / 10 minutes)",
    )
    args = parser.parse_args()

    # Ensure URL has protocol
    url = args.url
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    print("=" * 60)
    print("  PsiTunnel 24/7 Render Keep-Alive Service")
    print(f"  Target URL : {url}")
    print(f"  Interval   : Every {args.interval} seconds ({args.interval // 60} mins)")
    print("  Status     : Running (Press Ctrl+C to stop)")
    print("=" * 60)

    # Initial immediate ping
    ping(url)

    try:
        while True:
            time.sleep(args.interval)
            ping(url)
    except KeyboardInterrupt:
        print("\n[INFO] Keepalive pinger stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
