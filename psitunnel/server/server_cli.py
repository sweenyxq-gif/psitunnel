"""
Command line interface to launch the PsiTunnel relay server.
"""

import argparse
import asyncio
import os
import signal
import sys

from psitunnel.server.relay import PsiTunnelServer


def main():
    parser = argparse.ArgumentParser(description="PsiTunnel Censorship-Resistant Relay Server")
    parser.add_argument("--max-channels", type=int, default=128)
    parser.add_argument("--max-sessions", type=int, default=64)
    parser.add_argument("--bandwidth", type=int, default=0, help="Upload bytes/sec per stream; 0 is unlimited")
    parser.add_argument("--host", default="0.0.0.0", help="Host address to bind (default: 0.0.0.0)")
    parser.add_argument("--psk", default=os.getenv("PSK"), help="Pre-shared key (or set PSK)")
    parser.add_argument("--obfs-port", type=int, default=os.getenv("OBFS_PORT", "9001"), help="Port for obfuscated raw stream (default: 9001)")
    parser.add_argument("--tls-port", type=int, default=os.getenv("TLS_PORT", "9002"), help="Port for TLS tunnel (default: 9002)")
    parser.add_argument("--ws-port", type=int, default=os.getenv("WS_PORT", "9003"), help="Port for WebSocket tunnel (default: 9003)")
    parser.add_argument("--cert", default=None, help="Custom TLS certificate file")
    parser.add_argument("--key", default=None, help="Custom TLS private key file")

    args = parser.parse_args()
    if not args.psk or args.psk == "psitunnel-secret-key-change-me":
        parser.error("a non-default pre-shared key is required via --psk or PSK")

    if args.max_channels < 1 or args.max_sessions < 1 or args.bandwidth < 0:
        parser.error("Invalid resource limits")
    server = PsiTunnelServer(psk=args.psk, cert_path=args.cert, key_path=args.key,
                             max_channels=args.max_channels, max_sessions=args.max_sessions, bandwidth=args.bandwidth)

    async def run():
        await server.start(
            host=args.host,
            obfs_port=args.obfs_port,
            tls_port=args.tls_port,
            ws_port=args.ws_port,
        )
        print("\nPsiTunnel Relay is running. Press Ctrl+C to terminate.\n")
        stop_event = asyncio.Event()

        try:
            await stop_event.wait()
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            await server.stop()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\nRelay stopped.")


if __name__ == "__main__":
    main()
