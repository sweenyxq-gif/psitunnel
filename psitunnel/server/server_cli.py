"""
Command line interface to launch the PsiTunnel relay server.
"""

import argparse
import asyncio
import signal
import sys

from psitunnel.server.relay import PsiTunnelServer


def main():
    parser = argparse.ArgumentParser(description="PsiTunnel Censorship-Resistant Relay Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host address to bind (default: 0.0.0.0)")
    parser.add_argument("--psk", default="psitunnel-secret-key-change-me", help="Pre-shared key for AEAD authentication")
    parser.add_argument("--obfs-port", type=int, default=9001, help="Port for obfuscated raw stream (default: 9001)")
    parser.add_argument("--tls-port", type=int, default=9002, help="Port for TLS tunnel (default: 9002)")
    parser.add_argument("--ws-port", type=int, default=9003, help="Port for WebSocket tunnel (default: 9003)")
    parser.add_argument("--cert", default=None, help="Custom TLS certificate file")
    parser.add_argument("--key", default=None, help="Custom TLS private key file")

    args = parser.parse_args()

    server = PsiTunnelServer(psk=args.psk, cert_path=args.cert, key_path=args.key)

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

