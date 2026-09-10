"""
Command line interface to launch the PsiTunnel client with auto-fallback and local proxies.
"""

import argparse
import asyncio
import os
import sys

from psitunnel.client.fallback_mgr import FallbackManager
from psitunnel.client.local_http import LocalHttpProxyServer
from psitunnel.client.local_socks5 import LocalSocks5Server
from psitunnel.client.config import parse_client_args


def create_parser():
    parser = argparse.ArgumentParser(description="PsiTunnel Censorship-Resistant Client")
    parser.add_argument("--max-channels", type=int, default=128, help="Maximum simultaneous streams")
    parser.add_argument("--bandwidth", type=int, default=0, help="Download bytes/sec per stream; 0 is unlimited")
    parser.add_argument("--server", default="127.0.0.1", help="Remote relay server hostname or IP")
    parser.add_argument("--psk", default=os.getenv("PSK"), help="Pre-shared key (or set PSK)")
    parser.add_argument(
        "--transports",
        default="ws,tls,obfs",
        help="Comma-separated transport fallback priority (default: ws,tls,obfs)",
    )
    parser.add_argument("--obfs-port", type=int, default=9001, help="Relay OBFS port (default: 9001)")
    parser.add_argument("--tls-port", type=int, default=9002, help="Relay TLS port (default: 9002)")
    parser.add_argument("--ws-port", type=int, default=9003, help="Relay WS port (default: 9003)")
    parser.add_argument("--sni", default=None, help="Custom SNI header for TLS transport")

    parser.add_argument("--local-host", default="127.0.0.1", help="Local proxy bind address (default: 127.0.0.1)")
    parser.add_argument("--socks-port", type=int, default=1080, help="Local SOCKS5 port (default: 1080)")
    parser.add_argument("--http-port", type=int, default=8080, help="Local HTTP proxy port (default: 8080)")
    parser.add_argument(
        "--upstream-proxy",
        default=None,
        help="Optional corporate/company forward proxy to traverse (e.g. http://proxy.company.com:8080)",
    )

    return parser


def main():
    args = parse_client_args(create_parser())

    fallback_mgr = FallbackManager(
        psk=args.psk,
        candidate_endpoints=args.endpoints,
        upstream_proxy=args.upstream_proxy,
        max_channels=args.max_channels, bandwidth=args.bandwidth,
    )
    socks_server = LocalSocks5Server(fallback_mgr, host=args.local_host, port=args.socks_port)
    http_server = LocalHttpProxyServer(fallback_mgr, host=args.local_host, port=args.http_port)

    async def stats_monitor():
        while True:
            await asyncio.sleep(5.0)
            active_t = fallback_mgr.active_transport.name.upper() if fallback_mgr.active_transport else "NONE"
            channels_count = len(fallback_mgr.channels)
            kb_sent = fallback_mgr.bytes_sent / 1024.0
            kb_recv = fallback_mgr.bytes_received / 1024.0
            print(
                f"\r[STATUS] Active Transport: {active_t} | Active Streams: {channels_count} | "
                f"Tx: {kb_sent:.1f} KB | Rx: {kb_recv:.1f} KB",
                end="",
                flush=True,
            )

    async def run():
        loop = asyncio.get_running_loop()

        def proactor_exception_handler(l, context):
            exc = context.get("exception")
            # Suppress harmless Windows socket reset during close on tracker/short-lived connections
            if isinstance(exc, ConnectionResetError) or (isinstance(exc, OSError) and getattr(exc, "winerror", None) == 10054):
                return
            l.default_exception_handler(context)

        loop.set_exception_handler(proactor_exception_handler)

        connected = await fallback_mgr.start()
        if not connected:
            print("[ERROR] Failed to establish initial tunnel connection. Check server availability.", file=sys.stderr)
            return

        await socks_server.start()
        await http_server.start()

        print("\n" + "=" * 60)
        print(" PsiTunnel is active and protecting your traffic!")
        print(f" SOCKS5 Proxy : socks5://{args.local_host}:{args.socks_port}")
        print(f" HTTP Proxy   : http://{args.local_host}:{args.http_port}")
        print("=" * 60 + "\n")

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
        print("\nClient terminated.")


if __name__ == "__main__":
    main()
