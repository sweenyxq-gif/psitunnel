"""Authenticated endpoint diagnostics; never opens local proxy listeners."""
import asyncio
import json
import time

from psitunnel.client.client_cli import create_parser
from psitunnel.client.config import parse_client_args
from psitunnel.client.fallback_mgr import FallbackManager
from psitunnel.common.protocol import Command, TunnelMessage


async def diagnose(args):
    results = []
    manager = FallbackManager(args.psk, args.endpoints, args.upstream_proxy)
    for endpoint in args.endpoints:
        started = time.monotonic()
        conn = None
        result = {"host": endpoint["host"], "port": endpoint["port"],
                  "transport": endpoint["transport"]}
        try:
            conn = await manager.connect_endpoint(endpoint)
            await asyncio.wait_for(conn.send_message(TunnelMessage(Command.CMD_PING, 0, b"doctor")), 5)
            reply = await asyncio.wait_for(conn.recv_message(), 5)
            if reply is None or reply.cmd != Command.CMD_PONG or reply.payload != b"doctor":
                raise ConnectionError("Unexpected heartbeat response")
            result.update(ok=True, elapsed_ms=round((time.monotonic() - started) * 1000, 1))
        except Exception as exc:
            # Do not print exception text: upstream URLs may contain credentials.
            result.update(ok=False, error=type(exc).__name__)
        finally:
            if conn:
                await conn.close()
        results.append(result)
    return results


def main():
    parser = create_parser()
    parser.description = "Check relay connection, authentication and heartbeat (no local proxies)"
    parser.add_argument("--json", action="store_true", help="Machine-readable results")
    args = parse_client_args(parser)
    results = asyncio.run(diagnose(args))
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        for result in results:
            status = f"OK {result['elapsed_ms']} ms" if result["ok"] else f"FAILED {result['error']}"
            print(f"{result['transport']} {result['host']}:{result['port']}: {status}")
    raise SystemExit(0 if all(r["ok"] for r in results) else 1)
