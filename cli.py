"""
PsiTunnel Unified CLI: Run server relay or client proxy.
"""

import sys


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Usage: python cli.py [server | client | doctor] [options...]")
        print("\nCommands:")
        print("  server    Start the PsiTunnel relay server")
        print("  client    Start the PsiTunnel client with auto-fallback and local proxies")
        print("  doctor    Check configured relay connections and heartbeat")
        print("\nRun 'python cli.py <command> --help' for command-specific options.")
        sys.exit(0)

    cmd = sys.argv[1].lower()
    # Shift argv so sub-parsers see proper arguments
    sys.argv.pop(1)

    if cmd == "server":
        from psitunnel.server.server_cli import main as server_main
        server_main()
    elif cmd == "client":
        from psitunnel.client.client_cli import main as client_main
        client_main()
    elif cmd == "doctor":
        from psitunnel.client.doctor import main as doctor_main
        doctor_main()
    else:
        print(f"Unknown command: '{cmd}'. Choose 'server' or 'client'.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
