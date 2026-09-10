"""JSON client profiles shared by the client and diagnostics commands."""
import argparse
import json
from pathlib import Path


PORTS = {"ws": 9003, "tls": 9002, "obfs": 9001}
OPTIONS = {"server", "transports", "obfs_port", "tls_port", "ws_port", "sni",
           "local_host", "socks_port", "http_port", "upstream_proxy", "max_channels", "bandwidth"}


def load_settings(path, profile=None):
    if not path:
        if profile:
            raise ValueError("--profile requires --config")
        return {}
    with open(path, encoding="utf-8") as source:
        document = json.load(source)
    if not isinstance(document, dict):
        raise ValueError("Configuration must be a JSON object")
    if document.keys() - {"defaults", "profiles", "default_profile"}:
        raise ValueError("Configuration accepts only defaults, profiles, and default_profile")
    settings = document.get("defaults", {})
    profiles = document.get("profiles", {})
    if not isinstance(settings, dict) or not isinstance(profiles, dict):
        raise ValueError("defaults and profiles must be objects")
    settings = dict(settings)
    selected = profile or document.get("default_profile")
    if selected is not None and not isinstance(selected, str):
        raise ValueError("default_profile must be a string")
    if selected:
        if selected not in profiles or not isinstance(profiles[selected], dict):
            raise ValueError("Selected profile does not exist or is not an object")
        settings.update(profiles[selected])
    unknown = settings.keys() - OPTIONS - {"relays", "psk_file"}
    if unknown:
        raise ValueError("Unknown configuration keys: " + ", ".join(sorted(unknown)))
    if settings.get("psk_file"):
        settings["psk_file"] = str(Path(path).resolve().parent / settings["psk_file"])
    return settings


def parse_client_args(parser, argv=None):
    parser.add_argument("--config", help="JSON configuration file")
    parser.add_argument("--profile", help="Profile name in the configuration")
    parser.add_argument("--psk-file", help="Read the shared key from a UTF-8 file")
    probe = argparse.ArgumentParser(add_help=False)
    probe.add_argument("--config")
    probe.add_argument("--profile")
    preliminary, _ = probe.parse_known_args(argv)
    try:
        settings = load_settings(preliminary.config, preliminary.profile)
        parser.set_defaults(**{k: v for k, v in settings.items() if k in OPTIONS or k == "psk_file"})
        args = parser.parse_args(argv)
        if type(args.max_channels) is not int or args.max_channels < 1 or type(args.bandwidth) is not int or args.bandwidth < 0:
            raise ValueError("max_channels must be positive and bandwidth nonnegative")
        if args.psk_file and not args.psk:
            args.psk = Path(args.psk_file).read_text(encoding="utf-8").strip()
        if not args.psk or args.psk == "psitunnel-secret-key-change-me":
            raise ValueError("a non-default key is required via --psk, PSK, or --psk-file")
        if not isinstance(args.transports, str):
            raise ValueError("transports must be a comma-separated string")
        for name in ("obfs_port", "tls_port", "ws_port", "socks_port", "http_port"):
            value = getattr(args, name)
            if type(value) is not int or not 1 <= value <= 65535:
                raise ValueError(f"{name} must be an integer between 1 and 65535")
        for name in ("server", "local_host"):
            if not isinstance(getattr(args, name), str) or not getattr(args, name).strip():
                raise ValueError(f"{name} must be a nonempty string")
        args.relays = settings.get("relays")
        args.endpoints = build_endpoints(args)
        return args
    except (ValueError, OSError, TypeError) as exc:
        parser.error(str(exc))


def build_endpoints(args):
    from urllib.parse import urlparse
    if args.relays is not None:
        if not isinstance(args.relays, list) or not args.relays:
            raise ValueError("relays must be a nonempty list of endpoint objects")
        endpoints = []
        for item in args.relays:
            if not isinstance(item, dict) or item.keys() - {"host", "port", "transport", "sni", "path", "use_ssl"}:
                raise ValueError("Invalid relay endpoint fields")
            endpoint = dict(item)
            kind = endpoint.get("transport", "ws")
            if kind not in PORTS:
                raise ValueError("Relay transport must be ws, tls, or obfs")
            endpoint["transport"] = kind
            endpoint.setdefault("port", PORTS[kind])
            if not isinstance(endpoint.get("host"), str) or not endpoint["host"].strip() or any(c.isspace() for c in endpoint["host"]):
                raise ValueError("Relay host must be a hostname or IP address")
            if type(endpoint["port"]) is not int or not 1 <= endpoint["port"] <= 65535:
                raise ValueError("Relay port must be between 1 and 65535")
            if "use_ssl" in endpoint and type(endpoint["use_ssl"]) is not bool:
                raise ValueError("use_ssl must be a boolean")
            for field in ("path", "sni"):
                if field in endpoint and (not isinstance(endpoint[field], str) or any(c.isspace() for c in endpoint[field])):
                    raise ValueError(f"Invalid relay {field}")
            endpoints.append(endpoint)
        return endpoints
    host = args.server.strip()
    if "://" in host:
        host = urlparse(host).hostname or host
    kinds = [t.strip().lower() for t in args.transports.split(",") if t.strip()]
    if not kinds or any(t not in PORTS for t in kinds):
        raise ValueError("transports must contain ws, tls, or obfs")
    return [dict(transport=t, host=host, port=getattr(args, t + "_port"),
                 **({"sni": args.sni} if t == "tls" and args.sni else {})) for t in kinds]
