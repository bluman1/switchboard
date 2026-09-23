"""Run the relay: ``switchboard-relay [--host H] [--port P] [--ssl-certfile F --ssl-keyfile F]``.

Configuration comes from the environment:

- ``SWITCHBOARD_RELAY_DB``                    SQLite path (default ``switchboard-relay.db``)
- ``SWITCHBOARD_RELAY_OPERATORS``             comma-separated ed25519 pubkeys that are T2 roots
- ``SWITCHBOARD_RELAY_DOMAIN``                public hostname, informational
- ``SWITCHBOARD_RELAY_SSL_CERTFILE``          PEM certificate; with the key file, the relay serves HTTPS itself
- ``SWITCHBOARD_RELAY_SSL_KEYFILE``           PEM private key
- ``SWITCHBOARD_RELAY_TRUST_PROXY``           ``1`` when a proxy you control terminates TLS and sets X-Forwarded-For
- ``SWITCHBOARD_RELAY_REGISTER_PER_HOUR_PER_IP``  registration limit per client address (default 10)
"""

from __future__ import annotations

import argparse
import os
import sys

import uvicorn

from .app import Settings, create_app

LOOPBACK = {"127.0.0.1", "::1", "localhost"}


def main() -> None:
    parser = argparse.ArgumentParser(prog="switchboard-relay")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8470)
    parser.add_argument("--ssl-certfile", default=os.environ.get("SWITCHBOARD_RELAY_SSL_CERTFILE"))
    parser.add_argument("--ssl-keyfile", default=os.environ.get("SWITCHBOARD_RELAY_SSL_KEYFILE"))
    args = parser.parse_args()
    if bool(args.ssl_certfile) != bool(args.ssl_keyfile):
        parser.error("--ssl-certfile and --ssl-keyfile go together")
    settings = Settings.from_env()
    app = create_app(settings)
    print(f"relay pubkey: {app.state.relay_keypair.ed25519_pub}")
    print(f"operators:    {', '.join(sorted(app.state.operators))}")
    if args.ssl_certfile:
        print(f"tls:          {args.ssl_certfile}")
    elif settings.trust_proxy:
        print("tls:          terminated by a trusted proxy (X-Forwarded-For honoured)")
    elif args.host not in LOOPBACK:
        print(
            f"WARNING: serving plaintext HTTP on {args.host}. Clients refuse http:// relays that are not local.\n"
            "         Pass --ssl-certfile/--ssl-keyfile, or put a TLS proxy in front and set SWITCHBOARD_RELAY_TRUST_PROXY=1.",
            file=sys.stderr,
        )
    uvicorn.run(
        app, host=args.host, port=args.port, log_level="info",
        ssl_certfile=args.ssl_certfile, ssl_keyfile=args.ssl_keyfile,
    )


if __name__ == "__main__":
    main()
