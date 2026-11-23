"""`aib` command line: create agent keys, request delegated tokens, inspect tokens."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import httpx
import jwt

from idkit import KeyPair

from .client import AgentClient, BrokerError


def cmd_keygen(args: argparse.Namespace) -> int:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    key = KeyPair.generate(kid=args.agent_id)
    path = out / f"{args.agent_id.replace(':', '_')}.pem"
    path.write_bytes(key.private_pem())
    path.chmod(0o600)
    print(f"private key written to {path} (mode 600)", file=sys.stderr)
    print(json.dumps({"agent_id": args.agent_id, "jwk": key.jwk}, indent=2))
    return 0


def cmd_token(args: argparse.Namespace) -> int:
    key = KeyPair.from_pem(Path(args.key).read_bytes(), kid=args.agent_id)
    dpop = KeyPair.from_pem(Path(args.dpop_key).read_bytes()) if args.dpop_key else None
    client = AgentClient(args.agent_id, key, args.broker, httpx.Client(timeout=10), dpop)
    subject_token = Path(args.subject_token_file).read_text().strip()
    try:
        result = client.exchange(subject_token, args.resource, args.scope)
    except BrokerError as exc:
        print(json.dumps(exc.body, indent=2), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


def cmd_decode(args: argparse.Namespace) -> int:
    token = args.token if args.token != "-" else sys.stdin.read().strip()
    print("header:", json.dumps(jwt.get_unverified_header(token), indent=2))
    claims = jwt.decode(token, options={"verify_signature": False})
    print("claims (NOT verified):", json.dumps(claims, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aib", description="Agent Identity Broker CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("keygen", help="create an ES256 key for an agent and print its public JWK")
    p.add_argument("--agent-id", required=True)
    p.add_argument("--out", default="keys")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("token", help="exchange a user's ID token for a delegated agent token")
    p.add_argument("--broker", required=True, help="broker issuer URL")
    p.add_argument("--agent-id", required=True)
    p.add_argument("--key", required=True, help="agent private key (PEM)")
    p.add_argument("--dpop-key", help="DPoP private key (PEM); generated if omitted")
    p.add_argument("--subject-token-file", required=True)
    p.add_argument("--resource", required=True)
    p.add_argument("--scope", nargs="+", required=True)
    p.set_defaults(func=cmd_token)

    p = sub.add_parser("decode", help="pretty-print a JWT without verifying it")
    p.add_argument("token", help="the JWT, or - to read stdin")
    p.set_defaults(func=cmd_decode)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
