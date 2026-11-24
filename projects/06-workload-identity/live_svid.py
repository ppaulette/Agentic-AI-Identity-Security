"""Lab 6b, live: real JWT-SVIDs from SPIRE on kind, exchanged at the Agent Identity Broker.

The broker, gateway and PDP run in this process (as in the rest of the repo). What is real:
  * the SVIDs, minted by SPIRE for pods in the kind cluster and fetched over the Workload API
  * the trust bundle, fetched over HTTP from the SPIRE OIDC discovery provider's /keys

Prerequisites: the cluster from LAB.md (k8s/*.yaml applied, k8s/register.sh run).
Run from the repo root:  uv run python projects/06-workload-identity/live_svid.py

Shells out to kubectl with fixed argument lists (no shell), hence the S603/S607 waivers.
"""

# ruff: noqa: S603, S607
from __future__ import annotations

import base64
import contextlib
import json
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Iterator

from agent_broker.client import AgentClient, BrokerError
from agentlab import BROKER, MCP, build_lab
from idkit import BundleFetcher

OIDC_PORT = 18008
JWKS_URL = f"http://localhost:{OIDC_PORT}/keys"
SOCKET = "/run/spire/sockets/agent.sock"


def svid_from_pod(deployment: str) -> Callable[[str], str]:
    """An SVID source backed by the SPIRE Workload API inside a pod in namespace `agents`."""

    def fetch(audience: str) -> str:
        cmd = ["kubectl", "-n", "agents", "exec", f"deploy/{deployment}", "--",
               "/opt/spire/bin/spire-agent", "api", "fetch", "jwt", "-audience", audience,
               "-output", "json", "-socketPath", SOCKET]  # fmt: skip
        out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
        return json.loads(out)[0]["svids"][0]["svid"]

    return fetch


@contextlib.contextmanager
def port_forward() -> Iterator[None]:
    """kubectl port-forward to the OIDC discovery provider for the duration of the run."""
    proc = subprocess.Popen(
        ["kubectl", "-n", "spire", "port-forward", "svc/spire-oidc", f"{OIDC_PORT}:80"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(50):
            with contextlib.suppress(OSError), socket.create_connection(("localhost", OIDC_PORT), 0.2):
                break
            time.sleep(0.2)
        else:
            sys.exit("port-forward to spire-oidc did not come up")
        yield
    finally:
        proc.terminate()


def segment(token: str, i: int) -> dict:
    part = token.split(".")[i]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def step(n: int, text: str) -> None:
    print(f"\n[{n}] {text}")


def main() -> int:
    token_endpoint = f"{BROKER}/token"
    triage = svid_from_pod("triage-bot")

    with port_forward():
        bundle = BundleFetcher(JWKS_URL)
        lab = build_lab(spiffe_bundle=bundle, svid_source=triage)
        failures = 0

        step(1, "triage-bot pod asks the SPIRE agent for a JWT-SVID (audience = broker /token)")
        svid = triage(token_endpoint)
        header, claims = segment(svid, 0), segment(svid, 1)
        print(f"    header: alg={header['alg']} kid={header['kid']}")
        print(f"    sub={claims['sub']}")
        print(f"    aud={claims['aud']}  lifetime={claims['exp'] - claims['iat']}s  iss={claims.get('iss')}")

        step(2, "broker verifies it against the live bundle from the OIDC discovery provider")
        print(f"    bundle kids from {JWKS_URL}: {sorted(bundle()._keys)}")
        id_token = lab.id_token("alice", ["support"])
        grant = lab.svid_agent.exchange(id_token, MCP, ["tickets.read"])
        access = segment(grant["access_token"], 1)
        print(f"    issued: sub={access['sub']} act={access['act']['sub']} scope={access['scope']!r}")
        print(f"    DPoP-bound: cnf.jkt={access['cnf']['jkt'][:16]}...  expires_in={grant['expires_in']}s")
        event = lab.audit.find("token.issued")[-1]
        print(f"    audit: {event['event']} agent_auth={event.get('agent_auth')}")
        print(f"           spiffe_id={event.get('spiffe_id')}")

        step(3, "agent calls an MCP tool with the delegated token")
        r = lab.svid_agent.call_tool(MCP, grant["access_token"], "tickets.read", {"ticket_id": "T-100"},
                                     gateway=lab.gateway)  # fmt: skip
        print(f"    tickets.read -> HTTP {r.status_code}")
        failures += r.status_code != 200

        step(4, "report-bot: a real SVID from the same trust domain, but not registered as an agent")
        report_bot = svid_from_pod("report-bot")
        rogue = AgentClient("agent:report-bot", None, BROKER, lab.broker, svid_source=report_bot)
        failures += expect_denied(lambda: rogue.exchange(id_token, MCP, ["tickets.read"]))

        step(5, "triage-bot replays an SVID it holds for a different service")
        other = triage("https://payments.example/token")
        replay = AgentClient("agent:triage-bot", None, BROKER, lab.broker, svid_source=lambda _aud: other)
        failures += expect_denied(lambda: replay.exchange(id_token, MCP, ["tickets.read"]))

    print("\nLive SPIRE lab:", "PASS" if failures == 0 else f"{failures} unexpected result(s)")
    return 1 if failures else 0


def expect_denied(call: Callable[[], dict]) -> int:
    try:
        call()
    except BrokerError as e:
        print(f"    denied as expected: HTTP {e.status} {e.body.get('error_description')}")
        return 0
    print("    UNEXPECTED: broker issued a token")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
