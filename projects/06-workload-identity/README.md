# 06 · Workload identity for agents (SPIFFE / SPIRE)

**Goal:** an AI agent proves who it is with an identity the platform issues and rotates for
it, a SPIFFE ID, instead of a private key someone generated and stored. Nothing long-lived
sits on disk to steal.

```
SPIRE server ──attests node──▶ SPIRE agent ──attests pod──▶ agent workload
                                              (k8s namespace + service account)
agent workload ──JWT-SVID (aud = broker /token)──▶ Agent Identity Broker
broker ──verifies with trust-domain bundle, maps SPIFFE ID → agent──▶ delegated token
```

## Status

| Part | What | State |
|---|---|---|
| 6a | Broker accepts JWT-SVIDs as the actor token; trust-domain check, bundle pinning, audience check, SPIFFE ID → agent mapping | Done, tested (broker tests + red-team A19–A21) |
| 6b | SPIRE server and agent on a local Kubernetes cluster (kind); a real pod gets a real SVID and exchanges it at the broker | Done, run live ([LAB.md](LAB.md)) |
| 6c | mTLS between gateway and broker with X.509-SVIDs, replacing the shared introspection secret | Next |
| 6d | JWT-SVID → AWS credentials through OIDC federation, no stored cloud keys | Planned |

## Run it live (6b)

[LAB.md](LAB.md) walks through it step by step: kind cluster, SPIRE server with the OIDC
discovery provider, SPIRE agent with `k8s_psat` node attestation, two registered agent pods,
and [live_svid.py](live_svid.py), which exchanges a real SVID at the broker and shows an
unregistered workload and a replayed SVID being refused. Manifests are in [k8s/](k8s).

## How 6a works

See the [broker README](../03-agent-identity-broker/README.md#workload-identity-spiffe). In short:

- **JWT-SVIDs have no `iss`.** Trust comes from the trust domain's bundle (its JWT signing
  keys), so the broker pins the bundle for exactly one trust domain.
- **Audience is the replay boundary.** A workload may hold SVIDs for many services; the broker
  only accepts ones minted for its own token endpoint (attack A20).
- **Being in the trust domain is not enough.** Any pod can get an SVID. Only SPIFFE IDs
  registered to an agent may act as one (attack A21).
- **Short-lived, sender-constrained output.** The delegated access token the broker issues is
  still DPoP-bound and five minutes long, so a leaked SVID has limited value on its own.

## Why this matters for agents

| Registered key (`private_key_jwt`) | SPIFFE JWT-SVID |
|---|---|
| Someone generates, distributes and rotates a key | SPIRE issues and rotates automatically (minutes to an hour) |
| Key file can be copied off the host | Identity comes from attestation of where the workload runs |
| Offboarding an agent means finding its keys | Delete the registration entry; no new SVIDs |
| Works anywhere, including laptops | Best for agents running on managed infrastructure |

The broker supports both, so laptop agents (with hardware-backed keys, roadmap 08) and
cluster agents (with SVIDs) go through the same delegation and policy path.
