# Lab 6b · Real SPIRE on Kubernetes, real SVIDs at the broker

You will run a SPIRE server and agent on a local Kubernetes cluster, give two AI-agent pods
SPIFFE identities, and have the Agent Identity Broker accept a real JWT-SVID from one of them
in place of a stored key. Then you will show the three ways it should fail.

Verified on an Apple-silicon Mac with Colima 0.10.3, kind 0.33.0 (Kubernetes 1.37), kubectl
1.37.2 and SPIRE 1.15.3. Time: about 20 minutes, most of it image pulls.

```
                       kind cluster "spire-lab"
 ┌───────────────────────────────────────────────────────────────────┐
 │ ns spire                                                          │
 │   spire-server-0 ─┬─ spire-server (CA, registration entries)      │
 │                   └─ oidc-discovery-provider ── /keys (JWKS) ─────┼──┐ port-forward
 │   spire-agent (DaemonSet) ── node attested with k8s_psat          │  │
 │        │ Workload API socket (hostPath)                           │  │
 │ ns agents                                                         │  │
 │   triage-bot pod  ─ SVID spiffe://corp.example/ns/agents/sa/triage-bot ─┐
 │   report-bot pod  ─ SVID spiffe://corp.example/ns/agents/sa/report-bot  │
 └───────────────────────────────────────────────────────────────────┘  │  │
   live_svid.py:  broker (verifies with /keys) ◀── JWT-SVID ────────────┘◀─┘
```

## 0. Tools

```bash
brew install colima kind kubernetes-cli
colima start --cpu 4 --memory 8 --disk 40 --vm-type vz
docker version --format '{{.Server.Version}}'
```

If Homebrew says the Xcode license is not accepted, run `sudo xcodebuild -license accept` in
Terminal first. If `kubectl` fails with "bad CPU type", an old Intel build in /usr/local/bin is
shadowing the Homebrew one; use `/opt/homebrew/bin/kubectl` or remove the old one.

## 1. Cluster

```bash
cd projects/06-workload-identity/k8s
kind create cluster --config kind.yaml
kubectl get nodes
```

## 2. SPIRE server (and OIDC discovery provider)

```bash
kubectl apply -f spire-server.yaml
kubectl -n spire rollout status statefulset/spire-server
kubectl -n spire logs spire-server-0 -c spire-server | grep "JWT key activated"
```

What's in [spire-server.yaml](k8s/spire-server.yaml):

- **Trust domain `corp.example`**, JWT-SVID lifetime 5 minutes, X.509-SVID 1 hour.
- **`k8s_psat` node attestor.** The server only accepts agents that present a projected
  service account token for `spire:spire-agent`, validated with the Kubernetes TokenReview API.
- **`k8sbundle` notifier** writes the CA bundle to the `spire-bundle` ConfigMap, which is how
  agents bootstrap trust in the server.
- **OIDC discovery provider sidecar** reads the JWT signing keys over the server's local admin
  socket and serves them at `/keys`. Relying parties (our broker, later AWS in lab 6d) fetch
  keys from here instead of talking to SPIRE.

## 3. SPIRE agent

```bash
kubectl apply -f spire-agent.yaml
kubectl -n spire rollout status ds/spire-agent
kubectl -n spire logs ds/spire-agent | grep "Node attestation was successful"
```

The agent gets `spiffe://corp.example/spire/agent/k8s_psat/spire-lab/<node-uid>`. It runs with
`hostPID` so it can map the PID calling its socket to a pod, then asks the kubelet which
namespace and service account that pod has. Those are the workload's **selectors**.

## 4. Register workloads, then deploy them

```bash
./register.sh
kubectl apply -f workloads.yaml
kubectl -n agents rollout status deploy/triage-bot
```

[register.sh](k8s/register.sh) creates a node alias for all agents in the cluster and one entry
per workload: `k8s:ns:agents` + `k8s:sa:<name>` → `spiffe://corp.example/ns/agents/sa/<name>`.
No secret goes into the pod; the identity follows from where the pod runs.

## 5. Fetch a real SVID from inside a pod

```bash
kubectl -n agents exec deploy/triage-bot -- /opt/spire/bin/spire-agent api fetch jwt \
  -audience https://broker.example.test/token -socketPath /run/spire/sockets/agent.sock
```

If you get `no identity issued` right after registering, wait about 5 seconds: the agent syncs
entries from the server on an interval. Decode the token (`uv run aib decode <token>`) and note:
`sub` is the SPIFFE ID, `aud` is the broker, lifetime is 300 s, and **there is no `iss`**.

## 6. Exchange it at the broker

From the repo root:

```bash
uv run python projects/06-workload-identity/live_svid.py
```

Expected output (abridged):

```
[1] triage-bot pod asks the SPIRE agent for a JWT-SVID (audience = broker /token)
    sub=spiffe://corp.example/ns/agents/sa/triage-bot  lifetime=300s  iss=None
[2] broker verifies it against the live bundle from the OIDC discovery provider
    issued: sub=user:alice act=agent:triage-bot scope='tickets.read'
    audit: token.issued agent_auth=jwt-svid spiffe_id=spiffe://corp.example/ns/agents/sa/triage-bot
[3] agent calls an MCP tool with the delegated token
    tickets.read -> HTTP 200
[4] report-bot: a real SVID from the same trust domain, but not registered as an agent
    denied as expected: HTTP 401 no agent registered for this SPIFFE ID
[5] triage-bot replays an SVID it holds for a different service
    denied as expected: HTTP 401 SVID rejected: token not issued for this audience
Live SPIRE lab: PASS
```

The script port-forwards `svc/spire-oidc` to `localhost:18008`, builds the lab with
`BundleFetcher("http://localhost:18008/keys")` as the broker's trust source, and uses
`kubectl exec … fetch jwt` as the agent's SVID source. Everything else is the same code the
unit tests and red-team suite run.

## 7. Offboard an agent

```bash
kubectl -n spire exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server entry show \
  -spiffeID spiffe://corp.example/ns/agents/sa/triage-bot          # copy the Entry ID
kubectl -n spire exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server entry delete \
  -entryID <id>
# about 5 seconds later:
kubectl -n agents exec deploy/triage-bot -- /opt/spire/bin/spire-agent api fetch jwt \
  -audience https://broker.example.test/token -socketPath /run/spire/sockets/agent.sock
# rpc error: code = PermissionDenied desc = no identity issued
./register.sh   # put it back
```

Measured here: new SVIDs stopped within 5 seconds of the delete. **SVIDs already issued stay
valid until they expire** (up to 5 minutes), and so do broker tokens minted from them. That is
why the broker keeps its own per-agent kill switch, enforced at introspection on every call.

## 8. Clean up

```bash
kind delete cluster --name spire-lab
colima stop
```

## What I'd say in an interview

- **Why not just a Kubernetes service account token?** It identifies a pod to the Kubernetes
  API. A SPIFFE ID is portable across clusters, VMs and clouds, has one format, and comes with
  X.509 (for mTLS) and JWT (for HTTP APIs) forms from the same registration.
- **Where does trust come from?** Node: the cluster vouches for the agent's service account
  token (k8s_psat). Workload: the agent observes the calling process and asks the kubelet. No
  step hands a secret to the workload.
- **Why audience-pin?** A workload may hold SVIDs for many services. Without an audience
  check, any service that receives one can replay it to every other (step 5).
- **Why map SPIFFE IDs to agents?** Being in the trust domain only proves "something in our
  cluster". The broker needs "this specific agent, with this owner and these scopes" (step 4).
- **Lab shortcuts to fix for production:** serve the OIDC discovery provider over HTTPS;
  deliver the socket with the SPIFFE CSI driver instead of hostPath; verify the kubelet's
  serving certificate; use a durable SQL datastore and an upstream CA or KMS-backed keys;
  run more than one server.
