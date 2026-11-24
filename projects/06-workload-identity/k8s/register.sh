#!/usr/bin/env bash
# Create SPIRE registration entries: which workloads get which SPIFFE IDs.
# Safe to re-run; existing entries are reported and left alone.
set -euo pipefail

TD="spiffe://corp.example"
server() { kubectl -n spire exec spire-server-0 -c spire-server -- /opt/spire/bin/spire-server "$@"; }

# 1. A node alias: every SPIRE agent in cluster spire-lab running as spire:spire-agent.
#    Workload entries hang off this alias instead of one specific node's agent ID.
server entry create \
  -node \
  -spiffeID "$TD/ns/spire/sa/spire-agent" \
  -selector k8s_psat:cluster:spire-lab \
  -selector k8s_psat:agent_ns:spire \
  -selector k8s_psat:agent_sa:spire-agent || true

# 2. Workloads: identity comes from where the pod runs (namespace + service account),
#    which the agent checks with the kubelet. No secret is handed to the pod.
for sa in triage-bot report-bot; do
  server entry create \
    -parentID "$TD/ns/spire/sa/spire-agent" \
    -spiffeID "$TD/ns/agents/sa/$sa" \
    -selector k8s:ns:agents \
    -selector "k8s:sa:$sa" \
    -jwtSVIDTTL 300 || true
done

server entry show
