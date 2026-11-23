# 05 · Agent red team

Twenty-one attacks against the whole stack, each mapped to a threat and to the control that is
supposed to stop it. Every attack runs against a fresh in-process lab. The tests check that it
was blocked **by the intended control**, not by some unrelated failure, and also check that
the same flows succeed when nobody is attacking.

```bash
uv run python -m redteam          # prints results, writes reports/redteam-report.md
uv run pytest projects/05-agent-redteam
```

| Group | Attacks |
|---|---|
| Token theft and replay | stolen token without DPoP key · DPoP token sent as Bearer · replayed DPoP proof · genuine token for another API · expired token |
| Forgery | `alg=none` token · forged `act` claim |
| Impersonation | stolen agent ID with attacker's key · replayed agent assertion · look-alike IdP |
| Workload identity | SVID from a rogue SPIRE server · SVID for another service replayed · unregistered workload in the trust domain |
| Privilege expansion | scope escalation beyond user's role · confused deputy (unregistered resource) |
| Prompt injection / excessive agency | injected instruction → `admin.export_users` · refund without approval · approval reuse for a larger amount · approved refund over limit |
| Lifecycle | user deprovisioned mid-session · compromised agent kill switch |

The threat model these come from is in [docs/threat-model.md](../../docs/threat-model.md).
The latest output is in [reports/redteam-report.md](../../reports/redteam-report.md).

Adding an attack: write a function `(lab) -> Outcome` in
[`attacks.py`](src/redteam/attacks.py), add it to `ATTACKS`, and add the evidence you expect
to `EXPECTED_EVIDENCE` in the test.
