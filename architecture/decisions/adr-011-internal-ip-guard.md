# ADR-011 — Internal VPC CIDR unconditionally excluded from detection and enforcement

- **Status:** Accepted
- **Context date:** Phase 6 (hardening)

## Context

`live_detection.py` flagged VXLAN mirror traffic between `secops-zeek` (10.0.1.249) and `secops-target` (10.0.1.157) — legitimate internal traffic — as an anomaly. The alert was approved and the platform blocked its own infrastructure via NACL, breaking the Zeek→target capture path. Because NACL deny applies at subnet level, this also risked cutting admin SSH.

## Decision

Exclude the entire internal CIDR `10.0.0.0/16` at **two layers** (defense in depth):

1. **Detection** — `live_detection.py::is_internal(src_ip)` skips alert generation for internal sources, so they never reach n8n/Slack.
2. **Enforcement** — `firewall_actions.block_ip()` rejects any IP in `10.0.0.0/16` with `status: rejected_internal_ip` before any AWS call.

## Alternatives considered

- **Host-specific allowlist** (exempt only known infra IPs): more precise, but brittle as instances change and IPs churn.
- **Guard at one layer only:** insufficient — a single missed check re-enables self-blocking.

## Consequences

- **+** The platform can never block or alert on its own infrastructure.
- **+** Two independent guards; failure of one does not re-open the risk.
- **−** The system is **blind to intra-VPC lateral movement and insider threats** — any attack originating inside `10.0.0.0/16` is ignored.
- Acceptable for the current external-attacker demo scope. Extending to insider scenarios requires replacing the `/16` exclusion with a host-specific rule.
