# ADR-010 — NACL explicit deny for IP blocking, not Security Group rules

- **Status:** Accepted
- **Context date:** Phase 6 (hardening)

## Context

The original enforcement code blocked attackers by calling `authorize_security_group_ingress` with the attacker's IP. Testing revealed blocked IPs were never actually blocked.

**Root cause:** AWS Security Groups are **allow-only**. There is no deny rule type, and all rules are OR'd — adding a rule can only *widen* access, never restrict it. `authorize_ingress` on an attacker IP **grants** access. In a real attack this is a backdoor, not a block.

## Decision

Migrate enforcement to **Network ACL explicit deny** (`acl-02cccdb666cab9d47`). NACLs support both allow and deny, evaluated first-match by ascending rule number.

- Deny entries use rule numbers **1–99**, below the default allow-all at rule 100 (so they are evaluated first).
- `block_ip()` creates the deny entry, then **independently re-queries AWS** (`is_ip_blocked`) to confirm before returning `verified: true` — the audit log is never treated as ground truth.

## Alternatives considered

- **Security Group revoke:** only works if the IP was explicitly allowed; useless against a `0.0.0.0/0` public service.
- **AWS WAF IP-set:** native block semantics and scalable, but requires an ALB in front (not present until Phase 8).

## Consequences

- **+** Correct block semantics with independent verification.
- **−** NACL caps at ~99 usable deny slots and applies at **subnet** granularity — not production-scalable, and a deny affects the whole subnet.
- **−** Requires the internal-IP guard (ADR-011) to avoid self-blocking.
- **Production path:** AWS WAF IP-set via boto3, deferred to Phase 10 (arrives with the ALB in Phase 8).
