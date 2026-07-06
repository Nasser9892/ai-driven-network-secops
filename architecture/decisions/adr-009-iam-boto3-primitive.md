# ADR-009 — AWS actions via a single IAM-Role/boto3 primitive, not raw HTTP from n8n

- **Status:** Accepted
- **Context date:** Phase 6 (hardening)

## Context

n8n needed to perform two AWS actions: block an IP (NACL) and send an escalation email (SES). The initial approach called AWS service endpoints directly from n8n's generic HTTP Request node. SES rejected this with `403 MissingAuthenticationToken` — AWS signed endpoints require SigV4 on every request.

## Decision

Route **all** AWS actions through one primitive: a loopback Flask enforcement API (`enforcement_api.py`, port 5680) on `secops-management`, which uses **boto3 with the instance IAM Role** (`secops-ai-role`). n8n only makes plain HTTP calls to `127.0.0.1:5680`. Endpoints: `/block`, `/escalate`, `/flag`, `/reject`.

## Alternatives considered

- **SigV4 signing inside n8n:** possible, but fragile, and spreads AWS auth across many workflow nodes.
- **AWS access keys in n8n credentials:** works, but places long-lived secrets inside n8n — larger attack surface and a leak risk on export.

## Consequences

- **+** Single auth model; **zero AWS credentials inside n8n** (no keys to leak on workflow export to GitHub).
- **+** Each AWS action is unit-testable in isolation via `curl` to the API.
- **+** SES policy is scoped to the verified sender address only.
- **−** Adds one service to run and keep alive on `secops-management`.
- **−** Loopback-only means the API and n8n must co-locate on the same instance.
