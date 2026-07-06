# ADR-012 — Elastic IP on secops-management for stable Slack/webhook callbacks

- **Status:** Accepted
- **Context date:** Phase 6 (hardening)

## Context

`secops-management` hosts n8n and receives inbound callbacks: the Slack Interactivity Request URL and the n8n webhook base URL. Instances get a new public IP on every start. Each restart invalidated the Slack callback URL, requiring a manual fix in the Slack App config every session — the enforcement chain silently broke until then.

## Decision

Allocate an **Elastic IP** (`eipalloc-0cf96d693acb59cb5` → `13.55.19.90`) and associate it with `secops-management`. Slack Interactivity URL and `WEBHOOK_URL` are pinned to this stable address.

## Alternatives considered

- **Keep dynamic IP, script the Slack update:** still requires an API call and re-config on every restart; fragile.
- **Put an ALB / API Gateway in front:** stable DNS, but extra cost and infrastructure for a single inbound endpoint at this stage.
- **Dynamic DNS:** adds a dependency and propagation delay.

## Consequences

- **+** Slack callback and webhooks survive restarts with no manual intervention.
- **+** Simplest stable-endpoint option for one instance.
- **−** Small idle charge (~$0.005/hr) while the instance is stopped but the EIP stays allocated — negligible within the lab credit, but relevant since instances are stopped between sessions.
- Only this instance needs a stable IP; other instances remain on dynamic IPs (internal calls use stable private IPs).
