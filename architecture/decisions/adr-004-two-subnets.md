# ADR-004 — Two subnets instead of six

- **Status:** Accepted
- **Context date:** Phase 1 (infrastructure)

## Context

The reference design specified six per-layer subnets (workloads, security, AI, management, data, public) to minimise lateral movement if one layer is compromised. This is sound for production but heavy for a single-account portfolio build on constrained credit.

## Decision

Deploy **two subnets** — one public (`10.0.1.0/24`), one private (`10.0.2.0/24`, reserved for future segmentation). Per-layer isolation intent is instead enforced with **five role-based Security Groups** (workloads, zeek, detection, management, ai) plus a subnet-level NACL.

## Alternatives considered

- **Full six-subnet design:** best isolation, but adds NAT gateways, route tables, and cross-subnet SG rules — cost and operational overhead without proportional security gain at this scale.
- **Single flat subnet:** simplest, but no segmentation story at all.

## Consequences

- **+** Lower cost and fewer moving parts; faster to reason about in a demo.
- **+** SG-per-role still gives host-level east-west control.
- **−** No subnet-level blast-radius containment between layers; a compromised host relies on SG rules alone.
- **−** NACL enforcement applies to the whole public subnet, so a deny affects every instance in it (mitigated by the internal-IP guard, ADR-011).
- Six-subnet segmentation remains the documented production path.
