# ADR-002 — AI is passive, never inline in the live traffic path

- **Status:** Accepted
- **Context date:** Phase 0 (design)

## Context

The platform performs anomaly detection and LLM-based analysis. If any of these components sat inline (as a transparent proxy or bridge), their latency, crashes, or compromise would directly degrade or drop production traffic. An 8B LLM alone adds tens of seconds per call — unacceptable in-path.

## Decision

The entire detection and AI stack operates on a **mirrored copy** of traffic via VPC Traffic Mirroring (VXLAN, UDP 4789). No component of Layers 1.5–3 is on the forwarding path. Enforcement is applied out-of-band by mutating an AWS NACL, not by inline packet handling.

## Alternatives considered

- **Inline IPS/bridge (Suricata inline, gateway proxy):** lower detection-to-block latency, but any fault becomes a production outage, and LLM latency makes it infeasible.
- **Inline eBPF/XDP filtering:** fast, but couples detection logic to the datapath and complicates the AI integration.

## Consequences

- **+** Fault isolation: a crash or compromise of the AI/detection layer cannot break connectivity.
- **+** Free to run heavy, slow analysis (LLM, RAG) without datapath impact.
- **−** Enforcement is reactive, not preventive — an attacker gets a short window before the block lands.
- **−** Mirroring incurs per-GB cost; filtered to relevant traffic to contain it.
