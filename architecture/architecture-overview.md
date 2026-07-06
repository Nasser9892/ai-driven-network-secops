# AI-Driven Network Security Platform — AWS

**Architecture Reference | As-Built + Roadmap**

> This document describes the platform **as actually implemented** on AWS (`ap-southeast-2`), and the technical roadmap for the phases still on the plan (Phase 8–11). Where the delivered system deviates from the original idealized design, the deviation and its rationale are documented inline and in the linked ADRs.

---

## 1. Problem Statement & Design Goals

A **passive, AI-assisted network security platform** on AWS with three objectives, each requiring an independent but connected sub-architecture:

| Goal | Description | Core Challenge |
|------|-------------|----------------|
| **Traffic Visibility** | See all network traffic with no blind spot | Encrypted traffic (TLS/SSL), volume |
| **Anomaly Detection** | Detect abnormal behavior in near real-time | High false-positive rate, drifting baseline |
| **Automated Response** | Fast action with human oversight | Balance between speed and precision |

**Critical design principle:** the AI is **never inline** in the live traffic path. The entire detection and analysis architecture is **passive** — it operates on mirrored copies of traffic, so a failure or compromise of the AI layer cannot affect production connectivity. (See `ADR-002`.)

---

## 2. High-Level Architecture — Four Independent Layers

```
                    INTERNET / EXTERNAL TRAFFIC
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 0: PERIMETER                                              │
│  AWS Security Groups (allow-list) + Network ACL (explicit deny)  │
│  ← enforcement point, driven by boto3 from Layer 3              │
└──────────────────────────────┬──────────────────────────────────┘
                               │ live + VPC Traffic Mirroring (copy)
          ┌────────────────────┴────────────────────┐
          │ live traffic                            │ mirrored copy (passive)
          ▼                                         ▼
┌─────────────────────┐              ┌──────────────────────────────┐
│  LAYER 1: WORKLOAD  │              │  LAYER 1.5: CAPTURE          │
│  secops-target EC2  │              │  Zeek 8.0.5 (passive)        │
│  (attack target)    │              │  conn / dns / http / ssl /   │
│                     │              │  weird / notice logs         │
└─────────────────────┘              └───────────────┬──────────────┘
                                                     │
                                                     ▼
┌────────────────────────────────────────────────────────────────┐
│  LAYER 2: DETECTION ENGINE                                      │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ 2A: ML Anomaly Detection (fast path)                     │  │
│  │ Zeek logs → Feature Engineering → Isolation Forest       │  │
│  │ score < -0.05 → ALERT   |   score < -0.15 → CRITICAL     │  │
│  └──────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │ 2B: SIEM Correlation (Wazuh 4.14.5)                      │  │
│  │ Zeek logs + host syslogs → rules → MITRE ATT&CK mapping  │  │
│  └──────────────────────────────────────────────────────────┘  │
└───────────────────────────────────┬────────────────────────────┘
                                    │ filtered — suspicious only
                                    ▼
┌────────────────────────────────────────────────────────────────┐
│  LAYER 3: AI ANALYSIS & RESPONSE                               │
│  n8n Orchestrator ──► RAG Context (ChromaDB)                   │
│         │                    │                                 │
│         ▼                    ▼                                 │
│  Llama-3.1-8B (Ollama, CPU) — deep analysis, structured output │
│         │                                                      │
│    ┌────┴──────────────┬───────────────────┐                  │
│    ▼                   ▼                   ▼                  │
│  block_ip()      escalate_to_human()   notify_soc()          │
│  (boto3/NACL)    (Slack + SES)         (Slack / Dashboard)    │
│    │ Human-in-the-loop (Slack Approve/Reject)                 │
│    ▼                                                          │
│  NACL explicit deny entry (acl-02cccdb666cab9d47)             │
└────────────────────────────────────────────────────────────────┘
```

---

## 3. Layer 0 — AWS Infrastructure (As-Built)

### 3.1 VPC & Subnet Design

```
VPC: vpc-0455a10988fec19f5 — 10.0.0.0/16
├── Public Subnet:  subnet-023e50f4841e32e8c — 10.0.1.0/24
└── Private Subnet: subnet-07af774fee300d1d8 — 10.0.2.0/24
Internet Gateway: igw-00a8913e6e78d5204
NACL (enforcement): acl-02cccdb666cab9d47 (associated with public subnet)
```

**Deviation from original design (ADR-004):** the reference design specified six per-layer subnets for maximum lateral-movement isolation. The delivered platform uses **two subnets** (public/private). Rationale: within a single-account portfolio build on constrained credit, six subnets added NAT/routing cost and operational overhead without a proportional security gain at this scale. The per-layer isolation intent is instead enforced through **five distinct Security Groups** (one per role) plus the NACL. Six-subnet segmentation remains the documented production path.

### 3.2 EC2 Instances (all Ubuntu 22.04)

| Instance | ID | Private IP | Type | Role |
|----------|-----|-----------|------|------|
| secops-target | i-0e721b436786b05bb | 10.0.1.157 | t3.micro | Attack target / workload |
| secops-zeek | i-02d94970bcb1e77c9 | 10.0.1.249 | t3.large | Zeek passive capture |
| secops-detection | i-0d853b653bc2517ff | 10.0.1.207 | t3.large | ML engine + Wazuh SIEM (12 GB EBS) |
| secops-management | i-0860e2cc252977841 | 10.0.1.90 (EIP **13.55.19.90**) | t3.xlarge | Ollama + n8n + enforcement API |
| secops-dashboard | i-06df8b1c2e56eae0f | 10.0.1.36 | t3.medium | SOC Dashboard (FastAPI + React + SQLite) |

**Elastic IP on secops-management** is intentional: the Slack Interactivity Request URL and n8n webhook base URL must be stable across restarts. Without the EIP, every instance restart invalidated the Slack callback. (See `ADR-012`.)

### 3.3 VPC Traffic Mirroring — SPAN-equivalent in AWS

```
secops-target ENI ──► Mirror Session (tms-…) ──► secops-zeek ENI (VXLAN, UDP 4789)
Mirror Target: tmt-084d30311d7469c61
Mirror Filter: tmf-06a768068b7d883bd (all traffic, ingress + egress)
```

Zeek receives the mirrored copy over VXLAN port 4789. This is the AWS-native replacement for a physical SPAN port / promiscuous NIC.

### 3.4 Enforcement — NACL Explicit Deny (**not** Security Group)

**This is the single most important as-built correction.** The original design described blocking via `authorize_security_group_ingress`. That is architecturally wrong: **AWS Security Groups are allow-only** — all rules are OR'd, so adding a rule can only *widen* access, never restrict it. Calling `authorize_ingress` on an attacker IP would have opened a backdoor, not closed one.

Enforcement was therefore migrated to **Network ACL explicit deny**:

- Target NACL: `acl-02cccdb666cab9d47`
- Deny entries use rule numbers **1–99** (below the default `allow-all` at rule 100, so they are evaluated first — NACL is first-match by ascending rule number)
- `firewall_actions.block_ip()` creates the deny entry, then **independently re-queries AWS** to confirm the block before returning `verified: true` — the audit log is never trusted as ground truth
- **Internal-IP guard:** any source inside `10.0.0.0/16` is unconditionally rejected before any AWS call, so the platform can never block its own infrastructure

**Documented limitation:** NACLs cap at ~99 usable deny slots and apply at subnet granularity. Acceptable for a single-attacker demo; the production path is an **AWS WAF IP-set** (native block semantics, scalable), deferred to Phase 10. (See `ADR-010`, `ADR-011`.)

---

## 4. Layer 1.5 — Zeek: Raw Traffic to Structured Data

Zeek (v8.0.5) is the first and most important transformation point: it converts raw mirrored packets into structured logs that both the ML engine and Wazuh consume directly.

| Log | Content | ML Use |
|-----|---------|--------|
| `conn.log` | All TCP/UDP/ICMP connections | ✅ Primary feature source |
| `dns.log` | DNS queries | ✅ DNS tunneling detection (roadmap) |
| `http.log` | HTTP requests (URL, method, UA) | ✅ Web-attack detection (Phase 8) |
| `ssl.log` | TLS handshakes (no decrypt) | ✅ Suspicious-cert detection |
| `weird.log` | Protocol anomalies Zeek self-detects | ✅ Direct to Wazuh |
| `notice.log` | Built-in Zeek alerts (scan, DDoS) | ✅ Direct to Wazuh |

**Operational note:** Zeek and the log-sync process run as plain `nohup` background processes, not systemd units — they do not survive a disk-full event and require manual restart. Converting them to systemd is a tracked hardening item.

---

## 5. Layer 2A — ML Anomaly Detection

### 5.1 Why a lightweight ML layer before the LLM

An 8B LLM on CPU takes tens of seconds per request. Sending every log to it would collapse the system in minutes. The Isolation Forest engine scores thousands of connections per second on CPU and forwards only the small anomalous fraction to the LLM.

### 5.2 Feature Set (verified, consistent across all scripts)

```
FEATURE_COLS = [
  unique_dst_ports, unique_dst_ips, failed_conn_rate, bytes_out_ratio,
  conn_per_second, packet_to_byte_ratio, conn_state_encoded,
  duration, orig_bytes, orig_pkts
]
conn_state encoding: REJ=0, RST=1, S0=2, SF=3, other=4
FAILED_STATES = {REJ, RST, S0}
```

Aggregated features use a **10-second window per source IP**.

### 5.3 Model

- Algorithm: **Isolation Forest** (scikit-learn), `contamination=0.01`, `n_estimators=100`, `random_state=42`
- Trained on 833 baseline connection records
- Thresholds: score `< -0.05` → ALERT, score `< -0.15` → CRITICAL
- Poll interval: 5 s; deduplication by `(src_ip, window_start)`

**Known issue (tracked, highest pre-Phase-8 priority):** `live_detection.py` is **stateless** — each poll re-reads the whole `conn.log` and the cooldown/dedup dictionary is in-memory, so a restart re-flags old scan lines and duplicates alerts. Fix planned: byte-offset tracking on `conn.log` + persistent on-disk cooldown reloaded on startup.

---

## 6. Layer 2B — Wazuh SIEM

Wazuh 4.14.5 applies logical correlation rules on top of the statistical ML signal and maps each alert to MITRE ATT&CK.

- Manager on secops-detection (`10.0.1.207`); agent on secops-zeek (`10.0.1.249`)
- Zeek `conn.log` / `notice.log` / `weird.log` ingested via agent `localfile`
- Custom rules: Port Scan (T1046, level 10/12), Protocol Violation (T1071, level 8)

| MITRE Technique | ID | Log Signal |
|-----------------|-----|-----------|
| Network Scanning | T1046 | `unique_dst_ports > 15` in 10 s |
| Brute Force | T1110 | `failed_auth_rate > 50%` |
| DNS Tunneling | T1071.004 | `query_entropy > 3.5` |
| Data Exfiltration | T1041 | `bytes_out_ratio > 10` |
| Lateral Movement | T1021 | `unique_dst_ips > 5` from one internal host |

**Wazuh Vulnerability Detection is permanently disabled** (`<enabled>no</enabled>`). It repeatedly filled the 12 GB root disk (`queue/vd*` + `vd_*.tar` ≈ 8–9 GB). A `disk-guard.sh` cron (every 10 min, acts above 85% usage) provides defense in depth.

---

## 7. Layer 3 — AI Analysis: Llama-3.1-8B + RAG

### 7.1 As-built AI serving (deviation from design)

The reference design specified **vLLM on a g4dn GPU instance**. The delivered platform runs **Ollama + Llama-3.1-8B on CPU** (t3.xlarge, secops-management). Rationale: GPU instances are expensive to keep running and the credit budget favored a persistently-available CPU path over an intermittently-available GPU.

**Measured consequence:** LLM response is **~40–52 s** on CPU (≈9 s cold-start to load the ~5 GB model, plus generation), against the original `<10 s` KPI target. This is documented honestly as a **known limitation** — the KPI is achievable only with the GPU serving path, which remains the documented production option.

- `OLLAMA_HOST=0.0.0.0` must be set via systemd override for cross-instance VPC access (recurring post-restart pitfall).

### 7.2 RAG (ChromaDB)

Network knowledge is indexed into ChromaDB and injected into each analysis: topology, asset inventory, baseline behavior. The SOC Dashboard chat additionally injects a SOC-analyst system prompt plus the N most recent SQLite alerts, so the assistant answers are grounded in live data rather than hallucinated.

### 7.3 Function Calling / Tools

`block_ip` (via NACL/boto3, human-approval-gated), `escalate_to_human` (Slack + SES), `query_threat_intel`, `notify_soc`. Only `block_ip` and firewall-mutating actions require human approval; enrichment and escalation run automatically.

---

## 8. Layer 3 — n8n Orchestration

n8n (self-hosted, port 5678) coordinates the full chain. Enforcement is executed through a **Flask enforcement API** (port 5680, loopback) rather than n8n's `executeCommand` node (removed in n8n 2.8) — this also keeps a single IAM-Role/boto3 authentication model with **no AWS credentials anywhere inside n8n**.

| Workflow | Trigger | Function |
|----------|---------|----------|
| WF01 Alert Triage | Webhook from ML / Wazuh | Sanitize → RAG context → Llama → risk level |
| WF02 Human Approval | WF01 output | Slack Approve/Reject + policy-driven escalation timer |
| WF03 Firewall Enforcement | Approval or timeout | `block_ip` via enforcement API → NACL deny + SES email |
| WF04 Slack Interaction | Slack button callback | Cross-workflow state bridge via `/flag` |

**Escalation policy** is AEST-business-hours aware (CRITICAL 30 min, HIGH 60/30 min, MEDIUM 120/60 min email-only, LOW log-only).

The full **Approve path is independently verified** end-to-end via direct AWS NACL query (`203.0.113.50/32` deny entry confirmed) — not merely by green workflow nodes.

---

## 9. SOC Dashboard

```
Browser (admin IP, HTTPS) → nginx (443, self-signed TLS)
  ├── /            → React static build
  └── /api/        → FastAPI (localhost:8000)
                       ├── /chat         → Ollama 10.0.1.90:11434 (network-aware)
                       ├── /alerts       → SQLite read (last 50)
                       └── /ingest-alert → SQLite write (from detection sync)
```

Alerts sync from `secops-detection` (`live_detection.py` → `alerts.json` → `sync_alerts_to_dashboard.py` → `/ingest-alert`). nginx requires `proxy_read_timeout 300s` because CPU inference exceeds the default 60 s.

---

## 10. Egress Monitoring — Roadmap (Phase 9)

Most real attacks (exfiltration, C2, beaconing) are outbound. Beaconing is *regular*, not *anomalous*, so Isolation Forest does not catch it well — the planned detector uses **FFT on inter-connection intervals** to find a dominant frequency:

```python
intervals = np.diff(sorted(timestamps))
power = np.abs(np.fft.fft(intervals)) ** 2
dominant = max(power[1:]) / np.mean(power[1:])
return dominant > 10   # beaconing if a single frequency dominates
```

Egress features: `bytes_out_per_hour`, `unique_external_ips`, `connection_regularity`, `dst_port_unusual`, `tls_without_sni`. VPC Flow Logs → CloudWatch → Lambda complements Zeek for metadata-level egress. **Status: not yet implemented.**

---

## 11. Self-Security of the AI System — Roadmap (Phase 10)

- **Prompt-injection defense** (`sanitizer.py`): length-cap, escape/filter of injection markers, delimiter-wrap of log data before it reaches the LLM.
- **Data masking:** internal IPs / credentials masked before LLM submission.
- **Network isolation:** Ollama has no outbound internet path; reachable only within the VPC.
- **IAM scope-down (highest hardening priority):** `secops-ai-role` currently holds `AmazonEC2FullAccess` — too large a blast radius for an automated agent. To be replaced with a scoped policy limited to the specific NACL/SG describe+mutate actions on named resources.

---

## 12. End-to-End Flow — Nmap Scan (Phase 7, **implemented & recorded**)

```
1. Attacker (throwaway EC2, non-admin IP) runs nmap -sS -T4 --min-rate 500 → secops-target
2. VPC Traffic Mirroring copies traffic to Zeek
3. Zeek conn.log: many REJ/RST/S0, orig_bytes=0, high unique_dst_ports
4. live_detection.py: Isolation Forest score < -0.15 → CRITICAL alert JSON
5. Wazuh: "Port Scan Detected" → MITRE T1046
6. n8n WF01: sanitize → ChromaDB context → Llama analysis
7. Llama: {threat: Port Scan, mitre: T1046, action: block_ip}
8. WF02: Slack message with Approve/Reject
9. Admin clicks Approve → WF04 → WF03
10. enforcement API → NACL deny entry (rule 1–99) → verified via independent AWS query
11. Audit record written; blocked IP loses subnet access
```

**Verification note:** for enforcement-path testing, synthetic external alerts (`curl` with a fabricated `src_ip` such as `203.0.113.50`) are used — **never nmap from the admin IP**, because a subnet-level NACL deny would also cut the admin's own SSH / n8n / dashboard access.

---

## 13. Implementation Phases — Status & Roadmap

| Phase | Title | Status | Evidence |
|-------|-------|--------|----------|
| 0 | Account & tooling | ✅ Complete | AWS + IAM + GitHub |
| 1 | AWS infrastructure (Terraform) | ✅ Complete | VPC, subnets, SGs, EC2, NACL |
| 2 | Zeek + Traffic Mirroring | ✅ Complete | Mirror session active, structured logs |
| 3 | ML engine (Isolation Forest) | ✅ Complete | Trained model, live pipeline |
| 4 | Wazuh SIEM | ✅ Complete | Correlation rules, MITRE mapping |
| 5 | Llama-3.1-8B + ChromaDB/RAG | ✅ Complete | Ollama serving, function calling |
| 6 | n8n Orchestration | ✅ Complete | E2E Approve path AWS-verified |
| — | SOC Dashboard | ✅ Complete | FastAPI + React + SQLite + network-aware chat |
| 7 | 🎯 Demo 1 — Nmap (E2E) | ✅ **Recorded** | Full chain nmap → NACL block |
| 8 | 🎯 Demo 2 — SQL Injection | 🔲 Roadmap | ALB + TLS + DVWA + L7 parser |
| 9 | Egress Monitoring | 🔲 Roadmap | FFT beaconing detection |
| 10 | Security Hardening | 🔲 Roadmap | Prompt-injection, IAM scope-down, WAF migration |
| 11 | Red Team + KPI | 🔲 Roadmap | 10 scenarios, KPI table |
| 12 | Documentation & public release | 🔄 In progress | This document set |

Detailed technical implementation plans for Phase 8–11 are maintained in `docs/roadmap-phase-8-11.md`.

---

## 14. Tech Stack (As-Built)

| Layer | Tool | Role |
|-------|------|------|
| IaC | Terraform | All AWS resources (state imported) |
| Capture | Zeek 8.0.5 | Raw traffic → structured logs |
| ML Detection | Isolation Forest (scikit-learn) | Layer-1 anomaly detection |
| SIEM | Wazuh 4.14.5 | Correlation, MITRE mapping |
| AI Model | Llama-3.1-8B via **Ollama (CPU)** | Deep analysis, function calling |
| RAG | ChromaDB | Network knowledge injection |
| Orchestration | n8n 2.8 (self-hosted) | Workflow coordination |
| Enforcement | Flask API + boto3 → **NACL** | Human-approved IP blocking |
| Notifications | Slack + AWS SES | Approval + escalation |
| Dashboard | FastAPI + React + SQLite | Human-in-the-loop UI |

---

## 15. Success KPIs

| Metric | Target | Measurement | Status |
|--------|--------|-------------|--------|
| False Positive Rate | < 5% | admin rejects / total alerts | To be measured (Phase 11) |
| Detection Latency | < 30 s | suspicious traffic → Slack alert | To be measured (Phase 11) |
| LLM Response Time | < 10 s | mean Ollama round-trip | **~40–52 s on CPU — known limitation**, GPU path required |
| True Positive Rate | > 90% | admin approvals / total alerts | To be measured (Phase 11) |
| System Uptime | > 99.5% | CloudWatch availability | To be measured (Phase 11) |

---

## Architecture Decision Records

- **ADR-002** — AI is passive, never inline in the live traffic path
- **ADR-004** — Two subnets instead of six (cost/complexity vs. isolation trade-off)
- **ADR-009** — Escalation email via IAM-Role/boto3 primitive, not raw HTTP from n8n
- **ADR-010** — NACL explicit deny over Security-Group allow-rules for blocking
- **ADR-011** — Internal VPC CIDR unconditionally excluded from detection/enforcement
- **ADR-012** — Elastic IP on secops-management for stable Slack/webhook callbacks
