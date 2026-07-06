# Results & KPIs

**Scope of this document.** It separates what is **measured** (Phases 0–7, delivered) from what is **pending measurement** (Phases 8–11). No KPI is claimed until measured under the Phase 11 red-team protocol. Placeholders below are explicit, not padding.

---

## 1. Delivered & verified (Phases 0–7)

| Item | Result | Verification method |
|------|--------|---------------------|
| VPC Traffic Mirroring → Zeek | Capturing mirrored traffic (VXLAN UDP 4789) | Attacker REJ/RST lines present in `conn.log` |
| Isolation Forest scoring | Live, 5 s poll, 10 s window per src IP | Nmap scan → score `< -0.15` (CRITICAL) |
| Wazuh correlation | Port Scan → MITRE T1046 | Alert in Wazuh dashboard |
| Llama-3.1-8B triage | Structured output, function-call decision | Direct `curl` to Ollama, ~2.2 s node latency (warm) |
| n8n E2E Approve path | Full chain nmap → NACL block | **Independent AWS query** — see §2 |
| NACL enforcement + verify | Block created and confirmed | `describe-network-acls` shows deny entry |
| Internal-IP guard | Self-block prevented | `firewall_actions` rejects `10.0.1.157` as `rejected_internal_ip` |
| Phase 7 Nmap demo | Recorded end-to-end | Video (hosting pending) |

### 1.1 Enforcement — independently verified block
```bash
aws ec2 describe-network-acls --network-acl-ids acl-02cccdb666cab9d47 \
  --region ap-southeast-2 \
  --query "NetworkAcls[0].Entries[?RuleAction=='deny']"
# → 203.0.113.50/32 · RuleNumber 1 · Egress false · RuleAction deny
```
Success is defined as the exact IP appearing as a deny entry on a direct AWS query — **not** a green n8n node and **not** a `success:true` in the audit log.

---

## 2. Measured performance (Phases 0–7, indicative)

| Metric | Measured | Notes |
|--------|----------|-------|
| Llama round-trip (warm) | ~2.2 s | Direct `curl`, single alert, short prompt |
| Llama round-trip (Dashboard chat, with context) | ~40 s | System prompt + last-N alerts injected, CPU |
| Llama cold-start | ~9 s | Loading ~5 GB model into RAM (t3.xlarge) |
| Dashboard `/chat` full response | ~40–52 s | Requires `proxy_read_timeout 300s` on nginx |
| Detection poll interval | 5 s | `live_detection.py` |
| Alert cooldown | 300 s | In-memory (see known issue §4) |

These are indicative, not KPI-grade — measured ad hoc during builds, not under the controlled Phase 11 protocol.

---

## 3. KPI table — pending Phase 11

| KPI | Target | Status | Method (defined) |
|-----|--------|--------|------------------|
| False Positive Rate | < 5% | ⏳ Pending | admin rejects ÷ total alerts, over 10-scenario run + baseline |
| Detection Latency | < 30 s | ⏳ Pending | ts(suspicious traffic) → ts(Slack alert) |
| True Positive Rate | > 90% | ⏳ Pending | admin approvals ÷ total attack alerts |
| LLM Response Time | < 10 s | ⚠️ **Expected miss on CPU** | mean Ollama round-trip; ~40–52 s measured — GPU (vLLM) path required |
| System Uptime | > 99.5% | ⏳ Pending | CloudWatch availability over test window |

Full protocol and 10-scenario matrix: [`docs/roadmap-phase-8-11.md`](../docs/roadmap-phase-8-11.md) §Phase 11.

---

## 4. Known issues affecting measurement

- **`live_detection.py` is stateless** — re-reads full `conn.log` per poll; in-memory cooldown/dedup reset on restart → duplicate alerts. **Must be fixed before Phase 11**, or FPR is inflated by artifacts. Fix: byte-offset tracking + persistent on-disk cooldown.
- **`unique_dst_ports > 15` threshold** — single-connection internet noise (e.g. `total_conns=1`) currently produces false-positive HIGH alerts that auto-escalate. Needs review before FPR measurement.
- **Default-rate nmap** gets sliced across windows into weak partial alerts; high-rate (`-T4 --min-rate 500`) gives one clean alert. Detection-latency measurement must fix scan rate to be comparable.
- **LLM latency** is the one KPI known in advance to miss target on CPU — reported as-measured, GPU noted as remediation.

---

## 5. Evidence layout

```
evidence/
├── results.md          # this file
├── screenshots/        # AWS console, Slack, dashboard, Wazuh (per task)
├── logs/               # raw command output (conn.log excerpts, AWS queries, audit records)
└── demo-video/         # Phase 7 recording (or link)
```

**Rule:** a task is "done" only when its evidence (screenshot + text log) is captured here.

---

## 6. Honest status line for external use

> Phases 0–7 are built and verified end-to-end (Nmap attack → NACL block, confirmed by direct AWS query). Phases 8–11 have complete implementation plans and are on the roadmap. KPIs are defined and will be measured under a 10-scenario red-team protocol in Phase 11; the LLM-latency KPI is expected to require a GPU serving path and is documented as such.
