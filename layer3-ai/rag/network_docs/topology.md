# Network Topology

## VPC
- CIDR: 10.0.0.0/16
- Region: ap-southeast-2 (Sydney)
- Public Subnet: 10.0.1.0/24

## Instances
- 10.0.1.93  — secops-target    — t3.micro  — attack target (DVWA)
- 10.0.1.249 — secops-zeek      — t3.large  — Zeek + Wazuh Agent
- 10.0.1.207 — secops-detection — t3.large  — ML Engine + Wazuh Manager
- 10.0.1.90  — secops-ai        — t3.xlarge — Ollama + ChromaDB

## Traffic Flow
- All external traffic → secops-target
- Traffic mirrored → secops-zeek (Zeek analysis)
- Zeek logs → secops-detection (ML + Wazuh)
- Alerts → secops-ai (Llama analysis)
