# Asset Inventory

## Trusted Internal IPs
- 10.0.1.90  — secops-ai        — AI Analysis Engine
- 10.0.1.207 — secops-detection — ML Engine + Wazuh Manager
- 10.0.1.249 — secops-zeek      — Zeek Capture + Wazuh Agent
- 10.0.1.93  — secops-target    — Intentionally vulnerable (DVWA)

## Trusted Ports
- 22   — SSH (management only)
- 4789 — VXLAN (Traffic Mirroring)
- 1514 — Wazuh Agent communication
- 1515 — Wazuh Agent registration
- 11434 — Ollama API (internal only)
- 8000  — ChromaDB (internal only)

## External IPs
- Any IP outside 10.0.0.0/16 is untrusted
- 54.66.61.93 — secops-target public IP (legitimate)
- 52.62.144.23 — secops-zeek public IP (legitimate)
- 3.27.208.101 — secops-detection public IP (legitimate)
- 3.106.127.54 — secops-ai public IP (legitimate)
