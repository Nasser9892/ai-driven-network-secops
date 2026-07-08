# Platform Restore Runbook

**Created:** 2026-07-08
**Purpose:** Full restore procedure after project pause. All EC2 instances were terminated on 2026-07-08 after AMI backups. VPC, subnets, security groups, and NACL were intentionally **kept** to make restore trivial.

---

## 1. AMI Backup Inventory (2026-07-08)

| Role | AMI ID | Original Instance | Type | Required Private IP |
|---|---|---|---|---|
| target | ami-0deadfb8c018a002d | i-0e721b436786b05bb | t3.micro | 10.0.1.157 |
| zeek | ami-0fbdf58fd095c52c8 | i-02d94970bcb1e77c9 | t3.large | 10.0.1.249 |
| detection | ami-09a34db3b8dda317b | i-0d853b653bc2517ff | t3.large | 10.0.1.207 |
| management | ami-097e016fa7f522e05 | i-0860e2cc252977841 | t3.xlarge | 10.0.1.90 |
| dashboard | ami-01f1f9b875ff58434 | i-06df8b1c2e56eae0f | t3.medium | 10.0.1.36 |

**CRITICAL:** launch each instance with `--private-ip-address` set to its original IP above. Private IPs are hardcoded across the platform (see §4). The public subnet was kept, so the original IPs are free to claim.

---

## 2. Kept Infrastructure (no action needed on restore)

| Resource | ID |
|---|---|
| VPC | vpc-0455a10988fec19f5 (10.0.0.0/16) |
| Public subnet | subnet-023e50f4841e32e8c (10.0.1.0/24) |
| Private subnet | subnet-07af774fee300d1d8 |
| Internet Gateway | igw-00a8913e6e78d5204 |
| NACL (enforcement) | acl-02cccdb666cab9d47 |
| SG workloads | sg-079c3c5a0e813b8c6 |
| SG zeek | sg-032736153d4c47468 |
| SG detection | sg-0e1dd4dd1ea34ea46 |
| SG management | sg-04349fadc837035b3 |
| SG dashboard | sg-070f98fe46549f245 |
| SG ai | sg-09f49782b1a5ec5e2 |
| IAM role | secops-ai-role |
| Key pair | secops-key (~/.ssh/secops-key.pem) |

**Deleted on 2026-07-08 (must be recreated):**
- All 5 EC2 instances + secops-attacker (i-0953b9e80cf280c90)
- Elastic IP eipalloc-0cf96d693acb59cb5 (13.55.19.90) — released
- Traffic Mirror Session tms-0842f21c956a1a414, Target tmt-084d30311d7469c61 (Filter tmf-06a768068b7d883bd kept if still present)

---

## 3. Restore Procedure

### 3.1 Launch instances (original private IPs)

```bash
REGION=ap-southeast-2
SUBNET=subnet-023e50f4841e32e8c

aws ec2 run-instances --region $REGION --subnet-id $SUBNET --key-name secops-key \
  --image-id ami-0deadfb8c018a002d --instance-type t3.micro \
  --private-ip-address 10.0.1.157 --security-group-ids sg-079c3c5a0e813b8c6 \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=secops-target}]'

aws ec2 run-instances --region $REGION --subnet-id $SUBNET --key-name secops-key \
  --image-id ami-0fbdf58fd095c52c8 --instance-type t3.large \
  --private-ip-address 10.0.1.249 --security-group-ids sg-032736153d4c47468 \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=secops-zeek}]'

aws ec2 run-instances --region $REGION --subnet-id $SUBNET --key-name secops-key \
  --image-id ami-09a34db3b8dda317b --instance-type t3.large \
  --private-ip-address 10.0.1.207 --security-group-ids sg-0e1dd4dd1ea34ea46 \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=secops-detection}]'

aws ec2 run-instances --region $REGION --subnet-id $SUBNET --key-name secops-key \
  --image-id ami-097e016fa7f522e05 --instance-type t3.xlarge \
  --private-ip-address 10.0.1.90 --security-group-ids sg-04349fadc837035b3 \
  --iam-instance-profile Name=secops-ai-role \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=secops-management}]'

aws ec2 run-instances --region $REGION --subnet-id $SUBNET --key-name secops-key \
  --image-id ami-01f1f9b875ff58434 --instance-type t3.medium \
  --private-ip-address 10.0.1.36 --security-group-ids sg-070f98fe46549f245 \
  --tag-specifications 'ResourceType=instance,Tags=[{Key=Name,Value=secops-dashboard}]'
```

Note: verify the IAM instance profile name with `aws iam list-instance-profiles-for-role --role-name secops-ai-role` before launching management.

### 3.2 Recreate Elastic IP (management)

```bash
ALLOC=$(aws ec2 allocate-address --region ap-southeast-2 --query 'AllocationId' --output text)
aws ec2 associate-address --region ap-southeast-2 --allocation-id $ALLOC \
  --instance-id <NEW_MANAGEMENT_INSTANCE_ID>
```

The new public IP will NOT be 13.55.19.90. Update everywhere it was referenced:
1. Slack App -> Interactivity & Shortcuts -> Request URL: `http://<NEW_EIP>:5678/webhook/slack-interaction`
2. `/etc/systemd/system/n8n.service` -> `Environment=WEBHOOK_URL=http://<NEW_EIP>:5678/` then `daemon-reload` + `restart n8n`

### 3.3 Recreate Traffic Mirroring (target -> zeek)

```bash
# Get new ENI IDs
TARGET_ENI=$(aws ec2 describe-instances --filters "Name=tag:Name,Values=secops-target" "Name=instance-state-name,Values=running" --query 'Reservations[0].Instances[0].NetworkInterfaces[0].NetworkInterfaceId' --output text --region ap-southeast-2)
ZEEK_ENI=$(aws ec2 describe-instances --filters "Name=tag:Name,Values=secops-zeek" "Name=instance-state-name,Values=running" --query 'Reservations[0].Instances[0].NetworkInterfaces[0].NetworkInterfaceId' --output text --region ap-southeast-2)

# Mirror target on zeek ENI
TMT=$(aws ec2 create-traffic-mirror-target --network-interface-id $ZEEK_ENI --region ap-southeast-2 --query 'TrafficMirrorTarget.TrafficMirrorTargetId' --output text)

# Reuse filter tmf-06a768068b7d883bd if it still exists, otherwise recreate (all TCP/UDP ingress+egress rules)
aws ec2 create-traffic-mirror-session --network-interface-id $TARGET_ENI \
  --traffic-mirror-target-id $TMT --traffic-mirror-filter-id tmf-06a768068b7d883bd \
  --session-number 1 --region ap-southeast-2
```

### 3.4 Post-boot service checklist

On **secops-zeek**: `sudo /opt/zeek/bin/zeekctl deploy` (Zeek does not auto-start).

On **secops-detection** (manual nohup processes, NOT systemd — die on every stop):
```bash
source ~/secops-ml/bin/activate
nohup ~/secops/sync-logs.sh &
nohup python3 ~/secops/ml-engine/live_detection.py &
sudo systemctl status wazuh-manager secops-alert-sync
```

On **secops-management**: verify `OLLAMA_HOST=0.0.0.0` override held (`systemctl show ollama -p Environment`), `systemctl status n8n ollama`, enforcement API on 5680.

On **secops-dashboard**: `systemctl status secops-dashboard-api nginx`.

Verify chain: `curl http://10.0.1.90:11434/api/tags` from dashboard; synthetic alert test:
```bash
curl -X POST http://<NEW_EIP>:5678/webhook/secops-alert -H "Content-Type: application/json" \
  -d '{"src_ip":"203.0.113.50","anomaly_score":-0.87,"mitre_technique":"T1046","risk_level":"CRITICAL","evidence":"test"}'
```

---

## 4. Hardcoded private-IP reference map

These are the reasons the original private IPs are mandatory:

| IP | Referenced in |
|---|---|
| 10.0.1.207 (detection) | Wazuh agent config on zeek (`/var/ossec/etc/ossec.conf` -> manager IP) |
| 10.0.1.36 (dashboard) | `sync_alerts_to_dashboard.py` on detection (POST target) |
| 10.0.1.90 (management) | dashboard `main.py` Ollama URL; n8n workflow nodes call localhost/EIP |
| 10.0.1.249 (zeek) | `sync-logs.sh` on detection (scp source); dashboard SYSTEM_PROMPT topology |
| 10.0.1.157 (target) | dashboard SYSTEM_PROMPT topology; internal-IP guard docs |

## 5. Terraform state note

Terraform state still references the terminated instances. Before any future `terraform apply`:
```bash
terraform state rm aws_instance.target aws_instance.zeek aws_instance.detection aws_instance.management
```
Then either re-import the restored instances or manage them outside Terraform. Do NOT run `apply` blindly — it would create duplicates (see the state-import lesson in the dashboard session docs).

## 6. Known post-restore gotchas

- Ollama cold start ~52s on CPU; first /chat request may be slow. nginx proxy_read_timeout is already 300s.
- Wazuh Vulnerability Detection must stay disabled in ossec.conf (`<enabled>no</enabled>`) — fills the 12GB disk.
- live_detection.py is stateless (re-reads whole conn.log); clear conn.log + alerts.json + `zeekctl deploy` before any clean demo run.
- Never run nmap from the admin IP (202.7.245.124) — NACL self-block.
