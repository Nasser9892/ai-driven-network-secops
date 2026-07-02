"""
firewall_actions.py
Enforcement primitive using Network ACL explicit deny.
Security Groups are allow-only; a real block requires a NACL deny entry.
Importable module — no subprocess, no shell.
"""

import sys
import json
import ipaddress
from datetime import datetime

import boto3

NACL_ID = "acl-02cccdb666cab9d47"
REGION = "ap-southeast-2"
RULE_MIN = 1       # deny slots must sit below the default allow-all at 100
RULE_MAX = 99

ec2 = boto3.client("ec2", region_name=REGION)


def _validate_ip(ip: str) -> str:
    """Validate IPv4. Raises ValueError on bad input — closes injection/malformed vectors."""
    return str(ipaddress.IPv4Address(ip))


def _inbound_entries():
    resp = ec2.describe_network_acls(NetworkAclIds=[NACL_ID])
    return [e for e in resp["NetworkAcls"][0]["Entries"] if not e["Egress"]]


def _find_rule_number_for_ip(cidr: str):
    """Return the rule number of an existing inbound deny for this CIDR, or None."""
    for e in _inbound_entries():
        if e.get("CidrBlock") == cidr and e.get("RuleAction") == "deny":
            return e["RuleNumber"]
    return None


def _next_free_rule_number():
    """First free slot in [1,99]. Raises if the block space is exhausted."""
    used = {e["RuleNumber"] for e in _inbound_entries()}
    for n in range(RULE_MIN, RULE_MAX + 1):
        if n not in used:
            return n
    raise RuntimeError("NACL deny space exhausted (1-99) — migrate to WAF")


def is_ip_blocked(ip: str) -> bool:
    """Independently verify a deny entry exists in the NACL. Source of truth is AWS."""
    ip = _validate_ip(ip)
    return _find_rule_number_for_ip(f"{ip}/32") is not None


def block_ip(ip: str, reason: str = "Security Alert", mitre: str = "unknown") -> dict:
    try:
        ip = _validate_ip(ip)
    except ValueError as e:
        return {"status": "invalid_input", "ip": ip, "verified": False, "error": str(e)}

    if ipaddress.ip_address(ip) in ipaddress.ip_network("10.0.0.0/16"):
        return {"status": "rejected_internal_ip", "ip": ip, "verified": False, "error": "internal VPC address"}

    cidr = f"{ip}/32"

    # Idempotency: if already denied, report it without touching state.
    if _find_rule_number_for_ip(cidr) is not None:
        return {"status": "already_blocked", "ip": ip, "verified": True}

    try:
        rule_number = _next_free_rule_number()
        ec2.create_network_acl_entry(
            NetworkAclId=NACL_ID,
            RuleNumber=rule_number,
            Protocol="-1",
            RuleAction="deny",
            Egress=False,
            CidrBlock=cidr,
        )
    except Exception as e:
        return {"status": "error", "ip": ip, "verified": False, "error": str(e)}

    verified = is_ip_blocked(ip)
    return {
        "status": "blocked",
        "ip": ip,
        "rule_number": rule_number,
        "reason": reason,
        "mitre": mitre,
        "verified": verified,
    }


def unblock_ip(ip: str) -> dict:
    """Remove the deny entry for this IP, then verify removal in AWS."""
    try:
        ip = _validate_ip(ip)
    except ValueError as e:
        return {"status": "invalid_input", "ip": ip, "verified": False, "error": str(e)}

    cidr = f"{ip}/32"
    rule_number = _find_rule_number_for_ip(cidr)
    if rule_number is None:
        return {"status": "not_blocked", "ip": ip, "verified": True}

    try:
        ec2.delete_network_acl_entry(NetworkAclId=NACL_ID, RuleNumber=rule_number, Egress=False)
    except Exception as e:
        return {"status": "error", "ip": ip, "verified": False, "error": str(e)}

    still_blocked = is_ip_blocked(ip)
    return {"status": "unblocked", "ip": ip, "verified": not still_blocked}


if __name__ == "__main__":
    # Usage: firewall_actions.py <block|unblock> <ip> [reason] [mitre]
    if len(sys.argv) < 3 or sys.argv[1] not in ("block", "unblock"):
        print(json.dumps({"status": "usage_error",
                          "usage": "firewall_actions.py <block|unblock> <ip> [reason] [mitre]"}))
        sys.exit(2)

    action, ip_arg = sys.argv[1], sys.argv[2]
    if action == "block":
        reason_arg = sys.argv[3] if len(sys.argv) > 3 else "Manual block"
        mitre_arg = sys.argv[4] if len(sys.argv) > 4 else "unknown"
        result = block_ip(ip_arg, reason_arg, mitre_arg)
    else:
        result = unblock_ip(ip_arg)

    print(json.dumps(result, indent=2))
    sys.exit(0 if result.get("verified") else 1)
