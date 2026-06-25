import boto3
import json
from datetime import datetime

TARGET_SG_ID = "sg-079c3c5a0e813b8c6"
REGION = "ap-southeast-2"

ec2 = boto3.client("ec2", region_name=REGION)

def block_ip(ip: str, reason: str, mitre_technique: str) -> dict:
    try:
        timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        ec2.authorize_security_group_ingress(
            GroupId=TARGET_SG_ID,
            IpPermissions=[{
                "IpProtocol": "-1",
                "IpRanges": [{
                    "CidrIp": f"{ip}/32",
                    "Description": f"Blocked {mitre_technique} {timestamp}"
                }]
            }]
        )
        print(f"BLOCKED: {ip} — {reason}")
        return {"status": "blocked", "ip": ip, "reason": reason}
    except Exception as e:
        if "InvalidPermission.Duplicate" in str(e):
            return {"status": "already_blocked", "ip": ip}
        return {"status": "error", "ip": ip, "error": str(e)}

def escalate_to_human(alert: dict) -> dict:
    print(f"ESCALATED: {json.dumps(alert, indent=2)}")
    return {"status": "escalated", "alert": alert}

if __name__ == "__main__":
    result = block_ip(
        ip="1.2.3.4",
        reason="Port Scan Test",
        mitre_technique="T1046"
    )
    print(json.dumps(result, indent=2))
