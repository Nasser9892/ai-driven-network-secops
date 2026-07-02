from flask import Flask, request, jsonify
import subprocess
import json
import os
from datetime import datetime
import boto3
import firewall_actions

VERIFIED_EMAIL = 'naser.ronaghi@outlook.com'
SES_REGION = 'ap-southeast-2'

app = Flask(__name__)
AUDIT_LOG = os.path.expanduser('~/secops/logs/audit.json')
FLAG_FILE = os.path.expanduser('~/secops/logs/admin_responses.json')

@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})

@app.route('/block', methods=['POST'])
def block_ip():
    data = request.json
    src_ip = data.get('src_ip')
    duration = data.get('block_duration_hours', 2)
    reason = data.get('reason', 'Security Alert')
    if not src_ip:
        return jsonify({'success': False, 'error': 'src_ip required'}), 400
    try:
        result = firewall_actions.block_ip(
            ip=src_ip,
            reason=reason,
            mitre=data.get('mitre', 'unknown'),
        )
        # success reflects independent AWS verification, never a return code
        success = bool(result.get('verified'))
        audit_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'block_ip',
            'src_ip': src_ip,
            'block_duration_hours': duration,
            'risk_level': data.get('risk_level', 'unknown'),
            'threat_type': data.get('threat_type', 'unknown'),
            'mitre': data.get('mitre', 'unknown'),
            'anomaly_score': data.get('anomaly_score', 0),
            'triggered_by': data.get('triggered_by', 'unknown'),
            'reason': reason,
            'rule_number': result.get('rule_number'),
            'enforcement_status': result.get('status'),
            'success': success
        }
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        with open(AUDIT_LOG, 'a') as f:
            f.write(json.dumps(audit_entry) + '\n')
        return jsonify({'success': success, 'result': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/flag', methods=['POST'])
def set_flag():
    data = request.json
    alert_id = data.get('alert_id')
    if not alert_id:
        return jsonify({'success': False, 'error': 'alert_id required'}), 400
    try:
        responses = {}
        if os.path.exists(FLAG_FILE):
            with open(FLAG_FILE, 'r') as f:
                responses = json.load(f)
        responses[alert_id] = {
            'action': data.get('action'),
            'src_ip': data.get('src_ip'),
            'block_duration_hours': data.get('block_duration_hours', 2),
            'risk_level': data.get('risk_level', 'HIGH'),
            'threat_type': data.get('threat_type', 'Unknown'),
            'mitre': data.get('mitre', 'Unknown'),
            'timestamp': datetime.utcnow().isoformat()
        }
        with open(FLAG_FILE, 'w') as f:
            json.dump(responses, f)
        return jsonify({'success': True, 'alert_id': alert_id})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/flag/<alert_id>', methods=['GET'])
def get_flag(alert_id):
    try:
        if not os.path.exists(FLAG_FILE):
            return jsonify({'found': False})
        with open(FLAG_FILE, 'r') as f:
            responses = json.load(f)
        if alert_id in responses:
            return jsonify({'found': True, 'data': responses[alert_id]})
        return jsonify({'found': False})
    except Exception as e:
        return jsonify({'found': False, 'error': str(e)}), 500

@app.route('/escalate', methods=['POST'])
def escalate():
    data = request.json or {}
    src_ip = data.get('src_ip', 'unknown')
    subject = data.get('subject', f'SecOps Escalation: {src_ip}')
    body = data.get('body', 'Automated escalation from SecOps platform.')
    try:
        client = boto3.client('ses', region_name=SES_REGION)
        resp = client.send_email(
            Source=VERIFIED_EMAIL,
            Destination={'ToAddresses': [VERIFIED_EMAIL]},
            Message={
                'Subject': {'Data': subject},
                'Body': {'Text': {'Data': body}},
            },
        )
        audit_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'action': 'escalate_email',
            'src_ip': src_ip,
            'risk_level': data.get('risk_level', 'unknown'),
            'threat_type': data.get('threat_type', 'unknown'),
            'mitre': data.get('mitre', 'unknown'),
            'triggered_by': data.get('triggered_by', 'auto_escalation'),
            'message_id': resp.get('MessageId'),
            'success': True,
        }
        os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)
        with open(AUDIT_LOG, 'a') as f:
            f.write(json.dumps(audit_entry) + '\n')
        return jsonify({'success': True, 'message_id': resp.get('MessageId')})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5680, debug=False)
