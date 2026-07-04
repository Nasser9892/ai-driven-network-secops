from fastapi import FastAPI
from pydantic import BaseModel
import httpx, sqlite3
from datetime import datetime

app = FastAPI()
OLLAMA_URL = "http://10.0.1.90:11434/api/generate"
DB = "data.db"

SYSTEM_PROMPT = """You are the SOC assistant for an AI-driven network security platform on AWS (ap-southeast-2).

Network topology (VPC 10.0.0.0/16, public subnet 10.0.1.0/24):
- secops-target     10.0.1.157  t3.micro   workload / attack target
- secops-zeek       10.0.1.249  t3.large   Zeek capture via VPC Traffic Mirroring
- secops-detection  10.0.1.207  t3.large   Isolation Forest ML engine + Wazuh SIEM
- secops-management 10.0.1.90   t3.xlarge  Ollama LLM + n8n orchestration + enforcement API
- secops-dashboard  10.0.1.36   t3.medium  SOC dashboard (this UI)

Detection: Zeek conn.log -> ML anomaly scoring (score < -0.05 = anomaly, < -0.15 = critical) -> Wazuh correlation -> n8n -> Llama analysis -> Slack human approval -> NACL deny block.
Internal 10.0.0.0/16 IPs are excluded from detection and blocking by design.

Answer as a senior SOC analyst: short, precise, factual. Use the recent alerts below when asked about network status or threats. If the alerts do not contain the answer, say so — never invent data."""

class ChatRequest(BaseModel):
    prompt: str

class AlertIn(BaseModel):
    timestamp: str = ""
    src_ip: str
    anomaly_score: float = 0.0
    mitre_technique: str = ""
    risk_level: str = ""
    evidence: str = ""

def recent_alerts_context(n=10):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT timestamp, src_ip, anomaly_score, mitre_technique, risk_level, evidence "
        "FROM alerts ORDER BY id DESC LIMIT ?", (n,)
    ).fetchall()
    conn.close()
    if not rows:
        return "No alerts in the database."
    lines = [
        f"- [{r['timestamp']}] src={r['src_ip']} score={r['anomaly_score']} "
        f"mitre={r['mitre_technique']} risk={r['risk_level']} evidence={r['evidence']}"
        for r in rows
    ]
    return "Recent alerts (newest first):\n" + "\n".join(lines)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/chat")
async def chat(req: ChatRequest):
    full_prompt = f"{SYSTEM_PROMPT}\n\n{recent_alerts_context()}\n\nAnalyst question: {req.prompt}"
    async with httpx.AsyncClient(timeout=300.0) as client:
        r = await client.post(OLLAMA_URL, json={
            "model": "llama3.1:8b", "prompt": full_prompt, "stream": False, "options": {"num_predict": 300}
        })
        result = r.json().get("response", "")
    conn = sqlite3.connect(DB)
    conn.execute(
        "INSERT INTO chat_history (timestamp, prompt, response) VALUES (?, ?, ?)",
        (datetime.utcnow().isoformat(), req.prompt, result)
    )
    conn.commit()
    conn.close()
    return {"response": result}

@app.get("/alerts")
def get_alerts():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 50").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.post("/ingest-alert")
def ingest_alert(a: AlertIn):
    conn = sqlite3.connect(DB)
    conn.execute(
        "INSERT INTO alerts (timestamp, src_ip, anomaly_score, mitre_technique, risk_level, evidence, status) VALUES (?,?,?,?,?,?,?)",
        (a.timestamp or datetime.utcnow().isoformat(), a.src_ip, a.anomaly_score, a.mitre_technique, a.risk_level, a.evidence, "new")
    )
    conn.commit()
    conn.close()
    return {"success": True}
