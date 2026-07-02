from fastapi import FastAPI
from pydantic import BaseModel
import httpx, sqlite3
from datetime import datetime

app = FastAPI()
OLLAMA_URL = "http://10.0.1.90:11434/api/generate"
DB = "data.db"

class ChatRequest(BaseModel):
    prompt: str

class AlertIn(BaseModel):
    timestamp: str = ""
    src_ip: str
    anomaly_score: float = 0.0
    mitre_technique: str = ""
    risk_level: str = ""
    evidence: str = ""

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/chat")
async def chat(req: ChatRequest):
    async with httpx.AsyncClient(timeout=120.0) as client:
        r = await client.post(OLLAMA_URL, json={
            "model": "llama3.1:8b", "prompt": req.prompt, "stream": False
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
