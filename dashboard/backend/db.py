import sqlite3

def init_db():
    conn = sqlite3.connect("data.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            anomaly_score REAL,
            mitre_technique TEXT,
            risk_level TEXT,
            evidence TEXT,
            status TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS chat_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            prompt TEXT,
            response TEXT
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            action TEXT,
            src_ip TEXT,
            triggered_by TEXT,
            success INTEGER
        )
    """)
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("DB initialized")
