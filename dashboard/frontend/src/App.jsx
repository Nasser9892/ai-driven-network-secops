import { useState, useEffect } from "react";

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [prompt, setPrompt] = useState("");
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(false);

  const fetchAlerts = async () => {
    try {
      const r = await fetch("/api/alerts");
      setAlerts(await r.json());
    } catch (e) { console.error(e); }
  };

  useEffect(() => {
    fetchAlerts();
    const t = setInterval(fetchAlerts, 10000);
    return () => clearInterval(t);
  }, []);

  const sendChat = async () => {
    if (!prompt.trim()) return;
    const userMsg = prompt;
    setMessages(m => [...m, { role: "user", text: userMsg }]);
    setPrompt("");
    setLoading(true);
    try {
      const r = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ prompt: userMsg })
      });
      const d = await r.json();
      setMessages(m => [...m, { role: "assistant", text: d.response }]);
    } catch (e) {
      setMessages(m => [...m, { role: "assistant", text: "Error: " + e.message }]);
    }
    setLoading(false);
  };

  return (
    <div style={{ fontFamily: "system-ui", background: "#0d1117", color: "#c9d1d9", minHeight: "100vh", padding: 20 }}>
      <h1 style={{ color: "#58a6ff" }}>SecOps SOC Dashboard</h1>
      <div style={{ display: "flex", gap: 20 }}>
        <div style={{ flex: 1, background: "#161b22", padding: 16, borderRadius: 8 }}>
          <h2>Live Alerts</h2>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
            <thead>
              <tr style={{ borderBottom: "1px solid #30363d", textAlign: "left" }}>
                <th>Time</th><th>Src IP</th><th>Score</th><th>MITRE</th><th>Risk</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length === 0 && <tr><td colSpan="5" style={{ padding: 10, color: "#8b949e" }}>No alerts</td></tr>}
              {alerts.map(a => (
                <tr key={a.id} style={{ borderBottom: "1px solid #21262d" }}>
                  <td>{a.timestamp?.slice(11, 19)}</td>
                  <td>{a.src_ip}</td>
                  <td>{a.anomaly_score}</td>
                  <td>{a.mitre_technique}</td>
                  <td style={{ color: a.risk_level === "CRITICAL" ? "#f85149" : "#d29922" }}>{a.risk_level}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div style={{ flex: 1, background: "#161b22", padding: 16, borderRadius: 8, display: "flex", flexDirection: "column", height: "70vh" }}>
          <h2>Ask Llama</h2>
          <div style={{ flex: 1, overflowY: "auto", marginBottom: 10 }}>
            {messages.map((m, i) => (
              <div key={i} style={{ margin: "8px 0", textAlign: m.role === "user" ? "right" : "left" }}>
                <span style={{ background: m.role === "user" ? "#238636" : "#30363d", padding: "6px 12px", borderRadius: 8, display: "inline-block", maxWidth: "80%" }}>
                  {m.text}
                </span>
              </div>
            ))}
            {loading && <div style={{ color: "#8b949e" }}>Llama is thinking...</div>}
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <input
              value={prompt}
              onChange={e => setPrompt(e.target.value)}
              onKeyDown={e => e.key === "Enter" && sendChat()}
              placeholder="Ask about an alert..."
              style={{ flex: 1, padding: 8, background: "#0d1117", border: "1px solid #30363d", borderRadius: 6, color: "#c9d1d9" }}
            />
            <button onClick={sendChat} style={{ padding: "8px 16px", background: "#238636", color: "#fff", border: "none", borderRadius: 6, cursor: "pointer" }}>Send</button>
          </div>
        </div>
      </div>
    </div>
  );
}
