import json
import ollama
import chromadb
from sanitizer import sanitize_log
from firewall_actions import block_ip, escalate_to_human

# Load system prompt
with open("/home/ubuntu/secops-ai/agent/system_prompt.txt", "r") as f:
    system_prompt = f.read()

# Connect to ChromaDB
chroma_client = chromadb.PersistentClient(path="/home/ubuntu/secops-ai/rag/chromadb")
collection = chroma_client.get_collection(name="network_knowledge")

def get_context(query: str) -> str:
    results = collection.query(query_texts=[query], n_results=2)
    return "\n\n".join(results["documents"][0])

def run_pipeline(raw_log: str) -> dict:
    # Step 1: Sanitize
    clean_log = sanitize_log(raw_log)
    
    # Step 2: Get RAG context
    context = get_context(raw_log)
    
    # Step 3: Analyze with Llama
    user_message = f"NETWORK CONTEXT:\n{context}\n\nAnalyze this log:\n{clean_log}"
    
    response = ollama.chat(
        model="llama3.1:8b",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ]
    )
    
    raw = response.message.content.strip()
    if "```json" in raw:
        raw = raw.split("```json")[1].split("```")[0].strip()
    elif "```" in raw:
        raw = raw.split("```")[1].split("```")[0].strip()
    
    result = json.loads(raw)
    
    # Step 4: Take action
    action = result.get("recommended_action", "monitor")
    severity = result.get("severity", "low")
    
    if action == "block_ip" and severity in ["high", "critical"]:
        print(f"[ACTION] Blocking IP: {result['src_ip']}")
        # In production: requires human approval via n8n
        # block_ip(result["src_ip"], result["threat_type"], result["mitre_technique"])
        print("[INFO] Block requires human approval via n8n (Phase 6)")
    elif action == "escalate_to_human":
        escalate_to_human(result)
    else:
        print(f"[ACTION] Monitoring: {result['src_ip']}")
    
    return result

if __name__ == "__main__":
    test_log = """
    src_ip=185.220.101.5
    unique_dst_ports=1000
    failed_conn_rate=0.98
    conn_per_second=150
    packet_to_byte_ratio=999
    conn_state=REJ
    duration=0.001
    """
    
    print("Running full pipeline...")
    result = run_pipeline(test_log)
    print("\nFinal Result:")
    print(json.dumps(result, indent=2))
