import ollama
import json
import chromadb

# Load system prompt
with open("/home/ubuntu/secops-ai/agent/system_prompt.txt", "r") as f:
    system_prompt = f.read()

# Connect to ChromaDB
chroma_client = chromadb.PersistentClient(path="/home/ubuntu/secops-ai/rag/chromadb")
collection = chroma_client.get_collection(name="network_knowledge")

def get_context(query: str) -> str:
    results = collection.query(query_texts=[query], n_results=2)
    docs = results["documents"][0]
    return "\n\n".join(docs)

def analyze_log(log_data: str) -> dict:
    # Get relevant context from ChromaDB
    context = get_context(log_data)
    
    # Build prompt with context
    user_message = f"""NETWORK CONTEXT:
{context}

Analyze this log:
{log_data}"""

    response = ollama.chat(
        model="llama3.1:8b",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ]
    )
    
    raw = response.message.content.strip()
    
    # Clean markdown if present
    if "```json" in raw:
        raw = raw.split("```json")[1].split("```")[0].strip()
    elif "```" in raw:
        raw = raw.split("```")[1].split("```")[0].strip()
    
    return json.loads(raw)

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
    
    print("Analyzing log with RAG context...")
    result = analyze_log(test_log)
    print(json.dumps(result, indent=2))
