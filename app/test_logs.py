import sqlite3

conn = sqlite3.connect("logs/llmguard.db")
cursor = conn.cursor()

cursor.execute("""
    SELECT id, prompt, retrieved_document, action, blocked, reason, risk_score, created_at
    FROM logs
    ORDER BY id DESC
""")

rows = cursor.fetchall()

for row in rows:
    print(row)

conn.close()