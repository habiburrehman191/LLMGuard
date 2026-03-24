from app.retriever import load_documents

docs = load_documents()

for doc in docs:
    print("FILE:", doc["filename"])
    print("CONTENT:", doc["content"])
    print("-" * 50)