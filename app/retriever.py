from pathlib import Path


DOCS_DIR = Path("docs")


def load_documents():
    documents = []

    for file_path in DOCS_DIR.glob("*.txt"):
        content = file_path.read_text(encoding="utf-8")
        documents.append({
            "filename": file_path.name,
            "content": content
        })

    return documents


def retrieve_document(query: str):
    documents = load_documents()
    lowered_query = query.lower()

    for doc in documents:
        if "obfuscated" in lowered_query and doc["filename"] == "obfuscated_policy.txt":
            return doc

    for doc in documents:
        if "poison" in lowered_query and doc["filename"] == "poisoned_policy.txt":
            return doc

    for doc in documents:
        if doc["filename"] == "policy.txt":
            return doc

    return documents[0] if documents else None