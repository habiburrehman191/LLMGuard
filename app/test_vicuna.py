import requests

url = "http://localhost:11434/api/chat"
payload = {
    "model": "vicuna",
    "messages": [
        {
            "role": "user",
            "content": "What is indirect prompt injection? Answer in 2 short lines."
        }
    ],
    "stream": False
}

response = requests.post(url, json=payload, timeout=120)
response.raise_for_status()

data = response.json()
print(data["message"]["content"])