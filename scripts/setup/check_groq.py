import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

api_key = os.getenv("GROQ_API_KEY")

if not api_key:
    raise RuntimeError("GROQ_API_KEY was not found in .env")

client = OpenAI(
    api_key=api_key,
    base_url="https://api.groq.com/openai/v1",
)

models = client.models.list()

print("Groq connection successful.")
print("\nAvailable models:")

for model in models.data:
    print(f"- {model.id}")