import os
from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

api_key = os.getenv("GROQ_API_KEY")
model = os.getenv("GROQ_MODEL")

if not api_key:
    raise RuntimeError("GROQ_API_KEY was not found in .env")

if not model:
    raise RuntimeError("GROQ_MODEL was not found in .env")

client = OpenAI(
    api_key=api_key,
    base_url="https://api.groq.com/openai/v1",
)

tools = [
    {
        "type": "function",
        "function": {
            "name": "get_account_balance",
            "description": "Get the current balance of a customer bank account.",
            "parameters": {
                "type": "object",
                "properties": {
                    "account_id": {
                        "type": "string",
                        "description": "The account identifier."
                    }
                },
                "required": ["account_id"],
                "additionalProperties": False
            }
        }
    }
]

response = client.chat.completions.create(
    model=model,
    messages=[
        {
            "role": "user",
            "content": "What is the current balance of account ACC-1024?"
        }
    ],
    tools=tools,
    tool_choice="auto",
)

message = response.choices[0].message

print(f"Model: {model}")

if message.tool_calls:
    print("Tool calling successful.")

    for call in message.tool_calls:
        print(f"Tool name: {call.function.name}")
        print(f"Arguments: {call.function.arguments}")
else:
    print("No tool call was produced.")
    print(f"Model response: {message.content}")