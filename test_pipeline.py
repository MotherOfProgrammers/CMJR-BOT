from moderation.rules import analyze_message


messages = [
    "Hello everyone!",
    "Visit https://github.com/test",
    "Check https://example.com",
    "URGENT! Act now! Visit https://bit.ly/example",
    "Send money immediately to https://192.168.1.100/login",
]


for message in messages:
    result = analyze_message(sender="test", text=message)

    print(f"Message: {message}")
    print(result)
    print()
