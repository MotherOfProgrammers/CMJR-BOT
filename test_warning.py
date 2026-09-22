from actions.warning import warning_message
from moderation.rules import analyze_message


messages = [
    "Hello everyone!",
    "URGENT! Act now! Visit https://bit.ly/example",
    "Send money immediately to https://192.168.1.100/login",
]


for message in messages:
    result = analyze_message(sender="test", text=message)

    warning = warning_message(
        result["action"],
        result["scam"]["reasons"],
    )

    print(f"Message: {message}")
    print(f"Action: {result['action']}")
    print(f"Warning: {warning}")
    print()
