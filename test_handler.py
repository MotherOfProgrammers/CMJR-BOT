from actions.replies import handle_message


messages = [
    ("user123", "Hello everyone!"),
    ("user456", "URGENT! Act now! Visit https://bit.ly/example"),
    ("user789", "Send money immediately to https://192.168.1.100/login"),
]


for sender, text in messages:
    result = handle_message(sender, text)

    print(result)
    print()
