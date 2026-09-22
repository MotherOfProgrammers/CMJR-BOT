from moderation.scam import detect_scam_signals


messages = [
    "Hello everyone!",
    "URGENT! Act now!",
    "Please send money immediately.",
    "Enter your OTP and password.",
    "Congratulations! You won a prize!",
]


for message in messages:
    result = detect_scam_signals(message)

    print(f"Message: {message}")
    print(result)
    print()
