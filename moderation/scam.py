SCAM_PATTERNS = {
    "urgent_language": [
        "urgent",
        "act now",
        "immediately",
        "limited time",
    ],
    "credential_request": [
        "password",
        "verification code",
        "otp",
        "security code",
    ],
    "money_request": [
        "send money",
        "transfer money",
        "send payment",
        "pay now",
    ],
    "prize_claim": [
        "you won",
        "you have won",
        "claim your prize",
        "congratulations",
    ],
}


def detect_scam_signals(text: str) -> dict:
    text = text.lower()

    risk = 0
    reasons = []

    for category, patterns in SCAM_PATTERNS.items():
        for pattern in patterns:
            if pattern in text:
                risk += 1
                reasons.append(category)
                break

    return {
        "risk": risk,
        "reasons": reasons,
    }
