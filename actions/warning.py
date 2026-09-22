def warning_message(action: str, reasons: list[str]) -> str:
    if action == "ALLOW":
        return ""

    if action == "WARN":
        return (
            "⚠️ Please be careful. Continued suspicious behavior "
            "will lead to escalation."
        )

    if action == "REVIEW":
        return (
            "⚠️ This message contains potentially suspicious content. "
            "Please verify the link or request before interacting with it."
        )

    if action == "ESCALATE":
        return (
            "🚨 Repeated violations detected. Your account is now under "
            "closer monitoring. Further abuse will be blocked."
        )

    if action == "HIGH_RISK":
        return (
            "🚨 This message contains multiple high-risk indicators. "
            "Do not click links or send money, passwords, OTPs, or other sensitive information."
        )

    if action == "LOG":
        return (
            "ℹ️ This message has been noted for review. "
            "No action is taken."
        )

    if action == "DELETE":
        return "Message removed for containing prohibited content."

    if action == "KICK":
        return "You have been removed from this group."

    if action == "BLOCK":
        return ""

    return ""
