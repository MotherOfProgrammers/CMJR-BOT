def welcome_message(participants: list) -> str:
    if not participants:
        return ""

    names = [p for p in participants if isinstance(p, str)]

    count = len(names)

    if count == 1:
        return (
            "Welcome to the group! Please take a moment to read the group rules "
            "and introduce yourself. Enjoy your stay."
        )

    return (
        f"Welcome to the group, all {count} of you! Please take a moment to "
        "read the group rules and introduce yourselves. Enjoy your stay."
    )