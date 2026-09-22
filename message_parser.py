from dataclasses import dataclass


@dataclass
class Message:
    sender: str
    text: str


def parse_message(sender: str, text: str) -> Message:
    return Message(
        sender=sender,
        text=text.strip(),
    )
