from dataclasses import dataclass


@dataclass
class WhatsAppMessage:
    sender: str
    text: str
    message_id: str | None = None
    chat_id: str | None = None
    recipient_type: str = "individual"
