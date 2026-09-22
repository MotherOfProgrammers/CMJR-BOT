from whatsapp.models import WhatsAppMessage
from whatsapp.validation import validate_payload


class WhatsAppAdapter:
    def parse_message(self, payload: dict) -> WhatsAppMessage:
        raise NotImplementedError

    async def send_message(
        self,
        chat_id: str,
        text: str,
        recipient_type: str = "individual",
    ) -> None:
        raise NotImplementedError


class MockWhatsAppAdapter(WhatsAppAdapter):
    def parse_message(self, payload: dict) -> WhatsAppMessage:
        validate_payload(payload)

        return WhatsAppMessage(
            sender=payload["sender"],
            text=payload["text"],
            message_id=payload.get("message_id"),
            chat_id=payload.get("chat_id"),
        )

    async def send_message(
        self,
        chat_id: str,
        text: str,
        recipient_type: str = "individual",
    ) -> None:
        print(
            f"WhatsApp message to {chat_id}: {text}"
        )
