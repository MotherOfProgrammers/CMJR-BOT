from whatsapp.adapter import WhatsAppAdapter
from whatsapp.models import WhatsAppMessage
from whatsapp.validation import (
    PayloadValidationError,
    UnsupportedMessageTypeError,
    validate_payload,
)

UNSUPPORTED_MESSAGE_TYPES = {
    "audio",
    "button",
    "contacts",
    "document",
    "event",
    "image",
    "location",
    "media",
    "poll",
    "reaction",
    "request",
    "sticker",
    "system",
    "template",
    "video",
}


class GenericWhatsAppAdapter(WhatsAppAdapter):
    def parse_message(self, payload: dict) -> WhatsAppMessage:
        if not isinstance(payload, dict):
            raise PayloadValidationError(
                "Payload must be a JSON object"
            )

        messages = payload.get("messages")

        if not isinstance(messages, list):
            raise PayloadValidationError(
                "messages must be a list"
            )

        if not messages:
            raise PayloadValidationError(
                "messages must not be empty"
            )

        message = messages[0]

        if not isinstance(message, dict):
            raise PayloadValidationError(
                "Each message must be an object"
            )

        message_type = message.get("type", "text")

        if message_type in UNSUPPORTED_MESSAGE_TYPES:
            raise UnsupportedMessageTypeError(
                f"Unsupported message type: {message_type}"
            )

        if message_type != "text":
            raise PayloadValidationError(
                f"Unknown message type: {message_type}"
            )

        sender = message.get("from")
        message_id = message.get("id")
        chat_id = message.get("chat_id", sender)

        if not isinstance(sender, str) or not sender.strip():
            raise PayloadValidationError(
                "from must be a non-empty string"
            )

        if not isinstance(chat_id, str) or not chat_id.strip():
            chat_id = sender

        text_field = message.get("text")

        if not isinstance(text_field, dict):
            raise PayloadValidationError(
                "text must be an object"
            )

        text = text_field.get("body")

        if not isinstance(text, str) or not text.strip():
            raise PayloadValidationError(
                "text.body must be a non-empty string"
            )

        normalized = {
            "sender": sender,
            "text": text,
            "message_id": message_id,
            "chat_id": chat_id,
        }

        validate_payload(normalized)

        return WhatsAppMessage(
            sender=sender,
            text=text,
            message_id=message_id,
            chat_id=chat_id,
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