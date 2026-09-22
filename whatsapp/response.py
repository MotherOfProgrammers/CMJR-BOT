from whatsapp.models import WhatsAppMessage


def build_response(
    message: WhatsAppMessage,
    result: dict,
) -> dict:
    return {
        "chat_id": message.chat_id,
        "message_id": message.message_id,
        "action": result["action"],
        "text": result["warning"],
    }
