from actions.replies import handle_message
from whatsapp.adapter import WhatsAppAdapter
from whatsapp.response import build_response


async def process_whatsapp_message(
    adapter: WhatsAppAdapter,
    payload: dict,
) -> dict:
    message = adapter.parse_message(payload)

    result = handle_message(
        sender=message.sender,
        text=message.text,
        chat_id=message.chat_id,
    )

    response = build_response(
        message=message,
        result=result,
    )

    if response["text"]:
        await adapter.send_message(
            chat_id=response["chat_id"],
            text=response["text"],
            recipient_type=message.recipient_type,
        )

    return {
        "message": message,
        "result": result,
        "response": response,
    }
