import hashlib
import hmac

import httpx

import config
from whatsapp.adapter import WhatsAppAdapter
from whatsapp.models import WhatsAppMessage
from whatsapp.validation import (
    PayloadValidationError,
    ProviderError,
    UnsupportedMessageTypeError,
    WebhookNoEventError,
    validate_payload,
)

NON_TEXT_MESSAGE_TYPES = {
    "audio",
    "button",
    "contacts",
    "document",
    "edits",
    "gif",
    "group_invite",
    "hsm",
    "image",
    "interactive",
    "keep_in_chat",
    "link_preview",
    "list",
    "location",
    "media_placeholder",
    "order",
    "pin",
    "poll",
    "poll_creation",
    "poll_update",
    "product",
    "reaction",
    "request_welcome",
    "sticker",
    "system",
    "unsupported",
    "video",
}


def verify_meta_signature(
    raw_body: bytes,
    signature_header: str | None,
    app_secret: str | None,
) -> bool:
    if not app_secret:
        return False

    if not signature_header or not signature_header.startswith("sha256="):
        return False

    provided = signature_header[len("sha256="):]
    expected = hmac.new(
        app_secret.encode(),
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(provided, expected)


def _extract_message_value(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise PayloadValidationError(
            "Payload must be a JSON object"
        )

    if payload.get("object") != "whatsapp_business_account":
        raise PayloadValidationError(
            "object must be whatsapp_business_account"
        )

    entries = payload.get("entry")

    if not isinstance(entries, list) or not entries:
        raise PayloadValidationError(
            "entry must be a non-empty list"
        )

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        changes = entry.get("changes")

        if not isinstance(changes, list):
            continue

        for change in changes:
            if not isinstance(change, dict):
                continue

            if change.get("field") != "messages":
                continue

            value = change.get("value")

            if isinstance(value, dict):
                return value

    raise PayloadValidationError(
        "No messages webhook value found"
    )


class MetaWhatsAppAdapter(WhatsAppAdapter):
    def __init__(
        self,
        access_token: str | None = None,
        phone_number_id: str | None = None,
        api_version: str | None = None,
        graph_url: str | None = None,
        client=None,
    ):
        self.access_token = access_token or config.META_ACCESS_TOKEN
        self.phone_number_id = phone_number_id or config.META_PHONE_NUMBER_ID
        self.api_version = api_version or config.META_API_VERSION
        self.graph_url = graph_url or config.META_GRAPH_URL
        self._client = client

    def parse_message(self, payload: dict) -> WhatsAppMessage:
        value = _extract_message_value(payload)

        statuses = value.get("statuses")

        if (
            statuses is not None
            and not value.get("messages")
        ):
            raise WebhookNoEventError(
                "Webhook contains only message status updates"
            )

        messages = value.get("messages")

        if not isinstance(messages, list) or not messages:
            raise PayloadValidationError(
                "messages must be a non-empty list"
            )

        message = messages[0]

        if not isinstance(message, dict):
            raise PayloadValidationError(
                "Each message must be an object"
            )

        message_type = message.get("type")

        if not isinstance(message_type, str) or not message_type:
            raise PayloadValidationError(
                "message type is required"
            )

        if message_type != "text":
            if message_type in NON_TEXT_MESSAGE_TYPES:
                raise UnsupportedMessageTypeError(
                    f"Unsupported message type: {message_type}"
                )
            raise PayloadValidationError(
                f"Unknown message type: {message_type}"
            )

        sender = message.get("from")

        if not isinstance(sender, str) or not sender.strip():
            raise PayloadValidationError(
                "from must be a non-empty string"
            )

        message_id = message.get("id")

        if not isinstance(message_id, str) or not message_id.strip():
            raise PayloadValidationError(
                "id must be a non-empty string"
            )

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

        group_id = message.get("group_id")

        if isinstance(group_id, str) and group_id.strip():
            chat_id = group_id
            recipient_type = "group"
        else:
            chat_id = sender
            recipient_type = "individual"

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
            recipient_type=recipient_type,
        )

    async def send_message(
        self,
        chat_id: str,
        text: str,
        recipient_type: str = "individual",
    ) -> dict:
        if not self.access_token or not self.phone_number_id:
            raise ProviderError(
                "Meta credentials are not configured"
            )

        url = (
            f"{self.graph_url.rstrip('/')}"
            f"/{self.api_version}"
            f"/{self.phone_number_id}/messages"
        )

        payload = {
            "messaging_product": "whatsapp",
            "recipient_type": recipient_type,
            "to": chat_id,
            "type": "text",
            "text": {
                "body": text,
            },
        }

        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }

        client = self._client

        if client is None:
            client = httpx.AsyncClient()

        try:
            response = await client.post(
                url,
                headers=headers,
                json=payload,
            )
        finally:
            if self._client is None:
                await client.aclose()

        return self._check_response(response)

    @staticmethod
    def _check_response(response) -> dict:
        if 200 <= response.status_code < 300:
            data = response.json()
            return {
                "status_code": response.status_code,
                "response": data,
            }

        code = response.status_code
        message = f"Meta API error (HTTP {code})"

        try:
            error = response.json().get("error") or {}
            if isinstance(error, dict):
                message = f"Meta API error {error.get('code', code)}: {error.get('message', message)}"
        except ValueError:
            pass

        raise ProviderError(message)