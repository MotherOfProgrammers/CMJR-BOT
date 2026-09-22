class PayloadValidationError(ValueError):
    pass


class UnsupportedMessageTypeError(ValueError):
    pass


class WebhookNoEventError(ValueError):
    pass


class ProviderError(ValueError):
    pass


def validate_payload(payload: dict) -> None:
    if not isinstance(payload, dict):
        raise PayloadValidationError(
            "Payload must be a dictionary"
        )

    sender = payload.get("sender")
    text = payload.get("text")

    if not isinstance(sender, str) or not sender.strip():
        raise PayloadValidationError(
            "sender must be a non-empty string"
        )

    if not isinstance(text, str) or not text.strip():
        raise PayloadValidationError(
            "text must be a non-empty string"
        )