from ai.parsers import ALLOWED_ACTIONS, ALLOWED_CATEGORIES, normalize


def validate_response(raw: dict) -> dict | None:
    return normalize(raw)


__all__ = ["ALLOWED_ACTIONS", "ALLOWED_CATEGORIES", "normalize"]